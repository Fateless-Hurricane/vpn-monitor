"""
Fetches a V2Ray-style subscription (base64 blob of share-links) and parses
each line into a normalized dict describing the proxy config.

Supported schemes: vless://, vmess://, trojan://, ss://
"""
import base64
import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

import httpx

# Comprehensive keyword / code -> (Country name, flag emoji) lookup
COUNTRY_HINTS = [
    # Flag emoji matches first
    (["🇩🇪"], ("Germany", "🇩🇪")),
    (["🇫🇮"], ("Finland", "🇫🇮")),
    (["🇺🇸"], ("United States", "🇺🇸")),
    (["🇵🇱"], ("Poland", "🇵🇱")),
    (["🇳🇱"], ("Netherlands", "🇳🇱")),
    (["🇫🇷"], ("France", "🇫🇷")),
    (["🇬🇧"], ("United Kingdom", "🇬🇧")),
    (["🇹🇷"], ("Turkey", "🇹🇷")),
    (["🇮🇷"], ("Iran", "🇮🇷")),
    (["🇸🇬"], ("Singapore", "🇸🇬")),
    (["🇯🇵"], ("Japan", "🇯🇵")),
    (["🇨🇦"], ("Canada", "🇨🇦")),
    (["🇨🇭"], ("Switzerland", "🇨🇭")),
    (["🇸🇪"], ("Sweden", "🇸🇪")),
    (["🇳🇴"], ("Norway", "🇳🇴")),
    (["🇦🇹"], ("Austria", "🇦🇹")),
    (["🇮🇹"], ("Italy", "🇮🇹")),
    (["🇪🇸"], ("Spain", "🇪🇸")),
    (["🇦🇪"], ("UAE", "🇦🇪")),
    (["🇦🇺"], ("Australia", "🇦🇺")),
    (["🇮🇳"], ("India", "🇮🇳")),
    (["🇧🇷"], ("Brazil", "🇧🇷")),
    (["🇰🇷"], ("South Korea", "🇰🇷")),
    (["🇭🇰"], ("Hong Kong", "🇭🇰")),
    (["🇹🇼"], ("Taiwan", "🇹🇼")),
    (["🇷🇺"], ("Russia", "🇷🇺")),
    # Keywords and ISO codes
    (["germany", "frankfurt", "de-", "-de", " de "], ("Germany", "🇩🇪")),
    (["finland", "helsinki", "fi-", "-fi", " fi "], ("Finland", "🇫🇮")),
    (["united states", "usa", "us-", "-us", "america", "🇺🇸", " us "], ("United States", "🇺🇸")),
    (["poland", "warsaw", "pl-", "-pl", " pl "], ("Poland", "🇵🇱")),
    (["netherlands", "amsterdam", "nl-", "-nl", " nl "], ("Netherlands", "🇳🇱")),
    (["france", "paris", "fr-", "-fr", " fr "], ("France", "🇫🇷")),
    (["united kingdom", "london", "gb-", "uk-", "-gb", "-uk", " uk "], ("United Kingdom", "🇬🇧")),
    (["turkey", "istanbul", "tr-", "-tr", " tr "], ("Turkey", "🇹🇷")),
    (["iran", "tehran", "ir-", "-ir", " ir "], ("Iran", "🇮🇷")),
    (["singapore", "sg-", "-sg", " sg "], ("Singapore", "🇸🇬")),
    (["japan", "tokyo", "jp-", "-jp", " jp "], ("Japan", "🇯🇵")),
    (["canada", "ca-", "-ca", " ca "], ("Canada", "🇨🇦")),
    (["switzerland", "zurich", "ch-", "-ch", " ch "], ("Switzerland", "🇨🇭")),
    (["sweden", "stockholm", "se-", "-se", " se "], ("Sweden", "🇸🇪")),
    (["norway", "oslo", "no-", "-no", " no "], ("Norway", "🇳🇴")),
    (["austria", "vienna", "at-", "-at", " at "], ("Austria", "🇦🇹")),
    (["italy", "milan", "rome", "it-", "-it", " it "], ("Italy", "🇮🇹")),
    (["spain", "madrid", "es-", "-es", " es "], ("Spain", "🇪🇸")),
    (["uae", "dubai", "ae-", "-ae", " ae "], ("UAE", "🇦🇪")),
    (["australia", "sydney", "au-", "-au", " au "], ("Australia", "🇦🇺")),
    (["india", "mumbai", "in-", "-in", " in "], ("India", "🇮🇳")),
    (["brazil", "br-", "-br", " br "], ("Brazil", "🇧🇷")),
    (["korea", "seoul", "kr-", "-kr", " kr "], ("South Korea", "🇰🇷")),
    (["hong kong", "hk-", "-hk", " hk "], ("Hong Kong", "🇭🇰")),
    (["taiwan", "tw-", "-tw", " tw "], ("Taiwan", "🇹🇼")),
    (["russia", "moscow", "ru-", "-ru", " ru "], ("Russia", "🇷🇺")),
]


def guess_country(remark: str, address: str) -> tuple[str, str]:
    haystack = f" {remark} {address} ".lower()
    for keywords, result in COUNTRY_HINTS:
        if any(k.lower() in haystack for k in keywords):
            return result
    return ("Unknown", "🏳️")


def b64_decode_flex(data: str) -> str:
    """Base64 decode, tolerating missing padding, whitespace, and urlsafe variants."""
    clean = re.sub(r"\s+", "", data)
    clean += "=" * (-len(clean) % 4)
    try:
        return base64.b64decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        return base64.urlsafe_b64decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        return data


@dataclass
class ParsedProxy:
    protocol: str
    address: str
    port: int
    remark: str
    raw_uri: str
    fingerprint: str
    # protocol-specific fields needed to rebuild an xray outbound config
    extra: dict


def _parse_alpn(alpn_raw: str) -> list[str]:
    if not alpn_raw:
        return []
    parts = [p.strip() for p in re.split(r"[,+]", alpn_raw) if p.strip()]
    return parts


def parse_vless(uri: str) -> Optional[ParsedProxy]:
    # vless://uuid@host:port?params#remark
    m = re.match(r"vless://([^@]+)@([^:/?#]+):(\d+)(\?[^#]*)?(#.*)?", uri, re.IGNORECASE)
    if not m:
        return None
    uid, host, port, query, frag = m.groups()
    params = parse_qs(query[1:]) if query else {}
    remark = unquote(frag[1:]) if frag else host

    security = params.get("security", ["none"])[0].lower()
    tls = params.get("tls", [""])[0].lower()
    if not security and tls:
        security = tls

    transport_type = params.get("type", ["tcp"])[0].lower()
    alpn_raw = params.get("alpn", [""])[0]

    extra = {
        "id": uid,
        "encryption": params.get("encryption", ["none"])[0],
        "flow": params.get("flow", [""])[0],
        "security": security,
        "sni": params.get("sni", [""])[0],
        "type": transport_type,
        "path": params.get("path", ["/"])[0],
        "host_header": params.get("host", [""])[0] or params.get("sni", [""])[0],
        "fp": params.get("fp", ["chrome"])[0],
        "pbk": params.get("pbk", [""])[0],
        "sid": params.get("sid", [""])[0],
        "spx": params.get("spx", [""])[0],
        "alpn": _parse_alpn(alpn_raw),
        "allow_insecure": params.get("allowInsecure", params.get("insecure", ["0"]))[0] in ("1", "true", "True"),
        "mode": params.get("mode", ["auto"])[0],
    }
    fp = f"vless|{host}|{port}|{uid}|{security}|{transport_type}|{extra.get('path', '')}|{extra.get('sni', '')}|{extra.get('pbk', '')}"
    return ParsedProxy("vless", host, int(port), remark, uri, fp, extra)


def parse_vmess(uri: str) -> Optional[ParsedProxy]:
    # vmess://<base64 JSON>
    payload = uri[len("vmess://"):]
    try:
        obj = json.loads(b64_decode_flex(payload))
    except Exception:
        return None

    host = str(obj.get("add", "")).strip()
    try:
        port = int(obj.get("port", 0))
    except (ValueError, TypeError):
        port = 0
    if not host or not port:
        return None

    remark = str(obj.get("ps", host))
    net = str(obj.get("net", "tcp")).lower()
    type_hdr = str(obj.get("type", "none"))
    tls = str(obj.get("tls", "")).lower()
    alpn_raw = str(obj.get("alpn", ""))

    extra = {
        "id": str(obj.get("id", "")),
        "aid": int(obj.get("aid", 0) or 0),
        "net": net,
        "type": net,  # In vmess, transport protocol is 'net'
        "header_type": type_hdr,
        "path": str(obj.get("path", "/")),
        "host_header": str(obj.get("host", "")),
        "tls": tls,
        "security": "tls" if tls in ("tls", "1", "true") else "none",
        "sni": str(obj.get("sni", "")),
        "fp": str(obj.get("fp", "chrome")),
        "alpn": _parse_alpn(alpn_raw),
        "allow_insecure": str(obj.get("allowInsecure", obj.get("insecure", "0"))) in ("1", "true", "True"),
    }
    fp = f"vmess|{host}|{port}|{extra['id']}|{net}|{extra.get('path', '')}|{extra.get('sni', '')}"
    return ParsedProxy("vmess", host, port, remark, uri, fp, extra)


def parse_trojan(uri: str) -> Optional[ParsedProxy]:
    # trojan://password@host:port?params#remark
    m = re.match(r"trojan://([^@]+)@([^:/?#]+):(\d+)(\?[^#]*)?(#.*)?", uri, re.IGNORECASE)
    if not m:
        return None
    password, host, port, query, frag = m.groups()
    params = parse_qs(query[1:]) if query else {}
    remark = unquote(frag[1:]) if frag else host

    security = params.get("security", ["tls"])[0].lower()
    transport_type = params.get("type", ["tcp"])[0].lower()
    alpn_raw = params.get("alpn", [""])[0]

    extra = {
        "password": password,
        "sni": params.get("sni", [host])[0],
        "type": transport_type,
        "security": security,
        "path": params.get("path", ["/"])[0],
        "host_header": params.get("host", [""])[0] or params.get("sni", [host])[0],
        "fp": params.get("fp", ["chrome"])[0],
        "alpn": _parse_alpn(alpn_raw),
        "allow_insecure": params.get("allowInsecure", params.get("insecure", ["0"]))[0] in ("1", "true", "True"),
    }
    fp = f"trojan|{host}|{port}|{password}|{transport_type}|{extra.get('path', '')}|{extra.get('sni', '')}"
    return ParsedProxy("trojan", host, int(port), remark, uri, fp, extra)


def parse_shadowsocks(uri: str) -> Optional[ParsedProxy]:
    # ss://base64(method:password)@host:port#remark  OR  ss://base64(method:password@host:port)#remark
    body = uri[len("ss://"):]
    remark = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        remark = unquote(frag)

    if "@" in body:
        cred_b64, hostport = body.split("@", 1)
        try:
            cred = b64_decode_flex(cred_b64)
        except Exception:
            cred = unquote(cred_b64)
        method, _, password = cred.partition(":")
        host, _, port = hostport.partition(":")
        port = re.sub(r"[/?].*", "", port)
    else:
        decoded = b64_decode_flex(body)
        creds, _, hostport = decoded.rpartition("@")
        method, _, password = creds.partition(":")
        host, _, port = hostport.partition(":")
        port = re.sub(r"[/?].*", "", port)

    if not host or not port:
        return None
    try:
        port_num = int(port)
    except ValueError:
        return None

    remark = remark or host
    extra = {"method": method, "password": password}
    fp = f"ss|{host}|{port_num}|{method}|{password[:6]}"
    return ParsedProxy("shadowsocks", host, port_num, remark, uri, fp, extra)



PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_shadowsocks,
}


def parse_uri(uri: str) -> Optional[ParsedProxy]:
    uri = uri.strip()
    for prefix, fn in PARSERS.items():
        if uri.lower().startswith(prefix):
            try:
                return fn(uri)
            except Exception:
                return None
    return None


async def fetch_subscription(url: str, timeout: float = 15.0) -> list[str]:
    """Fetch a subscription URL and return the list of raw share-link lines."""
    headers = {
        "User-Agent": "v2rayN/6.23 ClashforWindows/0.20.39 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Accept": "*/*",
    }
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        raw_text = resp.text

    # Most subscriptions are base64-encoded; fall back to plaintext if decode fails
    decoded = raw_text
    stripped = raw_text.strip()
    if not any(stripped.lower().startswith(p) for p in PARSERS):
        try:
            decoded = b64_decode_flex(stripped)
        except Exception:
            decoded = raw_text

    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    return [l for l in lines if any(l.lower().startswith(p) for p in PARSERS)]


def parse_subscription_content(lines: list[str]) -> list[ParsedProxy]:
    results = []
    for line in lines:
        parsed = parse_uri(line)
        if parsed:
            results.append(parsed)
    return results

