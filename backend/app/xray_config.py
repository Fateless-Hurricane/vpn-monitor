"""
Builds a minimal xray-core config that exposes a local SOCKS5 inbound and
routes it through the target server's real outbound (vless/vmess/trojan/ss).

This is what makes the check a genuine "does traffic actually flow through
this V2Ray config" test, rather than a bare TCP/ICMP probe.
"""
from .subscription_parser import ParsedProxy


def build_config(proxy: ParsedProxy, local_socks_port: int) -> dict:
    inbound = {
        "listen": "127.0.0.1",
        "port": local_socks_port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }

    stream_settings = _stream_settings(proxy)

    if proxy.protocol == "vless":
        user_dict = {
            "id": proxy.extra["id"],
            "encryption": proxy.extra.get("encryption", "none") or "none",
        }
        flow = proxy.extra.get("flow", "")
        if flow:
            user_dict["flow"] = flow

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": proxy.address,
                    "port": proxy.port,
                    "users": [user_dict],
                }]
            },
            "streamSettings": stream_settings,
        }
    elif proxy.protocol == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": proxy.address,
                    "port": proxy.port,
                    "users": [{
                        "id": proxy.extra["id"],
                        "alterId": int(proxy.extra.get("aid", 0) or 0),
                    }],
                }]
            },
            "streamSettings": stream_settings,
        }
    elif proxy.protocol == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": proxy.address,
                    "port": proxy.port,
                    "password": proxy.extra["password"],
                }]
            },
            "streamSettings": stream_settings,
        }
    elif proxy.protocol == "shadowsocks":
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": proxy.address,
                    "port": proxy.port,
                    "method": proxy.extra["method"],
                    "password": proxy.extra["password"],
                }]
            },
        }
    else:
        raise ValueError(f"Unsupported protocol: {proxy.protocol}")

    outbound["tag"] = "proxy"

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def _stream_settings(proxy: ParsedProxy) -> dict:
    extra = proxy.extra
    raw_net = str(extra.get("type") or extra.get("net") or "tcp").lower()

    # Normalize network name
    if raw_net in ("splithttp", "xhttp"):
        net = "xhttp"
    elif raw_net in ("httpupgrade", "http-upgrade"):
        net = "httpupgrade"
    elif raw_net in ("websocket", "ws"):
        net = "ws"
    elif raw_net in ("grpc", "gun"):
        net = "grpc"
    elif raw_net in ("h2", "http"):
        net = "http"
    elif raw_net in ("kcp", "mkcp"):
        net = "kcp"
    else:
        net = "tcp"

    settings = {"network": net}

    security = str(extra.get("security") or extra.get("tls") or "").lower()
    is_reality = security == "reality"
    is_tls = security in ("tls", "true", "1") or is_reality

    sni = extra.get("sni") or extra.get("host_header") or proxy.address
    fp = extra.get("fp") or "chrome"
    alpn = extra.get("alpn") or []
    allow_insecure = bool(extra.get("allow_insecure", False))

    if is_reality:
        settings["security"] = "reality"
        reality_obj = {
            "show": False,
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": extra.get("pbk", ""),
            "shortId": extra.get("sid", ""),
        }
        spx = extra.get("spx", "")
        if spx:
            reality_obj["spiderX"] = spx
        settings["realitySettings"] = reality_obj

    elif is_tls:
        settings["security"] = "tls"
        tls_obj = {
            "serverName": sni,
            "fingerprint": fp,
            "allowInsecure": allow_insecure,
        }
        if alpn:
            tls_obj["alpn"] = alpn
        settings["tlsSettings"] = tls_obj

    # Transport settings
    path = extra.get("path") or "/"
    host_header = extra.get("host_header") or ""

    if net == "ws":
        ws_obj = {"path": path}
        if host_header:
            ws_obj["headers"] = {"Host": host_header}
        settings["wsSettings"] = ws_obj

    elif net == "xhttp":
        xhttp_obj = {"path": path, "mode": extra.get("mode", "auto")}
        if host_header:
            xhttp_obj["host"] = host_header
        settings["xhttpSettings"] = xhttp_obj

    elif net == "httpupgrade":
        httpup_obj = {"path": path}
        if host_header:
            httpup_obj["host"] = host_header
        settings["httpupgradeSettings"] = httpup_obj

    elif net == "grpc":
        service_name = path.lstrip("/") if path and path != "/" else extra.get("serviceName", "")
        settings["grpcSettings"] = {
            "serviceName": service_name,
            "multiMode": True,
        }

    elif net == "http":
        h2_obj = {"path": path}
        if host_header:
            h2_obj["host"] = [host_header]
        settings["httpSettings"] = h2_obj

    return settings

