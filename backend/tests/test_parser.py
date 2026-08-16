import base64
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.subscription_parser import (
    parse_vless, parse_vmess, parse_trojan, parse_shadowsocks, parse_uri,
    parse_subscription_content, guess_country,
)


def test_parse_vless_basic():
    uri = "vless://8a1b2c3d-1111-2222-3333-abcdef123456@de.example.com:443?encryption=none&security=tls&type=ws&path=%2Fws&host=de.example.com&sni=de.example.com#Germany-01"
    p = parse_vless(uri)
    assert p is not None
    assert p.protocol == "vless"
    assert p.address == "de.example.com"
    assert p.port == 443
    assert p.remark == "Germany-01"
    assert p.extra["security"] == "tls"
    assert p.extra["type"] == "ws"


def test_parse_vmess_basic():
    obj = {"v": "2", "ps": "Finland-01", "add": "fi.example.com", "port": "443",
           "id": "uuid-here", "aid": "0", "net": "ws", "path": "/ws", "tls": "tls"}
    b64 = base64.b64encode(json.dumps(obj).encode()).decode()
    uri = f"vmess://{b64}"
    p = parse_vmess(uri)
    assert p is not None
    assert p.address == "fi.example.com"
    assert p.port == 443
    assert p.remark == "Finland-01"


def test_parse_trojan_basic():
    uri = "trojan://supersecret@pl.example.com:443?sni=pl.example.com#Poland-01"
    p = parse_trojan(uri)
    assert p is not None
    assert p.protocol == "trojan"
    assert p.extra["password"] == "supersecret"
    assert p.remark == "Poland-01"


def test_parse_shadowsocks_basic():
    cred = base64.b64encode(b"aes-256-gcm:mypassword").decode()
    uri = f"ss://{cred}@us.example.com:8388#USA-01"
    p = parse_shadowsocks(uri)
    assert p is not None
    assert p.extra["method"] == "aes-256-gcm"
    assert p.extra["password"] == "mypassword"
    assert p.address == "us.example.com"


def test_parse_uri_dispatch_and_fingerprint_stability():
    uri = "vless://uuid-abc@host.example.com:443?security=none#Test"
    p1 = parse_uri(uri)
    p2 = parse_uri(uri)
    assert p1.fingerprint == p2.fingerprint


def test_parse_subscription_content_skips_invalid_lines():
    lines = [
        "trojan://pw@pl.example.com:443#Poland",
        "not-a-valid-uri",
        "vless://uuid@de.example.com:443?security=tls#Germany",
    ]
    results = parse_subscription_content(lines)
    assert len(results) == 2
    protocols = {r.protocol for r in results}
    assert protocols == {"trojan", "vless"}


def test_guess_country_from_remark():
    name, flag = guess_country("Germany-Frankfurt-01", "de1.example.com")
    assert name == "Germany"
    assert flag == "🇩🇪"

    name, flag = guess_country("🇹🇷 Turkey-Test-01", "tr1.example.com")
    assert name == "Turkey"
    assert flag == "🇹🇷"

    name, flag = guess_country("random-tag", "unknownhost.example.com")
    assert name == "Unknown"


def test_parse_vless_reality_with_spx_and_xhttp():
    uri = "vless://00000000-0000-0000-0000-000000000000@us.example.com:2092?encryption=none&fp=chrome&host=us.example.com&mode=auto&path=%2Fapi&pbk=DummyPublicKey1234567890abcdef&security=reality&sid=12345678&sni=example.com&spx=%2Ftestspider&type=xhttp#US-Direct"
    p = parse_vless(uri)
    assert p is not None
    assert p.protocol == "vless"
    assert p.extra["security"] == "reality"
    assert p.extra["type"] == "xhttp"
    assert p.extra["pbk"] == "DummyPublicKey1234567890abcdef"
    assert p.extra["sid"] == "12345678"
    assert p.extra["spx"] == "/testspider"
    assert p.extra["sni"] == "example.com"


def test_parse_vless_alpn():
    uri = "vless://uuid@cdn.example.com:443?alpn=http%2F1.1%2Ch2%2Ch3&security=tls&type=ws&path=%2Fws#Alpn-Test"
    p = parse_vless(uri)
    assert p is not None
    assert p.extra["alpn"] == ["http/1.1", "h2", "h3"]


