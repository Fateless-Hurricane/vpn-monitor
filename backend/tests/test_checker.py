import os
import sys
import socket
import threading
import datetime as dt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.checker import tcp_check
from app.incidents import classify, DEGRADED_LATENCY_MS
from app.models import CheckResult, ServerStatus


def _spin_up_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def accept_loop():
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv, port


def test_tcp_check_success():
    srv, port = _spin_up_listener()
    try:
        ok, latency = tcp_check("127.0.0.1", port, timeout=2)
        assert ok is True
        assert latency is not None and latency >= 0
    finally:
        srv.close()


def test_tcp_check_failure_closed_port():
    # Port 1 is reserved/closed; connection should fail fast.
    ok, latency = tcp_check("127.0.0.1", 1, timeout=1)
    assert ok is False
    assert latency is None


def test_classify_operational():
    c = CheckResult(proxy_success=True, proxy_latency_ms=80.0)
    assert classify(c) == ServerStatus.operational


def test_classify_degraded_on_high_latency():
    c = CheckResult(proxy_success=True, proxy_latency_ms=DEGRADED_LATENCY_MS + 50)
    assert classify(c) == ServerStatus.degraded


def test_classify_down_when_proxy_fails():
    c = CheckResult(proxy_success=False, proxy_latency_ms=None)
    assert classify(c) == ServerStatus.down


def test_build_config_reality_with_spx():
    from app.subscription_parser import parse_vless
    from app.xray_config import build_config

    uri = "vless://00000000-0000-0000-0000-000000000000@us.example.com:2092?encryption=none&fp=chrome&host=us.example.com&mode=auto&path=%2Fapi&pbk=DummyPublicKey1234567890abcdef&security=reality&sid=12345678&sni=example.com&spx=%2Ftestspider&type=xhttp#US-Direct"
    p = parse_vless(uri)
    cfg = build_config(p, 10850)

    outbounds = cfg["outbounds"]
    proxy_outbound = next(o for o in outbounds if o.get("tag") == "proxy")
    stream_settings = proxy_outbound["streamSettings"]

    assert stream_settings["network"] == "xhttp"
    assert stream_settings["security"] == "reality"
    assert stream_settings["realitySettings"]["publicKey"] == "DummyPublicKey1234567890abcdef"
    assert stream_settings["realitySettings"]["spiderX"] == "/testspider"
    assert stream_settings["realitySettings"]["show"] is False
    assert stream_settings["xhttpSettings"]["path"] == "/api"


