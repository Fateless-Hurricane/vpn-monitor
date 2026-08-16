"""
Two layers of checking per server:

1. tcp_check      – can we open a TCP connection to host:port at all
2. proxy_check     – spin up a throwaway xray-core process configured with
                     this exact config, then make an HTTP request THROUGH
                     it via SOCKS5. This proves the V2Ray inbound/outbound,
                     TLS/Reality handshake, and routing are all actually
                     working end-to-end, not just "the port is open".
"""
import asyncio
import json
import os
import shutil
import socket
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from .subscription_parser import ParsedProxy
from .xray_config import build_config

TEST_URL = os.getenv("PROXY_TEST_URL", "https://www.gstatic.com/generate_204")
XRAY_STARTUP_TIMEOUT = float(os.getenv("XRAY_STARTUP_TIMEOUT", "4"))
PROXY_REQUEST_TIMEOUT = float(os.getenv("PROXY_REQUEST_TIMEOUT", "10"))


def find_xray_binary() -> Optional[str]:
    """Dynamically search for an xray executable across environment variables and standard paths."""
    candidates = []

    env_path = os.getenv("XRAY_BINARY_PATH")
    if env_path:
        candidates.append(env_path)

    which_path = shutil.which("xray")
    if which_path:
        candidates.append(which_path)

    # Standard candidate locations
    candidates.extend([
        "/Applications/v2rayN.app/Contents/MacOS/bin/xray/xray",
        "/opt/homebrew/bin/xray",
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        str(Path.home() / ".local" / "bin" / "xray"),
        str(Path(__file__).resolve().parent.parent.parent / "bin" / "xray"),
        str(Path(__file__).resolve().parent.parent / "bin" / "xray"),
        "xray",
        "xray.exe",
    ])

    for c in candidates:
        if not c:
            continue
        p = Path(c).expanduser().resolve()
        if p.is_file():
            # Check and ensure executable bit
            try:
                st = os.stat(p)
                if not (st.st_mode & stat.S_IXUSR):
                    os.chmod(p, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except Exception:
                pass
            return str(p)

    return None


@dataclass
class CheckOutcome:
    tcp_success: bool
    tcp_latency_ms: Optional[float]
    proxy_success: bool
    proxy_latency_ms: Optional[float]
    error: Optional[str]


def tcp_check(host: str, port: int, timeout: float = 5.0) -> tuple[bool, Optional[float]]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000
            return True, round(elapsed, 1)
    except Exception as exc:
        return False, None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_port_open(port: int, timeout: float) -> bool:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return True
        except OSError:
            await asyncio.sleep(0.1)
    return False


async def proxy_check(proxy: ParsedProxy) -> tuple[bool, Optional[float], Optional[str]]:
    """Real connectivity test: run this exact config through xray-core and
    make a request through it. Returns (success, latency_ms, error)."""
    xray_binary = find_xray_binary()
    if not xray_binary:
        return False, None, "xray binary not found on host (check XRAY_BINARY_PATH or install Xray)"

    local_port = _free_port()
    try:
        config = build_config(proxy, local_port)
    except Exception as exc:
        return False, None, f"config generation error: {exc}"

    with tempfile.NamedTemporaryFile("w", suffix=f"-{uuid.uuid4().hex}.json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            xray_binary, "run", "-config", config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        port_opened = await _wait_port_open(local_port, XRAY_STARTUP_TIMEOUT)
        if not port_opened:
            # Try to grab stderr to see why it didn't start
            err_msg = "xray process failed to bind local SOCKS port"
            if proc.returncode is not None:
                _, stderr = await proc.communicate()
                err_text = stderr.decode(errors="ignore").strip()
                if err_text:
                    err_msg = f"xray exited early: {err_text[:200]}"
            return False, None, err_msg

        proxy_url = f"socks5://127.0.0.1:{local_port}"
        start = time.perf_counter()
        async with httpx.AsyncClient(proxy=proxy_url, timeout=PROXY_REQUEST_TIMEOUT) as client:
            resp = await client.get(TEST_URL)
        elapsed = (time.perf_counter() - start) * 1000

        if resp.status_code in (200, 204):
            return True, round(elapsed, 1), None
        return False, round(elapsed, 1), f"unexpected HTTP status {resp.status_code}"

    except httpx.HTTPError as exc:
        return False, None, f"proxy HTTP request error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, None, str(exc)
    finally:
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                proc.kill()
        try:
            os.remove(config_path)
        except OSError:
            pass


async def run_full_check(proxy: ParsedProxy) -> CheckOutcome:
    tcp_ok, tcp_ms = tcp_check(proxy.address, proxy.port)
    proxy_ok, proxy_ms, err = await proxy_check(proxy)
    return CheckOutcome(
        tcp_success=tcp_ok,
        tcp_latency_ms=tcp_ms,
        proxy_success=proxy_ok,
        proxy_latency_ms=proxy_ms,
        error=err,
    )

