#!/usr/bin/env python3
"""
Relay — V2Ray VPN Subscription Monitor
Single-command launcher:
- Validates Python 3.10+
- Checks & prepares virtualenv with dependencies
- Auto-detects or downloads xray-core binary (macOS / Linux / Windows)
- Starts the unified server (API + Worker + Web Dashboard) on http://localhost:8000
- Opens the dashboard in your default web browser
"""
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import webbrowser
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
BIN_DIR = ROOT_DIR / "bin"
VENV_DIR = BACKEND_DIR / ".venv"
REQ_FILE = BACKEND_DIR / "requirements.txt"

XRAY_VERSION = "v1.8.24"


def log(msg: str):
    print(f"\033[1;36m[Relay]\033[0m {msg}")


def log_success(msg: str):
    print(f"\033[1;32m[Relay ✓]\033[0m {msg}")


def log_warn(msg: str):
    print(f"\033[1;33m[Relay !]\033[0m {msg}")


def log_err(msg: str):
    print(f"\033[1;31m[Relay ✗]\033[0m {msg}")


def get_venv_python() -> Path:
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def get_venv_pip() -> Path:
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "pip.exe"
    return VENV_DIR / "bin" / "pip"


def check_and_prepare_venv() -> Path:
    venv_py = get_venv_python()
    needs_setup = False

    if not venv_py.exists():
        needs_setup = True
    else:
        # Check if venv python actually works (not a corrupted/relocated venv)
        try:
            res = subprocess.run([str(venv_py), "-c", "import sys; sys.exit(0)"], capture_output=True)
            if res.returncode != 0:
                needs_setup = True
        except Exception:
            needs_setup = True

    if needs_setup:
        log("Setting up virtual environment in backend/.venv...")
        if VENV_DIR.exists():
            shutil.rmtree(VENV_DIR, ignore_errors=True)
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        venv_py = get_venv_python()
        venv_pip = get_venv_pip()
        log("Installing backend dependencies...")
        subprocess.run([str(venv_pip), "install", "--upgrade", "pip"], check=False)
        subprocess.run([str(venv_pip), "install", "-r", str(REQ_FILE)], check=True)
        log_success("Dependencies installed successfully.")
    else:
        # Quick check for fastapi/uvicorn
        try:
            subprocess.run([str(venv_py), "-c", "import fastapi, uvicorn, httpx"], check=True, capture_output=True)
        except Exception:
            log("Updating backend dependencies...")
            venv_pip = get_venv_pip()
            subprocess.run([str(venv_pip), "install", "-r", str(REQ_FILE)], check=True)

    return venv_py


def ensure_xray_binary() -> str:
    # 1. Check existing binary paths via helper search
    sys.path.insert(0, str(BACKEND_DIR))
    try:
        from app.checker import find_xray_binary
        found = find_xray_binary()
        if found and os.path.isfile(found):
            log_success(f"Using Xray-core: {found}")
            return found
    except Exception:
        pass

    # 2. Download Xray binary for current platform
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        asset = "Xray-macos-arm64-v8a.zip" if ("arm" in machine or "aarch" in machine) else "Xray-macos-64.zip"
        target_name = "xray"
    elif system == "linux":
        asset = "Xray-linux-arm64-v8a.zip" if ("arm" in machine or "aarch" in machine) else "Xray-linux-64.zip"
        target_name = "xray"
    elif system == "windows":
        asset = "Xray-windows-64.zip"
        target_name = "xray.exe"
    else:
        log_warn(f"Unknown system {system} {machine}. Please install xray manually.")
        return ""

    xray_target = BIN_DIR / target_name
    if xray_target.exists():
        st = os.stat(xray_target)
        os.chmod(xray_target, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return str(xray_target)

    download_url = f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/{asset}"
    zip_dest = BIN_DIR / "xray_download.zip"
    log(f"Downloading Xray-core {XRAY_VERSION} for {system} ({machine})...")
    try:
        urllib.request.urlretrieve(download_url, zip_dest)
        with zipfile.ZipFile(zip_dest, "r") as z:
            z.extractall(BIN_DIR)
        if zip_dest.exists():
            zip_dest.unlink()

        if xray_target.exists():
            st = os.stat(xray_target)
            os.chmod(xray_target, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            log_success(f"Downloaded and installed Xray-core: {xray_target}")
            return str(xray_target)
    except Exception as exc:
        log_warn(f"Could not auto-download Xray ({exc}). You can manually place 'xray' in './bin/'.")

    return ""


def main():
    print("""
\033[1;36m=======================================================
   🚀 Relay — V2Ray VPN Subscription Monitor
=======================================================\033[0m
""")
    # 1. Environment & Venv
    venv_python = check_and_prepare_venv()

    # 2. Xray binary
    xray_path = ensure_xray_binary()
    env = os.environ.copy()
    if xray_path:
        env["XRAY_BINARY_PATH"] = xray_path

    port = int(os.getenv("PORT", "8000"))
    url = f"http://localhost:{port}"

    log(f"Starting unified server at {url}...")
    log("Status Dashboard & API running together on one port.")
    log("Press Ctrl+C to stop.\n")

    # Launch browser after 1.5s
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(url)

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    # 3. Run uvicorn
    cmd = [
        str(venv_python),
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        str(port),
    ]

    try:
        subprocess.run(cmd, cwd=str(BACKEND_DIR), env=env)
    except KeyboardInterrupt:
        print("\n")
        log("Server stopped.")


if __name__ == "__main__":
    main()
