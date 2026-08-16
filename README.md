# Relay — V2Ray & Proxy Subscription Status Monitor

A real-time monitoring system for VPN subscriptions that tests **real proxy connectivity**
per server (VLESS / VMess / Trojan / Shadowsocks), not just ICMP/TCP reachability.

```
Subscription → Configs (VLESS / VMess / Trojan / SS) → Server Discovery
                                                            │
                                                  every 30m or on-demand
                                                            │
                                            ┌───────────────┴───────────────┐
                                            │                               │
                                       TCP latency                 real xray-core proxy
                                       (port check)                 HTTPS end-to-end test
                                            │                               │
                                            └───────────────┬───────────────┘
                                                             ▼
                                                       Check Result
                                                             ▼
                                              History · Uptime % · Incidents
                                                             ▼
                                               Interactive Web Dashboard
```

---

## ⚡ Quick Start (Easiest Method)

Run the single-command launcher from the project root:

```bash
./run.sh
```
*(or `python3 run.py` on Windows/macOS/Linux)*

This will automatically:
1. Validate Python and prepare the virtual environment.
2. Install/update required dependencies.
3. Auto-detect or download `xray-core` for your OS/architecture (macOS, Linux, Windows).
4. Launch the combined API + Background Worker + Web Dashboard at `http://localhost:8000`.
5. Open the status dashboard in your default browser.

---

## 🐳 Quick Start (Docker)

```bash
docker compose up -d --build
```

- Dashboard & API: `http://localhost:8000`

---

## 🧭 Dashboard Features

- **⚡ "Check Now" Button**: Run a fresh connectivity check across all servers instantly without waiting for the 30-minute interval.
- **⚡ "Sync & Check"**: Re-fetch and test individual subscriptions on demand.
- **Dual Latency Display**: See both real **Proxy Latency** (HTTPS through Xray) and **TCP Ping**.
- **Diagnostic Error Notes**: View exact connection errors (e.g. handshake failure, reset by peer, timeout) directly on degraded/down server cards.
- **Status Filter**: Filter servers by *All*, *Operational*, *Degraded*, or *Down*.
- **Subscription Management**: Add or remove subscriptions directly from the UI.

---

## 🛠 Supported Protocols & Transports

- **Protocols**: `VLESS`, `VMess`, `Trojan`, `Shadowsocks` (SIP002 & legacy).
- **Security & Handshake**: `Reality` (with `spiderX` / `spx`, `pbk`, `sid`, `fp`), `TLS` (with `ALPN`, `SNI`, `allowInsecure`).
- **Transports**: `xhttp` (SplitHTTP), `httpupgrade`, `ws` (WebSocket), `grpc`, `tcp`, `kcp`, `h2`.

---

## ⚙ Configuration (Environment Variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8000` | HTTP port for API and Dashboard |
| `DATABASE_URL` | `sqlite:///./vpn_monitor.db` | Database URL (SQLite or PostgreSQL) |
| `XRAY_BINARY_PATH` | Auto-detected | Custom path to `xray` binary |
| `CHECK_INTERVAL_MINUTES` | `30` | Interval between automated check cycles |
| `CHECK_CONCURRENCY` | `5` | Number of parallel proxy checks |
| `DEGRADED_LATENCY_MS` | `250` | Latency threshold for "degraded" status |
| `FAILURES_BEFORE_INCIDENT` | `2` | Consecutive failures before opening an incident |
| `PROXY_TEST_URL` | `https://www.gstatic.com/generate_204` | Destination URL used for end-to-end proxy test |

---

## 🧪 Tests

Run the test suite with pytest:

```bash
./backend/.venv/bin/pytest -v
```
*(Tests cover protocol parsing, Reality spiderX, ALPN, stream config generation, TCP checks, and incident lifecycles).*

