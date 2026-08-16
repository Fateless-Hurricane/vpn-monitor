import asyncio
import datetime as dt
import os
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from .database import get_db, init_db, SessionLocal
from .models import Subscription, Server, CheckResult, Incident, ServerStatus
from .checker import find_xray_binary
from .worker import start_scheduler, run_cycle, sync_subscription, check_server_by_id, CHECK_CONCURRENCY

scheduler = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    global scheduler
    scheduler = start_scheduler()
    yield
    # Shutdown
    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(title="VPN Monitor API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SubscriptionIn(BaseModel):
    name: str
    url: str


def _uptime_pct_24h(db: Session, server_id: int) -> float:
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    total = db.query(func.count(CheckResult.id)).filter(
        CheckResult.server_id == server_id, CheckResult.checked_at >= since
    ).scalar()
    if not total:
        return 100.0
    ok = db.query(func.count(CheckResult.id)).filter(
        CheckResult.server_id == server_id,
        CheckResult.checked_at >= since,
        CheckResult.status == ServerStatus.operational,
    ).scalar()
    return round((ok / total) * 100, 2)


def _server_payload(db: Session, server: Server, history_limit: int = 90) -> dict:
    history = (
        db.query(CheckResult)
        .filter(CheckResult.server_id == server.id)
        .order_by(CheckResult.checked_at.desc())
        .limit(history_limit)
        .all()
    )
    history = list(reversed(history))
    open_incident = (
        db.query(Incident)
        .filter(Incident.server_id == server.id, Incident.resolved_at.is_(None))
        .first()
    )
    last_check = history[-1] if history else None

    return {
        "id": server.id,
        "protocol": server.protocol,
        "remark": server.remark,
        "country_name": server.country_name,
        "country_flag": server.country_flag,
        "status": server.current_status.value if server.current_status else "unknown",
        "latency_ms": server.current_latency_ms,
        "last_checked_at": server.last_checked_at,
        "last_error": last_check.error if (last_check and not last_check.proxy_success) else None,
        "tcp_latency_ms": last_check.tcp_latency_ms if last_check else None,
        "uptime_pct_24h": _uptime_pct_24h(db, server.id),
        "history": [
            {
                "checked_at": h.checked_at,
                "status": h.status.value,
                "latency_ms": h.proxy_latency_ms if h.proxy_success else (h.tcp_latency_ms if h.tcp_success else None),
                "error": h.error,
            }
            for h in history
        ],
        "open_incident": {
            "id": open_incident.id,
            "started_at": open_incident.started_at,
            "resolved_at": open_incident.resolved_at,
            "severity": open_incident.severity,
            "summary": open_incident.summary,
        } if open_incident else None,
    }


def _subscription_status(servers: list[Server]) -> str:
    statuses = [s.current_status for s in servers if s.is_active]
    if not statuses:
        return "unknown"
    if any(s == ServerStatus.down for s in statuses):
        return "down" if all(s == ServerStatus.down for s in statuses) else "degraded"
    if any(s == ServerStatus.degraded for s in statuses):
        return "degraded"
    return "operational"


@app.get("/api/system-info")
def system_info():
    xray_bin = find_xray_binary()
    xray_version = None
    if xray_bin:
        try:
            res = subprocess.run([xray_bin, "version"], capture_output=True, text=True, timeout=3)
            lines = res.stdout.strip().splitlines()
            if lines:
                xray_version = lines[0]
        except Exception:
            xray_version = "available (version check timed out)"

    return {
        "xray_installed": bool(xray_bin),
        "xray_binary_path": xray_bin,
        "xray_version": xray_version,
        "worker_running": bool(scheduler and scheduler.running),
    }


@app.get("/api/status")
def get_status(db: Session = Depends(get_db)):
    subs = db.query(Subscription).filter(Subscription.is_active.is_(True)).all()
    payload_subs = []
    all_statuses = []

    for sub in subs:
        active_servers = [s for s in sub.servers if s.is_active]
        status = _subscription_status(active_servers)
        all_statuses.append(status)
        payload_subs.append({
            "id": sub.id,
            "name": sub.name,
            "status": status,
            "last_fetched_at": sub.last_fetched_at,
            "servers": [_server_payload(db, s) for s in active_servers],
        })

    if "down" in all_statuses:
        overall = "down"
    elif "degraded" in all_statuses:
        overall = "degraded"
    elif all_statuses:
        overall = "operational"
    else:
        overall = "unknown"

    recent_incidents = (
        db.query(Incident).order_by(Incident.started_at.desc()).limit(20).all()
    )

    return {
        "overall_status": overall,
        "generated_at": dt.datetime.now(dt.timezone.utc),
        "subscriptions": payload_subs,
        "recent_incidents": [
            {
                "id": inc.id,
                "started_at": inc.started_at,
                "resolved_at": inc.resolved_at,
                "severity": inc.severity,
                "summary": inc.summary,
            }
            for inc in recent_incidents
        ],
    }


@app.post("/api/check-now")
async def trigger_check_now(background_tasks: BackgroundTasks):
    """Trigger an immediate monitoring cycle."""
    background_tasks.add_task(run_cycle)
    return {"message": "Check cycle started", "status": "running"}


@app.post("/api/subscriptions/{sub_id}/sync")
async def sync_subscription_endpoint(sub_id: int, db: Session = Depends(get_db)):
    sub = db.query(Subscription).get(sub_id)
    if not sub:
        raise HTTPException(404, "Subscription not found")

    await sync_subscription(db, sub)
    servers = [s for s in sub.servers if s.is_active]
    semaphore = asyncio.Semaphore(CHECK_CONCURRENCY)
    await asyncio.gather(*(check_server_by_id(s.id, s.raw_uri, semaphore) for s in servers))

    return {"message": f"Subscription '{sub.name}' synced and checked", "server_count": len(servers)}


@app.get("/api/servers/{server_id}/history")
def server_history(server_id: int, hours: int = 24, db: Session = Depends(get_db)):
    server = db.query(Server).get(server_id)
    if not server:
        raise HTTPException(404, "server not found")
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    checks = (
        db.query(CheckResult)
        .filter(CheckResult.server_id == server_id, CheckResult.checked_at >= since)
        .order_by(CheckResult.checked_at.asc())
        .all()
    )
    return [
        {"checked_at": c.checked_at, "status": c.status.value,
         "proxy_latency_ms": c.proxy_latency_ms, "tcp_latency_ms": c.tcp_latency_ms,
         "error": c.error}
        for c in checks
    ]


@app.get("/api/subscriptions")
def list_subscriptions(db: Session = Depends(get_db)):
    subs = db.query(Subscription).filter(Subscription.is_active.is_(True)).all()
    return [{"id": s.id, "name": s.name, "url": s.url,
             "server_count": len([srv for srv in s.servers if srv.is_active]), "last_fetched_at": s.last_fetched_at}
            for s in subs]


@app.post("/api/subscriptions")
async def add_subscription(payload: SubscriptionIn, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    existing = db.query(Subscription).filter(Subscription.url == payload.url).first()
    if existing:
        if not existing.is_active:
            existing.is_active = True
            existing.name = payload.name
            db.commit()
            background_tasks.add_task(run_cycle)
            return {"id": existing.id, "name": existing.name}
        raise HTTPException(400, "subscription already exists")

    sub = Subscription(name=payload.name, url=payload.url)
    db.add(sub)
    db.commit()
    db.refresh(sub)

    # Immediately trigger sync in background
    background_tasks.add_task(run_cycle)

    return {"id": sub.id, "name": sub.name}


@app.delete("/api/subscriptions/{sub_id}")
def remove_subscription(sub_id: int, db: Session = Depends(get_db)):
    sub = db.query(Subscription).get(sub_id)
    if not sub:
        raise HTTPException(404, "subscription not found")
    sub.is_active = False
    db.commit()
    return {"ok": True}


@app.get("/api/incidents")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.started_at.desc()).limit(50).all()
    return [
        {
            "id": inc.id,
            "started_at": inc.started_at,
            "resolved_at": inc.resolved_at,
            "severity": inc.severity,
            "summary": inc.summary,
        }
        for inc in incidents
    ]


# Mount frontend static files
frontend_dir = None
for candidate in [
    Path(__file__).resolve().parent.parent.parent / "frontend",
    Path(__file__).resolve().parent.parent / "frontend",
    Path("/frontend"),
    Path("./frontend"),
]:
    if candidate.exists() and (candidate / "index.html").exists():
        frontend_dir = candidate
        break

if frontend_dir:
    @app.get("/")
    async def serve_index():
        return FileResponse(frontend_dir / "index.html")

    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")


