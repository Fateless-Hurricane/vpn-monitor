"""
Turns raw check results into a server status + incident lifecycle.

Rules (tunable via env vars):
- proxy check fails                         -> "down" candidate
- proxy check succeeds but latency is high  -> "degraded"
- proxy check succeeds and latency is fine  -> "operational"
- an incident opens after N consecutive non-operational checks (avoids
  flapping from a single blip opening an incident)
- an incident resolves the moment a check comes back operational
"""
import os
import datetime as dt

from sqlalchemy.orm import Session

from .models import Server, Incident, CheckResult, ServerStatus

DEGRADED_LATENCY_MS = float(os.getenv("DEGRADED_LATENCY_MS", "250"))
FAILURES_BEFORE_INCIDENT = int(os.getenv("FAILURES_BEFORE_INCIDENT", "2"))


def classify(check: CheckResult) -> ServerStatus:
    if not check.proxy_success:
        return ServerStatus.down
    if check.proxy_latency_ms and check.proxy_latency_ms > DEGRADED_LATENCY_MS:
        return ServerStatus.degraded
    return ServerStatus.operational


def apply_check(db: Session, server: Server, check: CheckResult) -> None:
    status = classify(check)
    check.status = status

    server.current_status = status
    # Only set current_latency_ms when the proxy check actually succeeded
    server.current_latency_ms = check.proxy_latency_ms if check.proxy_success else None
    server.last_checked_at = check.checked_at

    open_incident = (
        db.query(Incident)
        .filter(Incident.server_id == server.id, Incident.resolved_at.is_(None))
        .first()
    )

    if status == ServerStatus.operational:
        server.consecutive_failures = 0
        if open_incident:
            open_incident.resolved_at = check.checked_at
    else:
        server.consecutive_failures += 1
        if not open_incident and server.consecutive_failures >= FAILURES_BEFORE_INCIDENT:
            summary = check.error
            if not summary:
                if status == ServerStatus.down:
                    summary = "Proxy connectivity check failed"
                else:
                    summary = f"Degraded latency — {check.proxy_latency_ms} ms"
            db.add(Incident(
                server_id=server.id,
                started_at=check.checked_at,
                severity="down" if status == ServerStatus.down else "degraded",
                summary=summary,
            ))
