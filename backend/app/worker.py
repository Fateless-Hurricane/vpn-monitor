import asyncio
import datetime as dt
import hashlib
import json
import logging
import os

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session

from .database import SessionLocal, init_db
from .models import Subscription, Server, CheckResult, SubscriptionChangeEvent, ServerStatus
from .subscription_parser import fetch_subscription, parse_subscription_content, guess_country, parse_uri
from .checker import run_full_check
from .incidents import apply_check

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("worker")

CHECK_INTERVAL_MINUTES = int(os.getenv("CHECK_INTERVAL_MINUTES", "30"))
CHECK_CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "5"))

_running_cycle_lock = asyncio.Lock()


def _hash_lines(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


async def sync_subscription(db: Session, sub: Subscription) -> None:
    """Fetch a subscription, detect changes, and upsert Server rows."""
    try:
        raw_lines = await fetch_subscription(sub.url)
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to fetch subscription %s (%s): %s", sub.name, sub.url, exc)
        return

    new_hash = _hash_lines(raw_lines)
    changed = new_hash != sub.last_hash
    now = dt.datetime.now(dt.timezone.utc)
    sub.last_fetched_at = now

    parsed = parse_subscription_content(raw_lines)
    seen_fingerprints = {p.fingerprint for p in parsed}
    existing = {s.fingerprint: s for s in sub.servers}

    added, removed = 0, 0

    for p in parsed:
        country_name, flag = guess_country(p.remark, p.address)
        if p.fingerprint in existing:
            server = existing[p.fingerprint]
            server.is_active = True
            server.remark = p.remark
            server.address = p.address
            server.port = p.port
            server.raw_uri = p.raw_uri
            server.country_name = country_name
            server.country_flag = flag
            server.last_seen_at = now
        else:
            server = Server(
                subscription_id=sub.id,
                fingerprint=p.fingerprint,
                protocol=p.protocol,
                remark=p.remark,
                address=p.address,
                port=p.port,
                country_name=country_name,
                country_flag=flag,
                raw_uri=p.raw_uri,
                is_active=True,
            )
            db.add(server)
            added += 1

    for fp, server in existing.items():
        if fp not in seen_fingerprints and server.is_active:
            server.is_active = False
            removed += 1

    if changed:
        sub.last_hash = new_hash
        db.add(SubscriptionChangeEvent(
            subscription_id=sub.id,
            added_count=added,
            removed_count=removed,
            detail=f"{added} added, {removed} removed (subscription content changed)",
        ))
        log.info("Subscription '%s' changed: +%d -%d", sub.name, added, removed)

    db.commit()


async def check_server_by_id(server_id: int, raw_uri: str, semaphore: asyncio.Semaphore) -> None:
    proxy = parse_uri(raw_uri)
    if proxy is None:
        return

    async with semaphore:
        outcome = await run_full_check(proxy)

    now = dt.datetime.now(dt.timezone.utc)
    with SessionLocal() as db:
        server = db.query(Server).get(server_id)
        if not server:
            return

        check = CheckResult(
            server_id=server.id,
            checked_at=now,
            tcp_success=outcome.tcp_success,
            tcp_latency_ms=outcome.tcp_latency_ms,
            proxy_success=outcome.proxy_success,
            proxy_latency_ms=outcome.proxy_latency_ms,
            error=outcome.error,
            status=ServerStatus.unknown,
        )
        db.add(check)
        db.flush()
        apply_check(db, server, check)
        db.commit()

        status_str = server.current_status.value if server.current_status else "unknown"
        if outcome.proxy_success:
            log.info("%s %s [%s] -> %s (%.0fms)", server.country_flag, server.remark, server.protocol, status_str, outcome.proxy_latency_ms or 0)
        elif outcome.tcp_success:
            log.info("%s %s [%s] -> %s (TCP %.0fms, Proxy failed: %s)", server.country_flag, server.remark, server.protocol, status_str, outcome.tcp_latency_ms or 0, outcome.error or "error")
        else:
            log.info("%s %s [%s] -> %s (unreachable: %s)", server.country_flag, server.remark, server.protocol, status_str, outcome.error or "unreachable")


async def run_cycle() -> None:
    if _running_cycle_lock.locked():
        log.info("A check cycle is already running; skipping overlapping cycle.")
        return

    async with _running_cycle_lock:
        log.info("Starting monitor cycle...")
        with SessionLocal() as db:
            subs = db.query(Subscription).filter(Subscription.is_active.is_(True)).all()
            for sub in subs:
                await sync_subscription(db, sub)

            servers = db.query(Server).filter(Server.is_active.is_(True)).all()
            server_targets = [(s.id, s.raw_uri) for s in servers]

        if not server_targets:
            log.info("No active servers to check.")
            return

        log.info("Checking %d servers with concurrency %d...", len(server_targets), CHECK_CONCURRENCY)
        semaphore = asyncio.Semaphore(CHECK_CONCURRENCY)
        await asyncio.gather(*(check_server_by_id(s_id, uri, semaphore) for s_id, uri in server_targets))
        log.info("Monitor cycle completed.")


def start_scheduler() -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_cycle,
        "interval",
        minutes=CHECK_INTERVAL_MINUTES,
        next_run_time=dt.datetime.now(),
        id="monitor_cycle",
        max_instances=1,
        replace_existing=True,
    )
    scheduler.start()
    return scheduler


async def main() -> None:
    init_db()
    start_scheduler()
    log.info("Worker started. Checking every %d minutes.", CHECK_INTERVAL_MINUTES)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())

