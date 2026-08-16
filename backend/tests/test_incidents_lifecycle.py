import os
import sys
import datetime as dt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Subscription, Server, CheckResult, Incident, ServerStatus
from app.incidents import apply_check


def make_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def make_server(db):
    sub = Subscription(name="Sub 1", url="https://example.com/sub1")
    db.add(sub)
    db.flush()
    server = Server(
        subscription_id=sub.id, fingerprint="x", protocol="vless",
        remark="Germany-01", address="1.2.3.4", port=443,
        country_name="Germany", country_flag="🇩🇪", raw_uri="vless://...",
    )
    db.add(server)
    db.commit()
    return server


def test_incident_opens_after_threshold_and_resolves_on_success():
    db = make_session()
    server = make_server(db)
    now = dt.datetime.now(dt.timezone.utc)

    # First failure: below FAILURES_BEFORE_INCIDENT threshold (default 2) -> no incident yet
    c1 = CheckResult(server_id=server.id, checked_at=now, proxy_success=False, proxy_latency_ms=None)
    db.add(c1); db.flush()
    apply_check(db, server, c1)
    db.commit()
    assert db.query(Incident).count() == 0
    assert server.consecutive_failures == 1

    # Second consecutive failure -> incident opens
    c2 = CheckResult(server_id=server.id, checked_at=now, proxy_success=False, proxy_latency_ms=None)
    db.add(c2); db.flush()
    apply_check(db, server, c2)
    db.commit()
    open_incidents = db.query(Incident).filter(Incident.resolved_at.is_(None)).all()
    assert len(open_incidents) == 1
    assert server.current_status == ServerStatus.down

    # Recovery -> incident resolves, failure counter resets
    c3 = CheckResult(server_id=server.id, checked_at=now, proxy_success=True, proxy_latency_ms=90.0)
    db.add(c3); db.flush()
    apply_check(db, server, c3)
    db.commit()
    assert server.consecutive_failures == 0
    assert server.current_status == ServerStatus.operational
    still_open = db.query(Incident).filter(Incident.resolved_at.is_(None)).count()
    assert still_open == 0
