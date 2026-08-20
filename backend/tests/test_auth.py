import os
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Use a temporary sqlite database file for tests
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db_path = temp_db.name
temp_db.close()

os.environ["DATABASE_URL"] = f"sqlite:///{temp_db_path}"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "secret123"

from app.main import app
from app.database import Base, engine, SessionLocal, init_db
from app.models import Subscription, Server, ServerStatus

init_db()
client = TestClient(app)


def teardown_module():
    try:
        os.remove(temp_db_path)
    except OSError:
        pass


def test_public_status_does_not_leak_urls_or_raw_uri():
    db = SessionLocal()
    sub = Subscription(name="Secret Sub", url="https://secret-provider.com/sub/private_token_123")
    db.add(sub)
    db.flush()
    srv = Server(
        subscription_id=sub.id,
        fingerprint="fp1",
        protocol="vless",
        remark="US Node",
        address="private-host.com",
        port=443,
        country_name="United States",
        country_flag="🇺🇸",
        raw_uri="vless://secret-uuid@private-host.com:443?security=reality#US",
        current_status=ServerStatus.operational,
        current_latency_ms=45.0,
    )
    db.add(srv)
    db.commit()
    db.close()

    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()

    # Verify no private token or share link is exposed in the public payload
    content_str = res.text
    assert "private_token_123" not in content_str
    assert "secret-uuid" not in content_str
    assert "secret-provider.com" not in content_str

    assert data["summary"]["total_nodes"] >= 1
    assert data["subscriptions"][0]["name"] == "Secret Sub"
    assert "url" not in data["subscriptions"][0]


def test_auth_login_and_protected_routes():
    # Attempt unauthenticated access to admin endpoints
    res = client.get("/api/admin/subscriptions")
    assert res.status_code == 401

    res = client.post("/api/subscriptions", json={"name": "Test", "url": "https://example.com/test"})
    assert res.status_code == 401

    res = client.post("/api/check-now")
    assert res.status_code == 401

    # Invalid login
    res = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert res.status_code == 401

    # Valid login
    res = client.post("/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert res.status_code == 200
    token = res.json()["token"]
    assert token

    headers = {"Authorization": f"Bearer {token}"}

    # Verify /api/auth/me
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200
    assert res.json()["username"] == "admin"

    # Authenticated access to admin subscriptions
    res = client.get("/api/admin/subscriptions", headers=headers)
    assert res.status_code == 200
    admin_subs = res.json()
    assert any("secret-provider.com" in s["url"] for s in admin_subs)

    # Logout
    res = client.post("/api/auth/logout", headers=headers)
    assert res.status_code == 200

    # Token revoked
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 401
