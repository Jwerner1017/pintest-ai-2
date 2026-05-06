"""v1.3 backend tests: cancel + AI summary + janitor + split-router regression."""
import os
import time
import uuid

import pytest
import requests
from motor.motor_asyncio import AsyncIOMotorClient

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE_URL}/api"
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="module")
def auth_headers(session):
    email = f"v13_{int(time.time())}_{uuid.uuid4().hex[:6]}@test.com"
    r = session.post(f"{API}/auth/register", json={
        "email": email, "password": "password123", "username": "v13user"
    }, timeout=30)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture(scope="module")
def second_user_headers(session):
    email = f"v13b_{int(time.time())}_{uuid.uuid4().hex[:6]}@test.com"
    r = session.post(f"{API}/auth/register", json={
        "email": email, "password": "password123", "username": "v13userB"
    }, timeout=30)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}", "Content-Type": "application/json"}


def _poll(session, headers, scan_id, timeout_s):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        r = session.get(f"{API}/scans/{scan_id}", headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        last = r.json()
        if last.get("status") in ("completed", "failed", "cancelled"):
            return last
        time.sleep(2)
    return last


# =============== Regression after split ===============
class TestRouterSplitRegression:
    def test_root(self, session):
        r = session.get(f"{API}/", timeout=10)
        assert r.status_code == 200
        assert "1.3" in r.json().get("version", "")

    def test_auth_me(self, session, auth_headers):
        r = session.get(f"{API}/auth/me", headers=auth_headers, timeout=10)
        assert r.status_code == 200
        assert "@test.com" in r.json()["email"]

    def test_dashboard_stats(self, session, auth_headers):
        r = session.get(f"{API}/dashboard/stats", headers=auth_headers, timeout=10)
        assert r.status_code == 200
        body = r.json()
        for k in ("total_scans", "active_scans", "vulnerabilities_found", "critical_alerts", "recent_activity"):
            assert k in body

    def test_shodan_status(self, session, auth_headers):
        r = session.get(f"{API}/shodan/status", headers=auth_headers, timeout=10)
        assert r.status_code == 200
        assert "configured" in r.json()

    def test_chat_endpoint_alive(self, session, auth_headers):
        r = session.post(f"{API}/chat", headers=auth_headers, json={"message": "ping (one short word)"}, timeout=60)
        # Either 200 or 500 from upstream - we only check route is wired
        assert r.status_code in (200, 500)

    def test_reports_list(self, session, auth_headers):
        r = session.get(f"{API}/reports", headers=auth_headers, timeout=10)
        assert r.status_code == 200
        body = r.json()
        # Endpoint returns either a list or {"reports": [...]}
        reports = body if isinstance(body, list) else body.get("reports")
        assert isinstance(reports, list)


# =============== Cancel ===============
class TestCancel:
    def test_cancel_running_scan(self, session, auth_headers):
        # Start a vuln scan (long-running).
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "vuln", "target": "http://scanme.nmap.org"
        }, timeout=15)
        assert r.status_code == 200
        scan_id = r.json()["id"]
        # Wait for progress > 0
        time.sleep(3)
        c = session.post(f"{API}/scans/{scan_id}/cancel", headers=auth_headers, timeout=15)
        assert c.status_code == 200, c.text
        body = c.json()
        assert body["status"] == "cancelled"
        assert body.get("stage") == "Cancelled by user"

        # Verify persisted
        g = session.get(f"{API}/scans/{scan_id}", headers=auth_headers, timeout=10)
        assert g.json()["status"] == "cancelled"

    def test_cancel_completed_returns_400(self, session, auth_headers):
        # Quick recon scan to completion
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "recon", "target": "scanme.nmap.org",
            "options": {"nmap_args": "-sT -T4 --top-ports 5 -Pn"}
        }, timeout=15)
        assert r.status_code == 200
        scan_id = r.json()["id"]
        final = _poll(session, auth_headers, scan_id, timeout_s=120)
        assert final["status"] == "completed", f"final={final}"
        c = session.post(f"{API}/scans/{scan_id}/cancel", headers=auth_headers, timeout=15)
        assert c.status_code == 400
        # store for summary tests
        TestCancel.completed_scan_id = scan_id

    def test_cancel_unknown_scan_404(self, session, auth_headers):
        c = session.post(f"{API}/scans/{uuid.uuid4()}/cancel", headers=auth_headers, timeout=10)
        assert c.status_code == 404

    def test_cancel_other_user_404(self, session, auth_headers, second_user_headers):
        # owner starts a scan
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "vuln", "target": "http://scanme.nmap.org"
        }, timeout=15)
        assert r.status_code == 200
        scan_id = r.json()["id"]
        # second user attempts to cancel
        c = session.post(f"{API}/scans/{scan_id}/cancel", headers=second_user_headers, timeout=10)
        assert c.status_code == 404
        # cleanup: cancel as owner
        session.post(f"{API}/scans/{scan_id}/cancel", headers=auth_headers, timeout=10)


# =============== AI summary ===============
class TestAISummary:
    def test_summary_lifecycle(self, session, auth_headers):
        scan_id = getattr(TestCancel, "completed_scan_id", None)
        if not scan_id:
            # Create our own completed scan
            r = session.post(f"{API}/scans", headers=auth_headers, json={
                "scan_type": "recon", "target": "scanme.nmap.org",
                "options": {"nmap_args": "-sT -T4 --top-ports 5 -Pn"}
            }, timeout=15)
            scan_id = r.json()["id"]
            final = _poll(session, auth_headers, scan_id, timeout_s=120)
            assert final["status"] == "completed"

        # First call - generates
        r1 = session.post(f"{API}/scans/{scan_id}/summary", headers=auth_headers, timeout=90)
        assert r1.status_code == 200, r1.text
        b1 = r1.json()
        assert b1.get("cached") is False
        assert isinstance(b1.get("summary"), str) and len(b1["summary"]) > 20

        # Second call - cached
        r2 = session.post(f"{API}/scans/{scan_id}/summary", headers=auth_headers, timeout=30)
        assert r2.status_code == 200
        b2 = r2.json()
        assert b2.get("cached") is True
        assert b2["summary"] == b1["summary"]

    def test_summary_400_when_not_completed(self, session, auth_headers):
        # Start running scan and immediately try to summarise
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "vuln", "target": "http://scanme.nmap.org"
        }, timeout=15)
        scan_id = r.json()["id"]
        s = session.post(f"{API}/scans/{scan_id}/summary", headers=auth_headers, timeout=10)
        assert s.status_code == 400
        # cleanup
        session.post(f"{API}/scans/{scan_id}/cancel", headers=auth_headers, timeout=10)

    def test_summary_404_unknown(self, session, auth_headers):
        r = session.post(f"{API}/scans/{uuid.uuid4()}/summary", headers=auth_headers, timeout=10)
        assert r.status_code == 404


# =============== Janitor ===============
def test_janitor_reaps_orphaned():
    """Insert orphaned 'running' scan, call reap function, verify it becomes 'failed'."""
    import asyncio
    import sys
    sys.path.insert(0, "/app/backend")
    from routers.scans import reap_orphaned_scans  # noqa: E402

    async def _run():
        client = AsyncIOMotorClient(MONGO_URL)
        db = client[DB_NAME]
        scan_id = f"ORPHAN_{uuid.uuid4()}"
        await db.scans.insert_one({
            "id": scan_id, "user_id": "fake", "scan_type": "vuln",
            "target": "x", "status": "running", "progress": 50,
            "stage": "stuck", "results": None,
            "created_at": "2024-01-01T00:00:00+00:00",
        })
        try:
            count = await reap_orphaned_scans()
            assert count >= 1
            doc = await db.scans.find_one({"id": scan_id})
            assert doc["status"] == "failed"
            assert "Orphaned" in doc["stage"]
        finally:
            await db.scans.delete_one({"id": scan_id})
            client.close()

    asyncio.run(_run())
