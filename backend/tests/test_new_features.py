"""
Tests for new features: Bulk Scans, Scheduled Scans, and CVE Details.
"""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE_URL}/api"

TEST_EMAIL = "tester@example.com"
TEST_PASSWORD = "test123456"
TEST_USERNAME = "tester"


@pytest.fixture(scope="session")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="session")
def auth_headers(session):
    r = session.post(f"{API}/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}, timeout=30)
    if r.status_code != 200:
        r = session.post(f"{API}/auth/register", json={
            "email": TEST_EMAIL, "password": TEST_PASSWORD, "username": TEST_USERNAME
        }, timeout=30)
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# -------------- Bulk Scans --------------
class TestBulkScans:
    ids = {}

    def test_create_bulk_scan_with_targets(self, session, auth_headers):
        r = session.post(f"{API}/bulk-scans", headers=auth_headers, json={
            "scan_type": "recon",
            "targets": ["google.com", "github.com"]
        }, timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["total_targets"] == 2
        assert data["status"] in ("pending", "running")
        TestBulkScans.ids["multi"] = data["id"]

    def test_create_bulk_scan_cidr(self, session, auth_headers):
        # Very small CIDR (2 usable hosts)
        r = session.post(f"{API}/bulk-scans", headers=auth_headers, json={
            "scan_type": "recon",
            "targets": [],
            "cidr": "192.168.100.0/30"
        }, timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        # /30 has 2 usable hosts
        assert data["total_targets"] == 2
        TestBulkScans.ids["cidr"] = data["id"]

    def test_bulk_scan_cidr_too_large(self, session, auth_headers):
        r = session.post(f"{API}/bulk-scans", headers=auth_headers, json={
            "scan_type": "recon", "targets": [], "cidr": "10.0.0.0/16"
        }, timeout=15)
        assert r.status_code == 400

    def test_bulk_scan_no_targets(self, session, auth_headers):
        r = session.post(f"{API}/bulk-scans", headers=auth_headers, json={
            "scan_type": "recon", "targets": []
        }, timeout=15)
        assert r.status_code == 400

    def test_list_bulk_scans(self, session, auth_headers):
        r = session.get(f"{API}/bulk-scans", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert "bulk_scans" in r.json()
        assert len(r.json()["bulk_scans"]) >= 1

    def test_get_bulk_scan_and_wait_complete(self, session, auth_headers):
        bid = TestBulkScans.ids["multi"]
        # Wait for bulk scan to complete (recon on 2 real hosts)
        completed = False
        data = None
        for _ in range(60):
            r = session.get(f"{API}/bulk-scans/{bid}", headers=auth_headers, timeout=30)
            assert r.status_code == 200
            data = r.json()
            if data["status"] == "completed":
                completed = True
                break
            time.sleep(3)
        assert completed, f"Bulk scan did not complete in time. Last status: {data['status'] if data else 'n/a'}"
        assert data["completed"] + data["failed"] == data["total_targets"]
        assert isinstance(data.get("results"), list)
        assert len(data["results"]) == 2
        # each result should have vulnerabilities_count
        for res in data["results"]:
            assert "target" in res
            if res.get("status") == "completed":
                assert "vulnerabilities_count" in res

    def test_get_bulk_scan_not_found(self, session, auth_headers):
        r = session.get(f"{API}/bulk-scans/{uuid.uuid4()}", headers=auth_headers, timeout=15)
        assert r.status_code == 404


# -------------- Scheduled Scans --------------
class TestScheduledScans:
    ids = {}

    def test_create_scheduled_scan_daily(self, session, auth_headers):
        r = session.post(f"{API}/scheduled-scans", headers=auth_headers, json={
            "name": "TEST_daily_scan",
            "scan_type": "recon",
            "targets": ["example.com"],
            "schedule_type": "daily",
            "schedule_time": "03:30",
            "enabled": True
        }, timeout=15)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["name"] == "TEST_daily_scan"
        assert data["schedule_type"] == "daily"
        assert data["enabled"] is True
        assert data["next_run"] is not None
        TestScheduledScans.ids["daily"] = data["id"]

    def test_create_scheduled_scan_weekly(self, session, auth_headers):
        r = session.post(f"{API}/scheduled-scans", headers=auth_headers, json={
            "name": "TEST_weekly",
            "targets": ["example.com"],
            "schedule_type": "weekly",
            "schedule_time": "10:00",
            "schedule_day": 1,
        }, timeout=15)
        assert r.status_code == 200
        TestScheduledScans.ids["weekly"] = r.json()["id"]

    def test_create_scheduled_scan_monthly(self, session, auth_headers):
        r = session.post(f"{API}/scheduled-scans", headers=auth_headers, json={
            "name": "TEST_monthly",
            "targets": ["example.com"],
            "schedule_type": "monthly",
            "schedule_time": "23:59",
            "schedule_day": 15,
        }, timeout=15)
        assert r.status_code == 200
        TestScheduledScans.ids["monthly"] = r.json()["id"]

    def test_invalid_schedule_time(self, session, auth_headers):
        r = session.post(f"{API}/scheduled-scans", headers=auth_headers, json={
            "name": "TEST_bad", "targets": ["example.com"],
            "schedule_type": "daily", "schedule_time": "25:99"
        }, timeout=15)
        assert r.status_code == 400

    def test_invalid_schedule_type(self, session, auth_headers):
        r = session.post(f"{API}/scheduled-scans", headers=auth_headers, json={
            "name": "TEST_bad", "targets": ["example.com"],
            "schedule_type": "yearly", "schedule_time": "10:00"
        }, timeout=15)
        assert r.status_code == 400

    def test_invalid_target(self, session, auth_headers):
        r = session.post(f"{API}/scheduled-scans", headers=auth_headers, json={
            "name": "TEST_bad", "targets": ["!!!bad!!!"],
            "schedule_type": "daily", "schedule_time": "10:00"
        }, timeout=15)
        assert r.status_code == 400

    def test_list_scheduled_scans(self, session, auth_headers):
        r = session.get(f"{API}/scheduled-scans", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        names = [s["name"] for s in r.json()["scheduled_scans"]]
        assert "TEST_daily_scan" in names

    def test_toggle_scheduled_scan(self, session, auth_headers):
        sid = TestScheduledScans.ids["daily"]
        # disable via query param (as frontend does)
        r = session.patch(f"{API}/scheduled-scans/{sid}?enabled=false", headers=auth_headers, timeout=15)
        assert r.status_code == 200, r.text
        assert r.json()["enabled"] is False
        # re-enable
        r = session.patch(f"{API}/scheduled-scans/{sid}?enabled=true", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert r.json()["enabled"] is True

    def test_manual_trigger(self, session, auth_headers):
        sid = TestScheduledScans.ids["daily"]
        r = session.post(f"{API}/scheduled-scans/{sid}/run", headers=auth_headers, timeout=30)
        assert r.status_code == 200, r.text
        assert "bulk_scan_id" in r.json()
        # verify last_run updated
        r2 = session.get(f"{API}/scheduled-scans/{sid}", headers=auth_headers, timeout=15)
        assert r2.status_code == 200
        assert r2.json()["last_run"] is not None

    def test_delete_scheduled_scans(self, session, auth_headers):
        for sid in list(TestScheduledScans.ids.values()):
            r = session.delete(f"{API}/scheduled-scans/{sid}", headers=auth_headers, timeout=15)
            assert r.status_code == 200
        # verify 404 after delete
        r = session.get(f"{API}/scheduled-scans/{list(TestScheduledScans.ids.values())[0]}",
                        headers=auth_headers, timeout=15)
        assert r.status_code == 404


# -------------- CVE Details --------------
class TestCVE:
    def test_cve_lookup_log4shell(self, session, auth_headers):
        r = session.get(f"{API}/cve/CVE-2021-44228", headers=auth_headers, timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["description"]
        assert data["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        assert data.get("score") is not None
        assert isinstance(data.get("references"), list)
        assert data.get("source") == "NVD"

    def test_cve_cache_faster(self, session, auth_headers):
        # First call may already be cached from prior test
        t1 = time.time()
        r1 = session.get(f"{API}/cve/CVE-2021-44228", headers=auth_headers, timeout=30)
        d1 = time.time() - t1
        assert r1.status_code == 200
        # Second call should be from cache => faster
        t2 = time.time()
        r2 = session.get(f"{API}/cve/CVE-2021-44228", headers=auth_headers, timeout=30)
        d2 = time.time() - t2
        assert r2.status_code == 200
        # Cache should be significantly fast (<2s round trip)
        assert d2 < 3.0, f"Cached response too slow: {d2:.2f}s"
        assert r1.json()["cve_id"] == r2.json()["cve_id"]

    def test_cve_invalid_format(self, session, auth_headers):
        r = session.get(f"{API}/cve/NOT-A-CVE", headers=auth_headers, timeout=15)
        assert r.status_code == 400

    def test_cve_not_found(self, session, auth_headers):
        r = session.get(f"{API}/cve/CVE-1999-99999", headers=auth_headers, timeout=30)
        assert r.status_code in (404, 502)
