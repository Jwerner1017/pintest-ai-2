"""
Backend API tests for PentestAI Platform
Covers: auth, scans (recon/vuln/network), AI chat, dashboard, reports
"""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://sec-ops-1.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

TEST_EMAIL = "tester@example.com"
TEST_PASSWORD = "test123456"
TEST_USERNAME = "tester"


# ---------------- Fixtures ----------------

@pytest.fixture(scope="session")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="session")
def auth_token(session):
    # Try login first, if fails, register
    r = session.post(f"{API}/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}, timeout=30)
    if r.status_code == 200:
        return r.json()["access_token"]
    # register
    r = session.post(f"{API}/auth/register", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD, "username": TEST_USERNAME
    }, timeout=30)
    assert r.status_code == 200, f"Register failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}


# ---------------- Auth ----------------

class TestAuth:
    def test_root(self, session):
        r = session.get(f"{API}/", timeout=15)
        assert r.status_code == 200
        assert "PentestAI" in r.json().get("message", "")

    def test_register_duplicate(self, session, auth_token):
        r = session.post(f"{API}/auth/register", json={
            "email": TEST_EMAIL, "password": TEST_PASSWORD, "username": TEST_USERNAME
        }, timeout=15)
        assert r.status_code == 400

    def test_login_success(self, session):
        r = session.post(f"{API}/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert data["user"]["email"] == TEST_EMAIL

    def test_login_invalid(self, session):
        r = session.post(f"{API}/auth/login", json={"email": TEST_EMAIL, "password": "wrong"}, timeout=15)
        assert r.status_code == 401

    def test_me(self, session, auth_headers):
        r = session.get(f"{API}/auth/me", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert r.json()["email"] == TEST_EMAIL

    def test_me_no_token(self, session):
        r = session.get(f"{API}/auth/me", timeout=15)
        assert r.status_code in (401, 403)


# ---------------- Scans (real scanner) ----------------

class TestScans:
    scan_ids = {}

    def test_invalid_target(self, session, auth_headers):
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "recon", "target": "not a domain!!!"
        }, timeout=30)
        assert r.status_code == 400

    def test_recon_scan_google(self, session, auth_headers):
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "recon", "target": "google.com"
        }, timeout=180)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["status"] == "completed"
        assert data["scan_type"] == "recon"
        results = data["results"]
        # Real scanner assertions
        assert results.get("ip_address") and results["ip_address"] != "Unable to resolve"
        assert isinstance(results.get("dns_records"), list) and len(results["dns_records"]) > 0
        assert isinstance(results.get("ports"), list)
        assert "whois" in results
        assert isinstance(results.get("vulnerabilities"), list)
        TestScans.scan_ids["recon"] = data["id"]

    def test_vuln_scan(self, session, auth_headers):
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "vuln", "target": "google.com"
        }, timeout=180)
        assert r.status_code == 200, r.text
        data = r.json()
        results = data["results"]
        assert isinstance(results.get("vulnerabilities"), list) and len(results["vulnerabilities"]) > 0
        assert "risk_score" in results
        TestScans.scan_ids["vuln"] = data["id"]

    def test_network_scan(self, session, auth_headers):
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "network", "target": "google.com"
        }, timeout=60)
        assert r.status_code == 200
        assert r.json()["results"]["scan_type"] == "network_analysis"
        TestScans.scan_ids["network"] = r.json()["id"]

    def test_list_scans(self, session, auth_headers):
        r = session.get(f"{API}/scans", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert len(r.json()) >= 3

    def test_get_scan(self, session, auth_headers):
        sid = TestScans.scan_ids.get("recon")
        assert sid
        r = session.get(f"{API}/scans/{sid}", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        assert r.json()["id"] == sid

    def test_get_scan_not_found(self, session, auth_headers):
        r = session.get(f"{API}/scans/{uuid.uuid4()}", headers=auth_headers, timeout=15)
        assert r.status_code == 404


# ---------------- Dashboard ----------------

class TestDashboard:
    def test_stats(self, session, auth_headers):
        r = session.get(f"{API}/dashboard/stats", headers=auth_headers, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert data["total_scans"] >= 3
        assert "vulnerabilities_found" in data
        assert isinstance(data["recent_activity"], list)

    def test_vuln_trends(self, session, auth_headers):
        r = session.get(f"{API}/dashboard/vulnerability-trends", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert "trends" in r.json()


# ---------------- Reports ----------------

class TestReports:
    def test_generate_and_list(self, session, auth_headers):
        sid = TestScans.scan_ids.get("recon")
        assert sid, "Need recon scan first"
        r = session.post(f"{API}/reports/generate", headers=auth_headers, json=[sid], timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["scan_count"] == 1
        assert "summary" in data
        # list
        r2 = session.get(f"{API}/reports", headers=auth_headers, timeout=15)
        assert r2.status_code == 200
        assert len(r2.json()["reports"]) >= 1


# ---------------- AI Chat ----------------

class TestAIChat:
    def test_chat(self, session, auth_headers):
        r = session.post(f"{API}/chat", headers=auth_headers, json={
            "message": "What is nmap in one short sentence?"
        }, timeout=90)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("response") and len(data["response"]) > 5
        assert data.get("session_id")

    def test_chat_history(self, session, auth_headers):
        time.sleep(1)
        r = session.get(f"{API}/chat/history", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert isinstance(r.json().get("history"), list)


# ---------------- Cleanup ----------------

class TestZCleanup:
    def test_delete_scans(self, session, auth_headers):
        for sid in list(TestScans.scan_ids.values()):
            r = session.delete(f"{API}/scans/{sid}", headers=auth_headers, timeout=15)
            assert r.status_code == 200
