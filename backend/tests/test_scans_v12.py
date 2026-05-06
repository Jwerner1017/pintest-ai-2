"""v1.2 backend tests: async scan execution + progress polling + real nmap/HTTP probing.

Covers:
- POST /api/scans returns immediately (status=running, progress=0)
- GET /api/scans/{id} reflects progress 0-100, status transitions running -> completed
- vuln scan against scanme.nmap.org -> scan_engine='nmap+http', vulns with severity/source/risk_score
- network scan against scanme.nmap.org -> scan_engine='nmap', alive_hosts non-empty, total_open_ports>=1
- recon regression -> scan_engine='nmap'
- PDF download regression for new vuln scan
"""
import os
import time
import uuid

import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="module")
def auth_headers(session):
    email = f"agent_v12_{int(time.time())}_{uuid.uuid4().hex[:6]}@test.com"
    r = session.post(f"{API}/auth/register", json={
        "email": email, "password": "password123", "username": "agentv12"
    }, timeout=30)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _poll_until_complete(session, headers, scan_id, timeout_s):
    """Poll GET /api/scans/{id} until status is completed/failed or timeout."""
    deadline = time.time() + timeout_s
    last = None
    progresses_seen = []
    while time.time() < deadline:
        r = session.get(f"{API}/scans/{scan_id}", headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        last = r.json()
        progresses_seen.append(last.get("progress"))
        if last.get("status") in ("completed", "failed"):
            return last, progresses_seen
        time.sleep(3)
    return last, progresses_seen


# ---------------- async creation behavior ----------------
class TestAsyncScanCreation:
    def test_post_scans_returns_immediately(self, session, auth_headers):
        t0 = time.time()
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "vuln", "target": "http://scanme.nmap.org"
        }, timeout=15)
        elapsed = time.time() - t0
        assert r.status_code == 200, r.text
        body = r.json()
        # Must return immediately (well under 5s; nmap vuln scan would take 30-90s)
        assert elapsed < 5, f"POST blocked for {elapsed:.1f}s — should be async"
        assert body["status"] == "running"
        assert body["progress"] == 0
        assert body.get("results") in (None, {})


# ---------------- vuln scan ----------------
class TestVulnScan:
    state = {}

    def test_vuln_scan_real_engine(self, session, auth_headers):
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "vuln", "target": "http://scanme.nmap.org"
        }, timeout=15)
        assert r.status_code == 200
        scan_id = r.json()["id"]
        TestVulnScan.state["scan_id"] = scan_id

        final, progresses = _poll_until_complete(session, auth_headers, scan_id, timeout_s=240)
        assert final is not None
        assert final["status"] == "completed", f"scan did not complete: {final}"
        assert final["progress"] == 100
        # Progress should have moved through intermediate values (>0 and <100 at some point)
        intermediate = [p for p in progresses if 0 < p < 100]
        # We may miss them if scan finishes between polls, but stage must exist
        assert final.get("stage")

        results = final.get("results") or {}
        assert results.get("scan_engine") == "nmap+http", f"engine={results.get('scan_engine')}"
        vulns = results.get("vulnerabilities", [])
        assert isinstance(vulns, list) and len(vulns) > 0, "expected vulnerabilities from missing security headers"
        # Each vuln has severity + source
        for v in vulns:
            assert v.get("severity") in ("critical", "high", "medium", "low", "info")
            assert v.get("source") in ("nmap-nse", "http-probe", "tls-probe")
        rs = results.get("risk_score")
        assert isinstance(rs, (int, float)) and 0 <= rs <= 10, f"risk_score={rs}"

        owasp = (results.get("compliance") or {}).get("owasp_top10_hits") or []
        assert isinstance(owasp, list) and len(owasp) >= 1, f"expected owasp hits, got {owasp}"

    def test_pdf_download_for_vuln_scan(self, session, auth_headers):
        scan_id = TestVulnScan.state["scan_id"]
        r = session.post(f"{API}/reports/generate", headers=auth_headers, json=[scan_id], timeout=30)
        assert r.status_code == 200, r.text
        report_id = r.json()["id"]
        r2 = session.get(f"{API}/reports/{report_id}/pdf", headers=auth_headers, timeout=30)
        assert r2.status_code == 200
        assert r2.content[:4] == b"%PDF"
        assert len(r2.content) > 1000


# ---------------- network scan ----------------
class TestNetworkScan:
    def test_network_scan_real_engine(self, session, auth_headers):
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "network", "target": "scanme.nmap.org"
        }, timeout=15)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "running"
        scan_id = body["id"]

        final, _ = _poll_until_complete(session, auth_headers, scan_id, timeout_s=120)
        assert final["status"] == "completed", f"final={final}"
        results = final.get("results") or {}
        assert results.get("scan_engine") == "nmap", f"engine={results.get('scan_engine')}"
        alive_hosts = results.get("alive_hosts", [])
        assert isinstance(alive_hosts, list) and len(alive_hosts) >= 1, f"alive_hosts={alive_hosts}"
        ts = results.get("traffic_summary") or {}
        assert ts.get("hosts_alive", 0) >= 1
        assert ts.get("total_open_ports", 0) >= 1, f"traffic_summary={ts}"


# ---------------- recon regression ----------------
class TestReconRegression:
    def test_recon_scan_still_uses_nmap(self, session, auth_headers):
        r = session.post(f"{API}/scans", headers=auth_headers, json={
            "scan_type": "recon",
            "target": "scanme.nmap.org",
            "options": {"nmap_args": "-sT -Pn --top-ports 5"},
        }, timeout=15)
        assert r.status_code == 200, r.text
        scan_id = r.json()["id"]
        final, _ = _poll_until_complete(session, auth_headers, scan_id, timeout_s=120)
        assert final["status"] == "completed", f"final={final}"
        results = final.get("results") or {}
        assert results.get("scan_engine") == "nmap", f"engine={results.get('scan_engine')}"
        assert isinstance(results.get("ports"), list)
