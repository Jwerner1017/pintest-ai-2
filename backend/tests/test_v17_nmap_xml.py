"""v1.7 tests: GET /api/scans/{id}/nmap-xml raw XML download endpoint."""
import os
import time
import uuid

import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE_URL}/api"


def _register():
    email = f"v17_{int(time.time())}_{uuid.uuid4().hex[:6]}@test.com"
    r = requests.post(f"{API}/auth/register", json={
        "email": email, "password": "password123", "username": f"v17_{uuid.uuid4().hex[:6]}"
    }, timeout=30)
    assert r.status_code in (200, 201), r.text
    token = r.json().get("access_token") or r.json().get("token")
    assert token, r.text
    return token, email


@pytest.fixture(scope="module")
def auth():
    token, email = _register()
    return {"Authorization": f"Bearer {token}", "email": email}


def _start_and_wait(auth, scan_type="recon", target="127.0.0.1", preset="fast", timeout=90):
    r = requests.post(f"{API}/scans", json={
        "scan_type": scan_type, "target": target, "options": {"preset": preset}
    }, headers=auth, timeout=30)
    assert r.status_code == 200, r.text
    scan_id = r.json()["id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        g = requests.get(f"{API}/scans/{scan_id}", headers=auth, timeout=15)
        assert g.status_code == 200
        st = g.json().get("status")
        if st in ("completed", "failed", "cancelled"):
            return scan_id, g.json()
        time.sleep(2)
    pytest.fail(f"Scan {scan_id} did not complete in {timeout}s")


class TestNmapXmlDownload:
    def test_recon_scan_produces_nmap_xml_in_results(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        scan_id, data = _start_and_wait(headers)
        assert data["status"] == "completed", data
        xml = (data.get("results") or {}).get("nmap_xml")
        assert xml and isinstance(xml, str), "results.nmap_xml missing/empty"
        assert xml.lstrip().startswith("<?xml"), f"unexpected xml prefix: {xml[:50]!r}"
        # stash for later tests
        pytest.completed_scan_id = scan_id

    def test_download_endpoint_returns_xml(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        scan_id = getattr(pytest, "completed_scan_id", None)
        assert scan_id, "prev test did not run"
        r = requests.get(f"{API}/scans/{scan_id}/nmap-xml", headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        assert "application/xml" in r.headers.get("content-type", "")
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd and ".xml" in cd
        assert r.text.lstrip().startswith("<?xml"), r.text[:120]
        assert len(r.content) > 100

    def test_download_endpoint_unknown_scan_404(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        r = requests.get(f"{API}/scans/nonexistent-scan-id-xyz/nmap-xml", headers=headers, timeout=15)
        assert r.status_code in (403, 404), r.status_code

    def test_download_endpoint_requires_auth(self):
        r = requests.get(f"{API}/scans/anything/nmap-xml", timeout=15)
        assert r.status_code in (401, 403), r.status_code

    def test_download_other_user_scan_404(self, auth):
        # New user tries to download previous user's scan_id
        scan_id = getattr(pytest, "completed_scan_id", None)
        assert scan_id
        token2, _ = _register()
        r = requests.get(f"{API}/scans/{scan_id}/nmap-xml",
                         headers={"Authorization": f"Bearer {token2}"}, timeout=15)
        assert r.status_code in (403, 404), r.status_code


class TestRegression:
    """Quick sanity on unrelated endpoints that must still work."""

    def test_dashboard_stats(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        r = requests.get(f"{API}/dashboard/stats", headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data, dict)

    def test_list_scans(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        r = requests.get(f"{API}/scans", headers=headers, timeout=15)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_login_flow(self, auth):
        # register then login
        email = f"v17login_{uuid.uuid4().hex[:6]}@test.com"
        pw = "password123"
        rr = requests.post(f"{API}/auth/register", json={
            "email": email, "password": pw, "username": f"lg_{uuid.uuid4().hex[:6]}"
        }, timeout=30)
        assert rr.status_code in (200, 201)
        lr = requests.post(f"{API}/auth/login", json={"email": email, "password": pw}, timeout=30)
        assert lr.status_code == 200, lr.text
        assert lr.json().get("access_token") or lr.json().get("token")

    def test_sarif_export(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        scan_id = getattr(pytest, "completed_scan_id", None)
        assert scan_id
        r = requests.get(f"{API}/scans/{scan_id}/sarif", headers=headers, timeout=30)
        assert r.status_code == 200, r.text
        assert "sarif" in r.headers.get("content-type", "").lower() or "json" in r.headers.get("content-type", "").lower()

    def test_vuln_scan_produces_nmap_xml(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        scan_id, data = _start_and_wait(headers, scan_type="vuln", target="127.0.0.1", preset="fast", timeout=180)
        assert data["status"] == "completed", data
        xml = (data.get("results") or {}).get("nmap_xml")
        assert xml and xml.lstrip().startswith("<?xml"), "vuln scan missing nmap_xml"
        r = requests.get(f"{API}/scans/{scan_id}/nmap-xml", headers=headers, timeout=15)
        assert r.status_code == 200

    def test_network_scan_produces_nmap_xml(self, auth):
        headers = {k: v for k, v in auth.items() if k == "Authorization"}
        scan_id, data = _start_and_wait(headers, scan_type="network", target="127.0.0.1", preset="fast", timeout=180)
        assert data["status"] == "completed", data
        xml = (data.get("results") or {}).get("nmap_xml")
        assert xml and xml.lstrip().startswith("<?xml"), "network scan missing nmap_xml"
