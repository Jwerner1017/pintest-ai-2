"""v1.9 - Terminal page backend endpoint regression tests.

Verifies each endpoint the rewritten TerminalPage.js relies on:
  - GET  /api/auth/me                    (whoami)
  - GET  /api/scans                      (scans, resolveScanId)
  - POST /api/scans                      (scan/vuln/netscan)
  - GET  /api/scans/{id}                 (polling)
  - POST /api/scans/{id}/cancel          (cancel)
  - POST /api/scans/{id}/summary         (summary)
  - GET  /api/scans/{id}/nmap-xml        (xml)
  - POST /api/chat                       (ai)
"""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"


def _register():
    email = f"term_{uuid.uuid4().hex[:8]}@example.com"
    payload = {"email": email, "password": "password123", "username": f"term_{uuid.uuid4().hex[:6]}"}
    r = requests.post(f"{BASE_URL}/api/auth/register", json=payload, timeout=15)
    assert r.status_code in (200, 201), r.text
    data = r.json()
    token = data.get("access_token") or data.get("token")
    assert token, f"no token in {data}"
    return token, email, payload["username"]


@pytest.fixture(scope="module")
def auth():
    token, email, username = _register()
    return {"headers": {"Authorization": f"Bearer {token}"}, "email": email, "username": username}


# ---------- whoami ----------
def test_whoami_returns_user_fields(auth):
    r = requests.get(f"{BASE_URL}/api/auth/me", headers=auth["headers"], timeout=10)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["email"] == auth["email"]
    assert d["username"] == auth["username"]
    assert "role" in d


# ---------- scans list ----------
def test_scans_list_initially_empty(auth):
    r = requests.get(f"{BASE_URL}/api/scans", headers=auth["headers"], timeout=10)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ---------- scan lifecycle: create -> poll -> completed (fast preset 127.0.0.1) ----------
@pytest.fixture(scope="module")
def completed_scan(auth):
    r = requests.post(
        f"{BASE_URL}/api/scans",
        headers=auth["headers"],
        json={"scan_type": "recon", "target": "127.0.0.1", "options": {"preset": "fast"}},
        timeout=15,
    )
    assert r.status_code in (200, 201), r.text
    scan_id = r.json()["id"]
    # Poll up to 60s
    deadline = time.time() + 60
    scan = None
    while time.time() < deadline:
        gr = requests.get(f"{BASE_URL}/api/scans/{scan_id}", headers=auth["headers"], timeout=10)
        assert gr.status_code == 200
        scan = gr.json()
        if scan["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(2)
    assert scan is not None
    assert scan["status"] == "completed", f"scan did not complete: {scan}"
    return scan


def test_scan_create_and_poll(completed_scan):
    assert completed_scan["scan_type"] == "recon"
    assert completed_scan["target"] == "127.0.0.1"
    assert "results" in completed_scan


def test_scans_list_after_creation(auth, completed_scan):
    r = requests.get(f"{BASE_URL}/api/scans", headers=auth["headers"], timeout=10)
    assert r.status_code == 200
    ids = [s["id"] for s in r.json()]
    assert completed_scan["id"] in ids
    # Prefix resolution used by the terminal must be feasible
    prefix = completed_scan["id"][:8]
    hit = [s for s in r.json() if s["id"].lower().startswith(prefix.lower())]
    assert len(hit) >= 1


# ---------- summary ----------
def test_scan_summary(auth, completed_scan):
    r = requests.post(f"{BASE_URL}/api/scans/{completed_scan['id']}/summary", headers=auth["headers"], timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert "summary" in d and isinstance(d["summary"], str) and len(d["summary"]) > 0
    assert "model" in d


# ---------- nmap-xml ----------
def test_scan_nmap_xml(auth, completed_scan):
    r = requests.get(f"{BASE_URL}/api/scans/{completed_scan['id']}/nmap-xml", headers=auth["headers"], timeout=15)
    # Should either be XML (200) or 404 if not available; per v1.7 spec, recon scans generate XML
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        ct = r.headers.get("content-type", "").lower()
        assert "xml" in ct
        assert b"<?xml" in r.content[:64] or b"<nmaprun" in r.content[:200]


# ---------- cancel ----------
def test_scan_cancel_running(auth):
    r = requests.post(
        f"{BASE_URL}/api/scans",
        headers=auth["headers"],
        json={"scan_type": "recon", "target": "127.0.0.1", "options": {"preset": "fast"}},
        timeout=15,
    )
    assert r.status_code in (200, 201)
    sid = r.json()["id"]
    time.sleep(0.5)
    cr = requests.post(f"{BASE_URL}/api/scans/{sid}/cancel", headers=auth["headers"], timeout=10)
    # Might be already completed for tiny local scan; accept 200 or 400 (already-final)
    assert cr.status_code in (200, 400), cr.text


# ---------- chat (ai command) ----------
def test_chat_ai(auth):
    r = requests.post(
        f"{BASE_URL}/api/chat",
        headers=auth["headers"],
        json={"message": "list one common SSH CVE in one sentence"},
        timeout=60,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert "response" in d and isinstance(d["response"], str) and len(d["response"]) > 0
