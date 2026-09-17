"""v1.8 - Cron scan scheduler CRUD + dispatch regression tests."""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"


def _register():
    email = f"sched_{uuid.uuid4().hex[:8]}@example.com"
    payload = {"email": email, "password": "password123", "username": f"sched_{uuid.uuid4().hex[:6]}"}
    r = requests.post(f"{BASE_URL}/api/auth/register", json=payload, timeout=15)
    assert r.status_code in (200, 201), r.text
    data = r.json()
    token = data.get("access_token") or data.get("token")
    assert token
    return token, email


@pytest.fixture(scope="module")
def auth_headers():
    token, _ = _register()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def auth_headers_other():
    token, _ = _register()
    return {"Authorization": f"Bearer {token}"}


# --- Basic API health ---
def test_api_root_fast():
    t0 = time.time()
    r = requests.get(f"{BASE_URL}/api/", timeout=5)
    assert r.status_code in (200, 404)
    assert (time.time() - t0) < 3


# --- Auth requirements ---
def test_schedules_requires_auth():
    r = requests.get(f"{BASE_URL}/api/schedules", timeout=10)
    assert r.status_code in (401, 403)

    r2 = requests.post(f"{BASE_URL}/api/schedules", json={
        "name": "x", "scan_type": "recon", "target": "127.0.0.1", "cron": "* * * * *"
    }, timeout=10)
    assert r2.status_code in (401, 403)


# --- Create validation ---
def test_create_invalid_cron(auth_headers):
    r = requests.post(f"{BASE_URL}/api/schedules", headers=auth_headers, json={
        "name": "bad", "scan_type": "recon", "target": "127.0.0.1", "cron": "not a cron"
    }, timeout=10)
    assert r.status_code == 400, r.text


def test_create_invalid_scan_type(auth_headers):
    r = requests.post(f"{BASE_URL}/api/schedules", headers=auth_headers, json={
        "name": "bad", "scan_type": "nope", "target": "127.0.0.1", "cron": "* * * * *"
    }, timeout=10)
    assert r.status_code == 400, r.text


# --- Create ok ---
def test_create_schedule_ok(auth_headers):
    payload = {"name": "hourly test", "scan_type": "recon", "target": "127.0.0.1",
               "cron": "0 * * * *", "preset": "fast", "enabled": True}
    r = requests.post(f"{BASE_URL}/api/schedules", headers=auth_headers, json=payload, timeout=10)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["id"]
    assert d["name"] == "hourly test"
    assert d["enabled"] is True
    assert d["next_run_at"] is not None
    assert "_id" not in d


# --- List & isolation ---
def test_list_returns_only_own_schedules(auth_headers, auth_headers_other):
    r_a = requests.get(f"{BASE_URL}/api/schedules", headers=auth_headers, timeout=10)
    r_b = requests.get(f"{BASE_URL}/api/schedules", headers=auth_headers_other, timeout=10)
    assert r_a.status_code == 200 and r_b.status_code == 200
    a_ids = {s["id"] for s in r_a.json()}
    b_ids = {s["id"] for s in r_b.json()}
    assert a_ids.isdisjoint(b_ids)


# --- Patch enable/disable ---
def test_patch_pause_and_resume(auth_headers):
    create = requests.post(f"{BASE_URL}/api/schedules", headers=auth_headers, json={
        "name": "toggle", "scan_type": "recon", "target": "127.0.0.1",
        "cron": "0 * * * *", "preset": "fast", "enabled": True,
    }, timeout=10).json()
    sid = create["id"]
    r = requests.patch(f"{BASE_URL}/api/schedules/{sid}", headers=auth_headers,
                       json={"enabled": False}, timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert d["enabled"] is False
    assert d["next_run_at"] is None

    r2 = requests.patch(f"{BASE_URL}/api/schedules/{sid}", headers=auth_headers,
                        json={"enabled": True}, timeout=10)
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["enabled"] is True
    assert d2["next_run_at"] is not None


def test_patch_recron(auth_headers):
    create = requests.post(f"{BASE_URL}/api/schedules", headers=auth_headers, json={
        "name": "recron", "scan_type": "recon", "target": "127.0.0.1",
        "cron": "0 * * * *", "preset": "fast", "enabled": True,
    }, timeout=10).json()
    sid = create["id"]
    r = requests.patch(f"{BASE_URL}/api/schedules/{sid}", headers=auth_headers,
                       json={"cron": "*/30 * * * *"}, timeout=10)
    assert r.status_code == 200
    assert r.json()["cron"] == "*/30 * * * *"
    assert r.json()["next_run_at"] is not None

    bad = requests.patch(f"{BASE_URL}/api/schedules/{sid}", headers=auth_headers,
                        json={"cron": "invalid"}, timeout=10)
    assert bad.status_code == 400


# --- Delete + cross-user delete ---
def test_delete_own_and_cross_user(auth_headers, auth_headers_other):
    create = requests.post(f"{BASE_URL}/api/schedules", headers=auth_headers, json={
        "name": "delme", "scan_type": "recon", "target": "127.0.0.1",
        "cron": "0 * * * *", "preset": "fast", "enabled": True,
    }, timeout=10).json()
    sid = create["id"]
    # other user cannot delete
    r_cross = requests.delete(f"{BASE_URL}/api/schedules/{sid}", headers=auth_headers_other, timeout=10)
    assert r_cross.status_code == 404
    # owner deletes ok
    r = requests.delete(f"{BASE_URL}/api/schedules/{sid}", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    # gone
    lst = requests.get(f"{BASE_URL}/api/schedules", headers=auth_headers, timeout=10).json()
    assert sid not in {s["id"] for s in lst}


# --- Dispatch end-to-end (takes ~60-90s) ---
@pytest.mark.timeout(180)
def test_scheduler_dispatch_every_minute(auth_headers):
    create = requests.post(f"{BASE_URL}/api/schedules", headers=auth_headers, json={
        "name": "dispatch-test", "scan_type": "recon", "target": "127.0.0.1",
        "cron": "* * * * *", "preset": "fast", "enabled": True,
    }, timeout=10)
    assert create.status_code == 200, create.text
    sid = create.json()["id"]

    dispatched = False
    for _ in range(18):  # up to ~108s (18 * 6s)
        time.sleep(6)
        lst = requests.get(f"{BASE_URL}/api/schedules", headers=auth_headers, timeout=10).json()
        me = next((s for s in lst if s["id"] == sid), None)
        if me and me.get("last_run_at") and me.get("last_scan_id"):
            dispatched = True
            last_scan_id = me["last_scan_id"]
            break

    assert dispatched, "Scheduler did not dispatch within ~108s"

    # Verify scan exists via GET /api/scans
    scans = requests.get(f"{BASE_URL}/api/scans", headers=auth_headers, timeout=10).json()
    ids = {s["id"] for s in scans}
    assert last_scan_id in ids, "Dispatched scan not found in /api/scans"

    # cleanup
    requests.delete(f"{BASE_URL}/api/schedules/{sid}", headers=auth_headers, timeout=10)


# --- Basic regressions ---
def test_dashboard_stats(auth_headers):
    r = requests.get(f"{BASE_URL}/api/dashboard/stats", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    d = r.json()
    for k in ("total_scans", "active_scans", "vulnerabilities_found", "critical_alerts", "recent_activity"):
        assert k in d


def test_scans_list(auth_headers):
    r = requests.get(f"{BASE_URL}/api/scans", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
