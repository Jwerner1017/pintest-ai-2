"""v1.4 feature tests — scan presets, NVD enrichment, lifespan, AI summary metadata, root version."""
import os
import time
import uuid
import asyncio
import pytest
import requests
from pymongo import MongoClient
from datetime import datetime, timezone

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL').rstrip('/')
API = f"{BASE_URL}/api"
MONGO_URL = os.environ.get('MONGO_URL')
DB_NAME = os.environ.get('DB_NAME')


@pytest.fixture(scope="module")
def auth_headers():
    email = f"v14_{int(time.time())}_{uuid.uuid4().hex[:6]}@test.com"
    r = requests.post(f"{API}/auth/register", json={
        "email": email, "password": "password123", "username": email.split("@")[0]
    }, timeout=15)
    assert r.status_code in (200, 201), f"register failed: {r.status_code} {r.text}"
    token = r.json().get("access_token") or r.json().get("token")
    if not token:
        lr = requests.post(f"{API}/auth/login", json={"email": email, "password": "password123"}, timeout=15)
        token = lr.json().get("access_token")
    assert token, "no token"
    return {"Authorization": f"Bearer {token}"}


# ===== Feature: Root / version =====
def test_root_returns_v14():
    r = requests.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data.get("version") == "1.4.0", f"expected 1.4.0, got {data}"


# ===== Feature: Presets endpoint =====
def test_presets_endpoint_requires_auth():
    r = requests.get(f"{API}/scans/presets", timeout=10)
    assert r.status_code in (401, 403)


def test_presets_endpoint_structure(auth_headers):
    r = requests.get(f"{API}/scans/presets", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    data = r.json()
    for key in ("recon", "vuln", "network"):
        assert key in data, f"missing {key}"
        assert len(data[key]) == 3, f"{key} should have 3 presets"
        names = {p["name"] for p in data[key]}
        assert names == {"fast", "thorough", "stealth"}, f"{key} names={names}"
        for p in data[key]:
            assert "label" in p and "description" in p
            # Should NOT leak internal nmap_args
            assert "nmap_args" not in p


# ===== Feature: Preset default is fast =====
def test_scan_no_preset_defaults_to_fast(auth_headers):
    r = requests.post(f"{API}/scans", headers=auth_headers,
                      json={"scan_type": "recon", "target": "scanme.nmap.org", "options": {}}, timeout=15)
    assert r.status_code == 200
    scan_id = r.json()["id"]
    # Wait up to 60s for completion
    final = _wait_for(scan_id, auth_headers, timeout=60)
    assert final["status"] == "completed", f"status={final['status']} stage={final.get('stage')}"
    assert final["results"].get("preset") == "fast"


def test_scan_preset_fast_recon_scanme(auth_headers):
    t0 = time.time()
    r = requests.post(f"{API}/scans", headers=auth_headers,
                      json={"scan_type": "recon", "target": "scanme.nmap.org",
                            "options": {"preset": "fast"}}, timeout=15)
    assert r.status_code == 200
    scan_id = r.json()["id"]
    final = _wait_for(scan_id, auth_headers, timeout=60)
    elapsed = time.time() - t0
    assert final["status"] == "completed"
    assert final["results"]["preset"] == "fast"
    assert final["results"]["scan_engine"] == "nmap"
    # Should be reasonably fast (top 20 ports). Allow 60s for network latency.
    assert elapsed < 60, f"fast preset too slow: {elapsed}s"


def test_scan_preset_thorough_recon_accepted(auth_headers):
    """Thorough preset accepted + results tagged. Don't wait for completion (can be 3+ min)."""
    r = requests.post(f"{API}/scans", headers=auth_headers,
                      json={"scan_type": "recon", "target": "scanme.nmap.org",
                            "options": {"preset": "thorough"}}, timeout=15)
    assert r.status_code == 200
    scan_id = r.json()["id"]
    # Poll briefly to confirm it kicked off with thorough stage label
    time.sleep(2)
    g = requests.get(f"{API}/scans/{scan_id}", headers=auth_headers, timeout=10).json()
    assert g["status"] in ("running", "completed")
    stage = g.get("stage", "") or ""
    assert "Thorough" in stage or "thorough" in stage.lower() or g.get("progress", 0) > 0
    # cleanup — cancel to free resources
    requests.post(f"{API}/scans/{scan_id}/cancel", headers=auth_headers, timeout=10)


# ===== Feature: AI summary metadata =====
def test_ai_summary_has_model_and_generated_at(auth_headers):
    # Create a recon scan and let it complete
    r = requests.post(f"{API}/scans", headers=auth_headers,
                      json={"scan_type": "recon", "target": "scanme.nmap.org",
                            "options": {"preset": "fast"}}, timeout=15)
    scan_id = r.json()["id"]
    final = _wait_for(scan_id, auth_headers, timeout=60)
    if final["status"] != "completed":
        pytest.skip(f"scan did not complete: {final['status']}")

    # First call — should not be cached
    s1 = requests.post(f"{API}/scans/{scan_id}/summary", headers=auth_headers, timeout=60)
    assert s1.status_code == 200, s1.text
    d1 = s1.json()
    assert "summary" in d1 and d1["summary"]
    assert d1.get("model") == "claude-sonnet-4-5-20250929"
    assert d1.get("generated_at")
    assert d1.get("cached") is False
    # ISO8601 parseable
    datetime.fromisoformat(d1["generated_at"])

    # Second call — cached
    s2 = requests.post(f"{API}/scans/{scan_id}/summary", headers=auth_headers, timeout=15)
    assert s2.status_code == 200
    d2 = s2.json()
    assert d2.get("cached") is True
    assert d2["model"] == d1["model"]
    assert d2["generated_at"] == d1["generated_at"]
    assert d2["summary"] == d1["summary"]


# ===== Feature: NVD enrichment (unit test on service directly) =====
def test_nvd_service_enrich_and_cache():
    """Test nvd_service _query_nvd (sync NVD fetch) + verify cache write via pymongo.

    Uses sync _query_nvd + manual cache simulation so we avoid motor/event-loop coupling
    inside a sync pytest.
    """
    import sys
    sys.path.insert(0, "/app/backend")
    from services import nvd_service

    # Clear cache doc
    mc = MongoClient(MONGO_URL)
    mc[DB_NAME].cve_cache.delete_one({"keyword": "openssh 7.4"})

    # 1) Sync NVD fetch — should return CVEs for OpenSSH 7.4
    t0 = time.time()
    cves = nvd_service._query_nvd("OpenSSH 7.4")
    fresh_time = time.time() - t0

    if not cves:
        pytest.skip("NVD API returned no CVEs (possible rate limit/network) — skipping")

    # Validate shape of each CVE record
    for c in cves:
        assert c.get("id", "").startswith("CVE-")
        assert c.get("severity") in ("critical", "high", "medium", "low", "info")
        if c.get("cvss") is not None:
            assert isinstance(c["cvss"], (int, float))

    # 2) Write to cache (simulating what _lookup_cves does) and read back
    mc[DB_NAME].cve_cache.update_one(
        {"keyword": "openssh 7.4"},
        {"$set": {"keyword": "openssh 7.4", "cves": cves,
                  "cached_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    cached_doc = mc[DB_NAME].cve_cache.find_one({"keyword": "openssh 7.4"})
    assert cached_doc is not None and cached_doc.get("cves")
    assert len(cached_doc["cves"]) == len(cves)

    # 3) Freshness helper
    assert nvd_service._fresh(cached_doc["cached_at"]) is True
    mc.close()
    assert fresh_time < 30, f"NVD query too slow: {fresh_time}s"


# ===== Feature: Lifespan janitor — existing v1.3 test covers janitor; just verify app boots cleanly =====
def test_backend_healthy_after_lifespan_migration():
    r = requests.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    # Also ensure auth router still mounted
    r2 = requests.post(f"{API}/auth/register", json={
        "email": f"lifecheck_{uuid.uuid4().hex[:8]}@t.com", "password": "password123", "username": "life"
    }, timeout=15)
    assert r2.status_code in (200, 201)


# ===== Helpers =====
def _wait_for(scan_id: str, headers: dict, timeout: int = 60) -> dict:
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(f"{API}/scans/{scan_id}", headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            if d["status"] in ("completed", "failed", "cancelled"):
                return d
        time.sleep(2)
    # final fetch
    return requests.get(f"{API}/scans/{scan_id}", headers=headers, timeout=10).json()
