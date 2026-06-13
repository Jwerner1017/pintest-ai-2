"""v1.4 distros feature tests — catalogue endpoints, recommendations, scan integration, AI chat addendum."""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL').rstrip('/')
API = f"{BASE_URL}/api"

EXPECTED_IDS = {"deft", "backbox", "kodachi", "pentoo"}
DISTRO_REQUIRED_FIELDS = ["id", "name", "full_name", "focus", "tagline", "best_for", "key_tools", "use_when", "site", "tags"]


@pytest.fixture(scope="module")
def auth_headers():
    email = f"v14d_{int(time.time())}_{uuid.uuid4().hex[:6]}@test.com"
    r = requests.post(f"{API}/auth/register", json={
        "email": email, "password": "password123", "username": email.split("@")[0]
    }, timeout=15)
    assert r.status_code in (200, 201), f"register failed: {r.status_code} {r.text}"
    token = r.json().get("access_token") or r.json().get("token")
    assert token, "no token returned"
    return {"Authorization": f"Bearer {token}"}


# ===== Root version =====
def test_root_version_is_1_4():
    r = requests.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    assert r.json().get("version") == "1.4.0"


# ===== GET /api/distros =====
def test_distros_requires_auth():
    r = requests.get(f"{API}/distros", timeout=10)
    assert r.status_code in (401, 403)


def test_distros_list_shape(auth_headers):
    r = requests.get(f"{API}/distros", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert "distros" in data
    distros = data["distros"]
    assert isinstance(distros, list)
    assert len(distros) == 4, f"expected 4 distros, got {len(distros)}"
    ids = {d["id"] for d in distros}
    assert ids == EXPECTED_IDS, f"unexpected ids: {ids}"
    for d in distros:
        for f in DISTRO_REQUIRED_FIELDS:
            assert f in d, f"distro {d.get('id')} missing field {f}"
        assert isinstance(d["best_for"], list) and len(d["best_for"]) >= 1
        assert isinstance(d["key_tools"], list) and len(d["key_tools"]) >= 1
        assert isinstance(d["tags"], list) and len(d["tags"]) >= 1
        assert d["site"].startswith("http")


# ===== GET /api/distros/{id} =====
@pytest.mark.parametrize("did", ["deft", "backbox", "kodachi", "pentoo"])
def test_distros_get_by_id(auth_headers, did):
    r = requests.get(f"{API}/distros/{did}", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert d["id"] == did
    for f in DISTRO_REQUIRED_FIELDS:
        assert f in d


def test_distros_get_unknown_404(auth_headers):
    r = requests.get(f"{API}/distros/unknown-xyz", headers=auth_headers, timeout=10)
    assert r.status_code == 404


# ===== Recommendations =====
@pytest.mark.parametrize("scan_type,expected", [
    ("recon", ["kodachi", "backbox"]),
    ("vuln", ["backbox", "pentoo"]),
    ("network", ["pentoo", "backbox"]),
    ("forensics", ["deft", "kodachi"]),
    ("incident_response", ["deft", "backbox"]),
])
def test_distros_recommend(auth_headers, scan_type, expected):
    r = requests.get(f"{API}/distros/recommend/{scan_type}", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert "primary" in data and "rationale" in data
    ids = [d["id"] for d in data["primary"]]
    assert ids == expected, f"{scan_type}: expected {expected}, got {ids}"
    assert isinstance(data["rationale"], str) and len(data["rationale"]) > 0


def test_distros_recommend_unknown(auth_headers):
    r = requests.get(f"{API}/distros/recommend/notathing", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data["primary"] == []
    assert data["rationale"] == ""


# ===== Scan integration — recommended_distros in results =====
def test_completed_scan_has_recommended_distros(auth_headers):
    r = requests.post(f"{API}/scans", headers=auth_headers,
                      json={"scan_type": "recon", "target": "scanme.nmap.org",
                            "options": {"preset": "fast"}}, timeout=15)
    assert r.status_code == 200
    scan_id = r.json()["id"]

    final = None
    start = time.time()
    while time.time() - start < 90:
        g = requests.get(f"{API}/scans/{scan_id}", headers=auth_headers, timeout=10)
        if g.status_code == 200:
            d = g.json()
            if d["status"] in ("completed", "failed", "cancelled"):
                final = d
                break
        time.sleep(2)
    assert final is not None, "scan did not finish in 90s"
    if final["status"] != "completed":
        pytest.skip(f"scan status={final['status']} — skipping rec_distros check")

    rec = final["results"].get("recommended_distros")
    assert rec is not None, "results.recommended_distros missing"
    assert "primary" in rec and "rationale" in rec
    ids = [d["id"] for d in rec["primary"]]
    assert ids == ["kodachi", "backbox"], f"recon expected [kodachi,backbox], got {ids}"
    assert len(rec["rationale"]) > 0


# ===== AI chat system prompt includes distro addendum =====
def test_chat_mentions_deft_for_forensics(auth_headers):
    r = requests.post(f"{API}/chat", headers=auth_headers,
                      json={"message": "What Linux distro should I use for memory forensics? Reply concisely.",
                            "session_id": f"distrotest-{uuid.uuid4().hex[:8]}"},
                      timeout=60)
    assert r.status_code == 200, r.text
    txt = r.json().get("response", "").lower()
    assert "deft" in txt, f"expected 'DEFT' in chat response, got: {txt[:300]}"


# ===== Vuln preset nmap_args differ between fast and thorough =====
def test_vuln_preset_nmap_args_differ():
    """Verify presets pass different nmap_args to vuln_service."""
    import sys
    sys.path.insert(0, "/app/backend")
    from services import presets as presets_service

    fast = presets_service.get_preset("vuln", "fast")
    thorough = presets_service.get_preset("vuln", "thorough")
    assert "nmap_args" in fast, f"fast preset missing nmap_args: {fast}"
    assert "nmap_args" in thorough, f"thorough preset missing nmap_args: {thorough}"
    assert fast["nmap_args"] != thorough["nmap_args"], \
        f"fast/thorough nmap_args identical: {fast['nmap_args']}"
    # Thorough should scan more ports than fast
    # Look for --top-ports number difference
    import re
    m_fast = re.search(r"--top-ports\s+(\d+)", fast["nmap_args"])
    m_thorough = re.search(r"--top-ports\s+(\d+)", thorough["nmap_args"])
    if m_fast and m_thorough:
        assert int(m_thorough.group(1)) > int(m_fast.group(1)), \
            f"thorough top-ports {m_thorough.group(1)} not > fast {m_fast.group(1)}"
