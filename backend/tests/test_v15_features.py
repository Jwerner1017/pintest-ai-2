"""v1.5 tests — SARIF 2.1 export + lifespan self-heal + runtime nmap check."""
import os
import json
import time
import uuid
import asyncio
import importlib

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")


def _register():
    suffix = uuid.uuid4().hex[:8]
    email = f"v15_{int(time.time())}_{suffix}@test.com"
    r = requests.post(
        f"{BASE_URL}/api/auth/register",
        json={"email": email, "password": "password123", "username": f"v15_{suffix}"},
        timeout=15,
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"], email


@pytest.fixture(scope="module")
def auth():
    token, email = _register()
    return {"Authorization": f"Bearer {token}"}, email


def _run_scan(headers, scan_type="recon", target="192.0.2.1", preset="fast", timeout=120):
    body = {"scan_type": scan_type, "target": target, "options": {"preset": preset}}
    r = requests.post(f"{BASE_URL}/api/scans", json=body, headers=headers, timeout=60)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            g = requests.get(f"{BASE_URL}/api/scans/{sid}", headers=headers, timeout=60)
        except requests.exceptions.RequestException:
            time.sleep(3)
            continue
        assert g.status_code == 200
        if g.json()["status"] in ("completed", "failed", "cancelled"):
            return g.json()
        time.sleep(3)
    pytest.fail(f"scan {sid} did not finish in {timeout}s")


# ---------------------------------------------------------------------------
# Root version
# ---------------------------------------------------------------------------
def test_root_version_150():
    r = requests.get(f"{BASE_URL}/api/", timeout=10)
    assert r.status_code == 200
    assert r.json()["version"] == "1.5.0"


# ---------------------------------------------------------------------------
# Runtime nmap check — module-level NMAP_AVAILABLE removed
# ---------------------------------------------------------------------------
def test_nmap_available_is_runtime_function():
    import sys
    sys.path.insert(0, "/app/backend")
    for mod_name in ("services.nmap_service", "services.vuln_service", "services.network_service"):
        mod = importlib.import_module(mod_name)
        assert not hasattr(mod, "NMAP_AVAILABLE"), f"{mod_name} should not define NMAP_AVAILABLE module-level"
        assert hasattr(mod, "_nmap_available"), f"{mod_name} missing _nmap_available()"
        assert callable(mod._nmap_available)


# ---------------------------------------------------------------------------
# SARIF 2.1 — scan endpoint
# ---------------------------------------------------------------------------
def test_scan_sarif_endpoint(auth):
    headers, _ = auth
    # SARIF requires completed scan — use mock vuln target (192.0.2.1) to ensure quick completion + vulns
    scan = _run_scan(headers, scan_type="vuln", target="scanme.nmap.org", preset="fast", timeout=120)
    assert scan["status"] == "completed", scan

    r = requests.get(f"{BASE_URL}/api/scans/{scan['id']}/sarif", headers=headers, timeout=15)
    assert r.status_code == 200, r.text
    assert "application/sarif+json" in r.headers.get("content-type", "")
    assert r.text.lstrip().startswith("{")
    doc = r.json()
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert doc["version"] == "2.1.0"
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "PentestAI"
    assert "rules" in run["tool"]["driver"]
    assert "results" in run


def test_scan_sarif_requires_completed(auth):
    headers, _ = auth
    # Fresh scan that we won't wait to complete — cancel it to put in non-completed state
    body = {"scan_type": "recon", "target": "scanme.nmap.org", "options": {"preset": "fast"}}
    r = requests.post(f"{BASE_URL}/api/scans", json=body, headers=headers, timeout=15)
    sid = r.json()["id"]
    requests.post(f"{BASE_URL}/api/scans/{sid}/cancel", headers=headers, timeout=10)
    s = requests.get(f"{BASE_URL}/api/scans/{sid}/sarif", headers=headers, timeout=10)
    assert s.status_code == 400, s.text


def test_scan_sarif_requires_auth(auth):
    headers, _ = auth
    scan = _run_scan(headers, scan_type="recon", target="scanme.nmap.org", preset="fast", timeout=120)
    r = requests.get(f"{BASE_URL}/api/scans/{scan['id']}/sarif", timeout=10)
    # FastAPI returns 401 or 403 for missing token depending on dep
    assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# SARIF 2.1 — report endpoint
# ---------------------------------------------------------------------------
def test_report_sarif_endpoint(auth):
    headers, _ = auth
    # Two scans → report with two runs
    s1 = _run_scan(headers, scan_type="vuln", target="scanme.nmap.org", preset="fast", timeout=120)
    s2 = _run_scan(headers, scan_type="recon", target="scanme.nmap.org", preset="fast", timeout=120)

    r = requests.post(
        f"{BASE_URL}/api/reports/generate",
        json=[s1["id"], s2["id"]],
        headers=headers, timeout=20,
    )
    assert r.status_code == 200, r.text
    rid = r.json()["id"]

    sr = requests.get(f"{BASE_URL}/api/reports/{rid}/sarif", headers=headers, timeout=15)
    assert sr.status_code == 200, sr.text
    cd = sr.headers.get("content-disposition", "")
    assert ".sarif" in cd
    doc = sr.json()
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 2


# ---------------------------------------------------------------------------
# SARIF severity + security-severity mapping (unit-level using sarif_service)
# ---------------------------------------------------------------------------
def test_sarif_severity_mapping():
    import sys
    sys.path.insert(0, "/app/backend")
    from services import sarif_service

    scan = {
        "id": "s1",
        "scan_type": "vuln",
        "target": "example.com",
        "status": "completed",
        "created_at": "2025-01-01T00:00:00+00:00",
        "results": {
            "vulnerabilities": [
                {"id": "CVE-A", "severity": "critical", "description": "c", "cvss": 9.8},
                {"id": "CVE-B", "severity": "high", "description": "h"},
                {"id": "CVE-C", "severity": "medium", "description": "m"},
                {"id": "CVE-D", "severity": "low", "description": "l"},
                {"id": "CVE-E", "severity": "info", "description": "i"},
            ],
        },
    }
    doc = sarif_service.build_sarif_for_scans([scan])
    results = doc["runs"][0]["results"]
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["CVE-A"] == "error"
    assert levels["CVE-B"] == "error"
    assert levels["CVE-C"] == "warning"
    assert levels["CVE-D"] == "note"
    assert levels["CVE-E"] == "none"

    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    # CVSS present → use it
    assert rules["CVE-A"]["properties"]["security-severity"] == "9.8"
    # Fallback per severity
    assert rules["CVE-B"]["properties"]["security-severity"] == "8.0"
    assert rules["CVE-C"]["properties"]["security-severity"] == "5.5"
    assert rules["CVE-D"]["properties"]["security-severity"] == "3.0"
    assert rules["CVE-E"]["properties"]["security-severity"] == "1.0"


def test_sarif_rules_dedup_by_id():
    import sys
    sys.path.insert(0, "/app/backend")
    from services import sarif_service
    scan = {
        "id": "s1", "scan_type": "vuln", "target": "x", "status": "completed",
        "created_at": "2025-01-01T00:00:00+00:00",
        "results": {"vulnerabilities": [
            {"id": "CVE-X", "severity": "high", "description": "d"},
            {"id": "CVE-X", "severity": "high", "description": "d"},
            {"id": "CVE-Y", "severity": "low", "description": "d"},
        ]},
    }
    doc = sarif_service.build_sarif_for_scans([scan])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]
    assert len(rules) == 2  # unique ids
    assert len(results) == 3  # one per occurrence


# ---------------------------------------------------------------------------
# Regression — nmap engine in use after self-heal
# ---------------------------------------------------------------------------
def test_recon_uses_nmap_engine_when_installed(auth):
    """If nmap binary is installed, scan_engine should be 'nmap' not 'mock'."""
    import shutil
    if not shutil.which("nmap"):
        pytest.skip("nmap not installed in env")
    headers, _ = auth
    scan = _run_scan(headers, scan_type="recon", target="scanme.nmap.org", preset="fast", timeout=120)
    if scan["status"] != "completed":
        pytest.skip(f"scan didn't complete: {scan.get('stage')}")
    engine = (scan.get("results") or {}).get("scan_engine")
    assert engine == "nmap", f"expected nmap engine, got {engine}; results={scan.get('results')}"
