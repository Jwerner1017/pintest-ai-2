"""v2.0 - AI remediation + auth/scan regression API tests.

Modules/features covered:
- Auth regression (login/me)
- Scan list/get + summary regression
- AI remediation generate/cache/access-control behavior
"""
import os
import time
import uuid

import pytest
import requests
from dotenv import load_dotenv


load_dotenv("/app/frontend/.env")


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL")
QA_EMAIL = "qa.v20@example.com"
QA_PASSWORD = "PentestAI-V20!"
SEEDED_COMPLETED_SCAN_ID = "4891f8c0-14a8-4e50-82b8-07d1c4e169c4"


def _assert_base_url():
    assert BASE_URL and BASE_URL.startswith("http"), "REACT_APP_BACKEND_URL must be configured"


def _login(email: str, password: str) -> str:
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password}, timeout=20)
    assert r.status_code == 200, r.text
    data = r.json()
    token = data.get("access_token")
    assert isinstance(token, str) and token
    return token


def _register_user() -> tuple[str, str, str]:
    email = f"v20_{uuid.uuid4().hex[:8]}@example.com"
    password = "password123"
    username = f"v20_{uuid.uuid4().hex[:6]}"
    payload = {"email": email, "password": password, "username": username}
    r = requests.post(f"{BASE_URL}/api/auth/register", json=payload, timeout=20)
    assert r.status_code in (200, 201), r.text
    data = r.json()
    token = data.get("access_token")
    assert isinstance(token, str) and token
    return token, email, username


def _wait_for_terminal_state(headers: dict, scan_id: str, timeout_seconds: int = 240) -> dict:
    deadline = time.time() + timeout_seconds
    latest = None
    while time.time() < deadline:
        r = requests.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        latest = r.json()
        if latest.get("status") in ("completed", "failed", "cancelled"):
            return latest
        time.sleep(2)
    pytest.fail(f"Timed out waiting for scan completion: {scan_id}, last={latest}")


@pytest.fixture(scope="module")
def qa_auth_headers():
    _assert_base_url()
    token = _login(QA_EMAIL, QA_PASSWORD)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def other_user_auth_headers():
    token, _email, _username = _register_user()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def qa_completed_vuln_scan_id(qa_auth_headers):
    # Create an uncached completed vuln scan to validate first remediation generation (cached=false).
    create = requests.post(
        f"{BASE_URL}/api/scans",
        headers=qa_auth_headers,
        json={"scan_type": "vuln", "target": "https://darkpulse-2.preview.emergentagent.com", "options": {"preset": "fast"}},
        timeout=20,
    )
    assert create.status_code in (200, 201), create.text
    scan_id = create.json()["id"]

    completed = _wait_for_terminal_state(qa_auth_headers, scan_id)
    assert completed["status"] == "completed", f"scan not completed: {completed}"
    vulns = ((completed.get("results") or {}).get("vulnerabilities") or [])
    if not vulns:
        pytest.skip("No vulnerabilities produced by scan; remediation endpoint requires findings")
    return scan_id


@pytest.fixture(scope="module")
def seeded_scan(qa_auth_headers):
    r = requests.get(f"{BASE_URL}/api/scans/{SEEDED_COMPLETED_SCAN_ID}", headers=qa_auth_headers, timeout=20)
    if r.status_code != 200:
        pytest.skip("Seeded completed scan not available")
    return r.json()


@pytest.fixture(scope="module")
def remediation_target(qa_auth_headers, seeded_scan, qa_completed_vuln_scan_id):
    # Prefer seeded scan with an uncached finding (smoke cached only one finding earlier).
    seeded_findings = ((seeded_scan.get("results") or {}).get("vulnerabilities") or [])
    for idx, finding in enumerate(seeded_findings):
        if not finding.get("ai_remediation"):
            return {"scan_id": SEEDED_COMPLETED_SCAN_ID, "finding_index": idx}

    # Fallback to fresh completed scan and first uncached finding.
    fr = requests.get(f"{BASE_URL}/api/scans/{qa_completed_vuln_scan_id}", headers=qa_auth_headers, timeout=20)
    assert fr.status_code == 200, fr.text
    fresh = fr.json()
    findings = ((fresh.get("results") or {}).get("vulnerabilities") or [])
    for idx, finding in enumerate(findings):
        if not finding.get("ai_remediation"):
            return {"scan_id": qa_completed_vuln_scan_id, "finding_index": idx}

    pytest.skip("No uncached finding available to validate first remediation generation")


@pytest.fixture(scope="module")
def first_generated_remediation(qa_auth_headers, remediation_target):
    r = requests.post(
        f"{BASE_URL}/api/scans/{remediation_target['scan_id']}/remediations/{remediation_target['finding_index']}",
        headers=qa_auth_headers,
        timeout=120,
    )
    assert r.status_code == 200, r.text
    return r.json(), remediation_target


def test_auth_login_and_me_regression(qa_auth_headers):
    me = requests.get(f"{BASE_URL}/api/auth/me", headers=qa_auth_headers, timeout=15)
    assert me.status_code == 200, me.text
    data = me.json()
    assert data["email"] == QA_EMAIL
    assert isinstance(data["username"], str) and data["username"]
    assert isinstance(data["role"], str) and data["role"]


def test_scan_list_and_get_regression(qa_auth_headers):
    list_r = requests.get(f"{BASE_URL}/api/scans", headers=qa_auth_headers, timeout=15)
    assert list_r.status_code == 200, list_r.text
    scans = list_r.json()
    assert isinstance(scans, list)
    hit = next((s for s in scans if s.get("id") == SEEDED_COMPLETED_SCAN_ID), None)
    assert hit is not None, "Seeded QA scan missing"

    get_r = requests.get(f"{BASE_URL}/api/scans/{SEEDED_COMPLETED_SCAN_ID}", headers=qa_auth_headers, timeout=15)
    assert get_r.status_code == 200, get_r.text
    scan = get_r.json()
    assert scan["id"] == SEEDED_COMPLETED_SCAN_ID
    assert scan["status"] == "completed"


def test_summary_regression_completed_scan(qa_auth_headers):
    r = requests.post(f"{BASE_URL}/api/scans/{SEEDED_COMPLETED_SCAN_ID}/summary", headers=qa_auth_headers, timeout=80)
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data.get("summary"), str) and data["summary"].strip()
    assert isinstance(data.get("model"), str) and data["model"].strip()
    assert isinstance(data.get("cached"), bool)


def test_remediation_unauthenticated_rejected():
    r = requests.post(f"{BASE_URL}/api/scans/{SEEDED_COMPLETED_SCAN_ID}/remediations/0", timeout=20)
    assert r.status_code in (401, 403), r.text


def test_remediation_cross_user_scan_hidden(other_user_auth_headers):
    r = requests.post(
        f"{BASE_URL}/api/scans/{SEEDED_COMPLETED_SCAN_ID}/remediations/0",
        headers=other_user_auth_headers,
        timeout=20,
    )
    assert r.status_code == 404, r.text


def test_remediation_invalid_finding_index_returns_404(qa_auth_headers):
    r = requests.post(
        f"{BASE_URL}/api/scans/{SEEDED_COMPLETED_SCAN_ID}/remediations/9999",
        headers=qa_auth_headers,
        timeout=30,
    )
    assert r.status_code == 404, r.text
    data = r.json()
    assert "detail" in data


def test_remediation_non_completed_scan_returns_400(qa_auth_headers):
    create = requests.post(
        f"{BASE_URL}/api/scans",
        headers=qa_auth_headers,
        json={"scan_type": "vuln", "target": "127.0.0.1", "options": {"preset": "fast"}},
        timeout=20,
    )
    assert create.status_code in (200, 201), create.text
    scan_id = create.json()["id"]
    r = requests.post(f"{BASE_URL}/api/scans/{scan_id}/remediations/0", headers=qa_auth_headers, timeout=20)
    assert r.status_code == 400, r.text
    data = r.json()
    assert "completed" in str(data.get("detail", "")).lower()


def test_remediation_first_generate_returns_structured_uncached(first_generated_remediation):
    data, remediation_target = first_generated_remediation

    assert data["finding_index"] == remediation_target["finding_index"]
    assert isinstance(data.get("finding_id"), str) and data["finding_id"]
    assert data["cached"] is False
    assert isinstance(data.get("model"), str) and data["model"].strip()
    assert isinstance(data.get("generated_at"), str) and data["generated_at"].strip()

    plan = data["remediation"]
    assert isinstance(plan.get("summary"), str) and plan["summary"].strip()
    assert str(plan.get("priority", "")).lower() in {"immediate", "high", "medium", "low"}
    assert isinstance(plan.get("steps"), list)
    assert 3 <= len(plan["steps"]) <= 6
    for step in plan["steps"]:
        assert isinstance(step.get("title"), str) and step["title"].strip()
        assert isinstance(step.get("action"), str) and step["action"].strip()
        assert isinstance(step.get("details"), str) and step["details"].strip()
        assert isinstance(step.get("commands", []), list)
    assert isinstance(plan.get("validation", []), list)
    assert isinstance(plan.get("rollback", []), list)


def test_remediation_second_call_returns_cached_and_identical(qa_auth_headers, first_generated_remediation):
    d1, remediation_target = first_generated_remediation
    second = requests.post(
        f"{BASE_URL}/api/scans/{remediation_target['scan_id']}/remediations/{remediation_target['finding_index']}",
        headers=qa_auth_headers,
        timeout=30,
    )
    assert second.status_code == 200, second.text

    d2 = second.json()
    assert d2["cached"] is True
    assert d1["remediation"] == d2["remediation"]
    assert d1["model"] == d2["model"]
    assert d1["generated_at"] == d2["generated_at"]
