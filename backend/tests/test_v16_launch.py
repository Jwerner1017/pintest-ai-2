"""v1.6 distro launch script tests — one-click bash launch artifact per distro."""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL').rstrip('/')
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def auth_headers():
    email = f"v16_{int(time.time())}_{uuid.uuid4().hex[:6]}@test.com"
    r = requests.post(f"{API}/auth/register", json={
        "email": email, "password": "password123", "username": email.split("@")[0]
    }, timeout=15)
    assert r.status_code in (200, 201), f"register failed: {r.status_code} {r.text}"
    token = r.json().get("access_token") or r.json().get("token")
    assert token
    return {"Authorization": f"Bearer {token}"}


# ===== Auth required =====
def test_launch_requires_auth():
    r = requests.get(f"{API}/distros/backbox/launch?target=scanme.nmap.org", timeout=10)
    assert r.status_code in (401, 403)


# ===== BackBox =====
def test_launch_backbox(auth_headers):
    r = requests.get(
        f"{API}/distros/backbox/launch",
        params={"target": "scanme.nmap.org", "scan_id": "abc"},
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200
    assert "text/x-shellscript" in r.headers.get("content-type", "")
    cd = r.headers.get("content-disposition", "")
    assert "launch-backbox-scanme-nmap-org.sh" in cd, f"bad CD: {cd}"
    body = r.text
    assert body.startswith("#!/usr/bin/env bash"), f"bad shebang start: {body[:80]!r}"
    assert "PENTESTAI_TARGET='scanme.nmap.org'" in body
    assert "PENTESTAI_SCAN_ID='abc'" in body
    assert "docker run" in body
    assert "backbox/backbox" in body


# ===== Pentoo =====
def test_launch_pentoo(auth_headers):
    r = requests.get(
        f"{API}/distros/pentoo/launch",
        params={"target": "example.org"},
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200
    body = r.text
    assert "pentoo" in body.lower()
    # docker fallback to gentoo/stage3
    assert "gentoo/stage3" in body
    assert "docker run" in body
    cd = r.headers.get("content-disposition", "")
    assert "launch-pentoo-" in cd


# ===== DEFT =====
def test_launch_deft(auth_headers):
    r = requests.get(
        f"{API}/distros/deft/launch",
        params={"target": "10.0.0.1"},
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200
    body = r.text
    # No docker run for DEFT (informational)
    assert "docker run" not in body
    # Reference ISO + dd
    lower = body.lower()
    assert "deft" in lower or "tsurugi" in lower
    assert " dd " in body or "dd if=" in body
    cd = r.headers.get("content-disposition", "")
    assert "launch-deft-" in cd


# ===== Kodachi =====
def test_launch_kodachi(auth_headers):
    r = requests.get(
        f"{API}/distros/kodachi/launch",
        params={"target": "victim.example"},
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200
    body = r.text
    lower = body.lower()
    # warns against persistent install
    assert "never install" in lower or "live-only" in lower or "live boot" in lower
    # references Tor / proxychains
    assert "tor" in lower
    assert "proxychains" in lower
    # qemu boot example
    assert "qemu-system-x86_64" in body
    cd = r.headers.get("content-disposition", "")
    assert "launch-kodachi-" in cd


# ===== Unknown distro 404 =====
def test_launch_unknown_distro_404(auth_headers):
    r = requests.get(f"{API}/distros/unknown/launch", headers=auth_headers, timeout=10)
    assert r.status_code == 404
    detail = r.json().get("detail", "")
    assert "not found" in detail.lower()


# ===== Shell-quoting safety =====
def test_launch_target_shell_quote_escapes_single_quote(auth_headers):
    # target with embedded single quote: it's test
    bad_target = "it's test"
    r = requests.get(
        f"{API}/distros/backbox/launch",
        params={"target": bad_target},
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200
    body = r.text
    # Expected proper single-quote escape: 'it'\''s test'
    assert "PENTESTAI_TARGET='it'\\''s test'" in body, \
        f"shell-escape missing — possible injection: {[l for l in body.splitlines() if 'PENTESTAI_TARGET' in l]}"


# ===== Empty target defaults to example.com =====
def test_launch_empty_target_defaults(auth_headers):
    r = requests.get(
        f"{API}/distros/backbox/launch",
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200
    body = r.text
    assert "PENTESTAI_TARGET='example.com'" in body
    # Preamble Target: line
    assert "Target:   example.com" in body or "Target: example.com" in body


# ===== Regression: root version =====
def test_root_version(auth_headers):
    r = requests.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    v = r.json().get("version", "")
    # Spec says we did NOT bump for v1.6, so still 1.5.0
    assert v == "1.5.0", f"expected 1.5.0, got {v!r}"


# ===== Regression: distros list still 4 =====
def test_regression_distros_list(auth_headers):
    r = requests.get(f"{API}/distros", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    distros = r.json().get("distros", [])
    assert len(distros) == 4
    assert {d["id"] for d in distros} == {"deft", "backbox", "kodachi", "pentoo"}


# ===== Filename slug correctness =====
def test_launch_filename_slug(auth_headers):
    # target with chars that must be slugified
    r = requests.get(
        f"{API}/distros/backbox/launch",
        params={"target": "http://my.site.com:8080/path"},
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200
    cd = r.headers.get("content-disposition", "")
    # should not contain ":" or "/"
    assert ":" not in cd.split("filename=")[-1]
    assert "launch-backbox-" in cd
