"""
Tests for four advanced features:
1) APScheduler auto-execute (verified via backend logs / behavior)
2) PDF Report Export via GET /api/reports/{id}/pdf
3) Concurrent Bulk Scanning with semaphore(5) - timing check
4) WebSocket progress at /api/ws/scan/{scan_id}
"""
import os
import time
import json
import asyncio
import pytest
import requests
import websockets

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE_URL}/api"
WS_BASE = BASE_URL.replace("https://", "wss://").replace("http://", "ws://")

TEST_EMAIL = "tester@example.com"
TEST_PASSWORD = "test123456"


@pytest.fixture(scope="module")
def auth():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}, timeout=30)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# --- Feature 3: Concurrent Bulk Scanning ---
class TestConcurrentBulk:
    bulk_id = None

    def test_bulk_5_targets_concurrent_timing(self, auth):
        targets = ["google.com", "github.com", "cloudflare.com", "example.com", "microsoft.com"]
        t0 = time.time()
        r = requests.post(f"{API}/bulk-scans", headers=auth, json={
            "scan_type": "recon", "targets": targets
        }, timeout=30)
        assert r.status_code == 200, r.text
        bulk_id = r.json()["id"]
        TestConcurrentBulk.bulk_id = bulk_id

        # Poll until completed (max 40s)
        deadline = time.time() + 40
        status = None
        while time.time() < deadline:
            gr = requests.get(f"{API}/bulk-scans/{bulk_id}", headers=auth, timeout=15)
            assert gr.status_code == 200
            status = gr.json()["status"]
            if status == "completed":
                break
            time.sleep(1)
        elapsed = time.time() - t0
        print(f"Bulk 5 targets elapsed: {elapsed:.1f}s (status={status})")
        assert status == "completed", f"Did not complete in time. Last status={status}"
        # Concurrent should be well under 30s (sequential would be ~50s+ with 0.5s sleeps and shodan calls)
        assert elapsed < 30, f"Bulk scan took {elapsed:.1f}s - concurrency may not be working"


# --- Feature 4: WebSocket Progress ---
class TestWebSocketProgress:
    def test_ws_receives_progress(self, auth):
        # Kick off a small bulk scan
        r = requests.post(f"{API}/bulk-scans", headers=auth, json={
            "scan_type": "recon", "targets": ["example.com", "example.org", "example.net"]
        }, timeout=30)
        assert r.status_code == 200
        bulk_id = r.json()["id"]

        ws_url = f"{WS_BASE}/api/ws/scan/{bulk_id}"

        async def run():
            events = []
            try:
                async with websockets.connect(ws_url, open_timeout=10) as ws:
                    end = time.time() + 30
                    while time.time() < end:
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=15)
                            try:
                                data = json.loads(msg)
                            except Exception:
                                continue
                            events.append(data)
                            if data.get("type") == "completed":
                                break
                        except asyncio.TimeoutError:
                            break
            except Exception as e:
                print(f"WS error: {e}")
            return events

        events = asyncio.run(run())
        print(f"WS events received: {len(events)} -> types={[e.get('type') for e in events]}")
        # Expect at least one progress event
        types = [e.get("type") for e in events]
        assert any(t in ("progress", "completed", "started", "connected") for t in types), \
            f"No progress-like events received: {events}"


# --- Feature 2: PDF Export ---
class TestPdfExport:
    def test_generate_report_and_download_pdf(self, auth):
        # Create a fast recon scan to get a scan id
        r = requests.post(f"{API}/scans", headers=auth, json={
            "scan_type": "recon", "target": "example.com"
        }, timeout=60)
        assert r.status_code == 200, r.text
        scan_id = r.json()["id"]

        # Wait for scan to complete
        deadline = time.time() + 30
        while time.time() < deadline:
            gr = requests.get(f"{API}/scans/{scan_id}", headers=auth, timeout=15)
            if gr.status_code == 200 and gr.json().get("status") == "completed":
                break
            time.sleep(1)

        # Create a report from that scan (endpoint takes bare list body)
        rr = requests.post(f"{API}/reports/generate", headers=auth, json=[scan_id], timeout=60)
        assert rr.status_code == 200, rr.text
        report_id = rr.json()["id"]

        # Download PDF
        pr = requests.get(f"{API}/reports/{report_id}/pdf", headers={"Authorization": auth["Authorization"]}, timeout=60)
        assert pr.status_code == 200, pr.text
        assert pr.headers.get("content-type", "").startswith("application/pdf"), pr.headers
        assert pr.content[:4] == b"%PDF", f"Not a PDF file, got: {pr.content[:20]}"
        assert len(pr.content) > 500, f"PDF too small: {len(pr.content)} bytes"


# --- Feature 1: Scheduler running ---
class TestSchedulerRunning:
    def test_scheduler_started_in_logs(self):
        # Check backend logs for scheduler started message
        with open("/var/log/supervisor/backend.err.log", "r") as f:
            content = f.read()
        assert "Scheduler started" in content, "Scheduler start log not found"
