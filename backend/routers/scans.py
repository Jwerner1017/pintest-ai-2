"""Scan + Shodan + AI summariser routes. Includes background-task tracking & cancellation."""
import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException

from core.db import db
from core.models import ScanCreate, ScanResponse, ShodanRequest
from core.security import get_current_user
from services import nmap_service, vuln_service, network_service, shodan_service

logger = logging.getLogger(__name__)

router = APIRouter()

# Track running scan tasks so they can be cancelled.
_active_tasks: dict[str, asyncio.Task] = {}


def _scan_resp(doc: dict) -> ScanResponse:
    return ScanResponse(**{k: doc.get(k) for k in (
        "id", "scan_type", "target", "status", "created_at", "progress", "stage", "results",
    )})


@router.post("/scans", response_model=ScanResponse)
async def create_scan(scan_data: ScanCreate, current_user: dict = Depends(get_current_user)):
    """Queue a scan and run it asynchronously. Poll GET /api/scans/{id} for progress."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    scan_doc = {
        "id": scan_id,
        "user_id": current_user["id"],
        "scan_type": scan_data.scan_type,
        "target": scan_data.target,
        "options": scan_data.options or {},
        "status": "running",
        "progress": 0,
        "stage": "Queued",
        "results": None,
        "created_at": now,
    }
    await db.scans.insert_one(scan_doc)
    scan_doc.pop("_id", None)

    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "action": f"Created {scan_data.scan_type} scan",
        "target": scan_data.target,
        "created_at": now,
    })

    task = asyncio.create_task(_execute_scan(scan_id, scan_data.scan_type, scan_data.target, scan_data.options or {}))
    _active_tasks[scan_id] = task
    task.add_done_callback(lambda _t: _active_tasks.pop(scan_id, None))

    return _scan_resp(scan_doc)


async def _execute_scan(scan_id: str, scan_type: str, target: str, options: dict):
    async def progress_cb(percent: int, stage: str):
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"progress": int(percent), "stage": stage}},
        )

    options = {**options, "progress_cb": progress_cb}
    try:
        await progress_cb(5, "Starting")
        if scan_type == "recon":
            results = await nmap_service.run_recon_scan(target, options)
        elif scan_type == "vuln":
            results = await vuln_service.run_vuln_scan(target, options)
        elif scan_type == "network":
            results = await network_service.run_network_scan(target, options)
        else:
            results = {"target": target, "scan_type": scan_type, "scan_engine": "unknown"}

        # Only mark completed if the user did not cancel mid-flight.
        await db.scans.update_one(
            {"id": scan_id, "status": "running"},
            {"$set": {"status": "completed", "progress": 100, "stage": "Completed", "results": results}},
        )
    except asyncio.CancelledError:
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "cancelled", "stage": "Cancelled by user"}},
        )
        raise
    except Exception as e:  # noqa: BLE001
        logger.exception("scan %s failed", scan_id)
        await db.scans.update_one(
            {"id": scan_id, "status": "running"},
            {"$set": {"status": "failed", "progress": 100, "stage": f"Failed: {e}", "results": {"error": str(e)}}},
        )


@router.post("/scans/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = await db.scans.find_one({"id": scan_id, "user_id": current_user["id"]}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] not in ("running", "queued"):
        raise HTTPException(status_code=400, detail=f"Scan already {scan['status']}")

    task = _active_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
    # Set DB state immediately even if task isn't actively cancellable yet.
    await db.scans.update_one(
        {"id": scan_id},
        {"$set": {"status": "cancelled", "stage": "Cancelled by user"}},
    )
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    return _scan_resp(scan)


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(current_user: dict = Depends(get_current_user)):
    scans = await db.scans.find(
        {"user_id": current_user["id"]}, {"_id": 0},
    ).sort("created_at", -1).to_list(100)
    return [_scan_resp(s) for s in scans]


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = await db.scans.find_one(
        {"id": scan_id, "user_id": current_user["id"]}, {"_id": 0},
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_resp(scan)


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.scans.delete_one({"id": scan_id, "user_id": current_user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan deleted"}


# ==================== AI scan summary ====================

@router.post("/scans/{scan_id}/summary")
async def ai_summary(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Generate (or return cached) Claude-powered executive summary of a scan's results."""
    scan = await db.scans.find_one({"id": scan_id, "user_id": current_user["id"]}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan must be completed before summarising")
    if scan.get("ai_summary"):
        return {"summary": scan["ai_summary"], "cached": True}

    api_key = os.environ.get("EMERGENT_LLM_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="AI service not configured")

    from emergentintegrations.llm.chat import LlmChat, UserMessage  # local import to avoid global cost

    system_prompt = (
        "You are a senior penetration testing analyst. Given raw scan output, write a concise "
        "executive summary as EXACTLY 3 markdown bullet points (each <= 25 words). "
        "Bullet 1: top risk in plain English. "
        "Bullet 2: most actionable remediation. "
        "Bullet 3: business impact / next step. "
        "Use security-aware language but keep it readable for a non-technical CISO."
    )
    chat = LlmChat(
        api_key=api_key,
        session_id=f"summary_{scan_id}",
        system_message=system_prompt,
    ).with_model("anthropic", "claude-sonnet-4-5-20250929")

    import json
    payload = {
        "scan_type": scan.get("scan_type"),
        "target": scan.get("target"),
        "results": scan.get("results"),
    }
    msg = UserMessage(text=f"Scan output:\n```json\n{json.dumps(payload, default=str)[:6000]}\n```")
    summary = await chat.send_message(msg)

    await db.scans.update_one({"id": scan_id}, {"$set": {"ai_summary": summary}})
    return {"summary": summary, "cached": False}


# ==================== Shodan ====================

@router.get("/shodan/status")
async def shodan_status(current_user: dict = Depends(get_current_user)):
    return {"configured": shodan_service.is_configured()}


@router.post("/shodan/lookup")
async def shodan_lookup(req: ShodanRequest, current_user: dict = Depends(get_current_user)):
    return await shodan_service.host_lookup(req.target.strip())


# ==================== Janitor (called from server.py startup) ====================

async def reap_orphaned_scans() -> int:
    """Mark scans stuck in 'running' (from a previous worker) as failed."""
    res = await db.scans.update_many(
        {"status": "running"},
        {"$set": {"status": "failed", "stage": "Orphaned (server restarted)", "progress": 100}},
    )
    return res.modified_count
