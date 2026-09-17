"""Cron-style scan schedules.

Endpoints (all under /api):
  POST   /schedules            create
  GET    /schedules            list current user's schedules
  PATCH  /schedules/{id}       enable/disable/rename/re-cron
  DELETE /schedules/{id}       remove
"""
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException

from core.db import db
from core.models import ScheduleCreate, ScheduleResponse, ScheduleUpdate
from core.security import get_current_user
from services import scheduler as scheduler_service

router = APIRouter()

_VALID_SCAN_TYPES = {"recon", "vuln", "network"}


def _to_response(doc: dict) -> ScheduleResponse:
    return ScheduleResponse(**{k: doc.get(k) for k in (
        "id", "name", "scan_type", "target", "cron", "preset",
        "enabled", "next_run_at", "last_run_at", "last_scan_id", "created_at",
    )})


@router.post("/schedules", response_model=ScheduleResponse)
async def create_schedule(payload: ScheduleCreate, current_user: dict = Depends(get_current_user)):
    if payload.scan_type not in _VALID_SCAN_TYPES:
        raise HTTPException(status_code=400, detail=f"scan_type must be one of {sorted(_VALID_SCAN_TYPES)}")
    if not payload.target.strip():
        raise HTTPException(status_code=400, detail="target required")
    if not scheduler_service.validate_cron(payload.cron):
        raise HTTPException(status_code=400, detail="Invalid cron expression (expected 5-field, e.g. '0 * * * *')")

    now = datetime.now(timezone.utc)
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "name": payload.name.strip() or f"{payload.scan_type} · {payload.target}",
        "scan_type": payload.scan_type,
        "target": payload.target.strip(),
        "cron": payload.cron.strip(),
        "preset": payload.preset or "fast",
        "enabled": payload.enabled,
        "next_run_at": scheduler_service.compute_next_run(payload.cron, now).isoformat() if payload.enabled else None,
        "last_run_at": None,
        "last_scan_id": None,
        "created_at": now.isoformat(),
    }
    await db.schedules.insert_one(doc)
    doc.pop("_id", None)
    return _to_response(doc)


@router.get("/schedules", response_model=List[ScheduleResponse])
async def list_schedules(current_user: dict = Depends(get_current_user)):
    docs = await db.schedules.find({"user_id": current_user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return [_to_response(d) for d in docs]


@router.patch("/schedules/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(schedule_id: str, payload: ScheduleUpdate, current_user: dict = Depends(get_current_user)):
    sched = await db.schedules.find_one({"id": schedule_id, "user_id": current_user["id"]}, {"_id": 0})
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    updates: dict = {}
    if payload.name is not None:
        updates["name"] = payload.name.strip() or sched["name"]
    if payload.cron is not None:
        if not scheduler_service.validate_cron(payload.cron):
            raise HTTPException(status_code=400, detail="Invalid cron expression")
        updates["cron"] = payload.cron.strip()

    if payload.enabled is not None:
        updates["enabled"] = payload.enabled

    # Recompute next_run_at whenever cron changes or a disabled schedule is re-enabled.
    now = datetime.now(timezone.utc)
    effective_cron = updates.get("cron", sched["cron"])
    effective_enabled = updates.get("enabled", sched["enabled"])
    if effective_enabled:
        if "cron" in updates or payload.enabled is True:
            updates["next_run_at"] = scheduler_service.compute_next_run(effective_cron, now).isoformat()
    else:
        updates["next_run_at"] = None

    if not updates:
        return _to_response(sched)

    await db.schedules.update_one({"id": schedule_id}, {"$set": updates})
    fresh = await db.schedules.find_one({"id": schedule_id}, {"_id": 0})
    return _to_response(fresh)


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str, current_user: dict = Depends(get_current_user)):
    res = await db.schedules.delete_one({"id": schedule_id, "user_id": current_user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"message": "Schedule deleted"}
