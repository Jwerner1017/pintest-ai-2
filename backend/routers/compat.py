"""UI-compat routes. Bulk/scheduled jobs use services.scan_engine."""
from __future__ import annotations

import asyncio, csv, io, ipaddress, json, logging, re, uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.db import db
from core.security import get_current_user
from services.scan_engine import run_scan_engine

logger = logging.getLogger(__name__)
router = APIRouter()
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")

def is_valid_target(target: str) -> bool:
    if _IP_RE.match(target):
        return all(0 <= int(part) <= 255 for part in target.split("."))
    return bool(_DOMAIN_RE.match(target))

class BulkScanCreate(BaseModel):
    scan_type: str = "recon"
    targets: List[str] = []
    cidr: Optional[str] = None
    options: Optional[dict] = {}

class BulkScanResponse(BaseModel):
    id: str
    scan_type: str
    total_targets: int
    completed: int
    failed: int
    status: str
    created_at: str
    results: Optional[List[dict]] = None

class ScheduledScanCreate(BaseModel):
    name: str
    scan_type: str = "recon"
    targets: List[str]
    schedule_type: str
    schedule_time: str
    schedule_day: Optional[int] = None
    enabled: bool = True

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        self.active_connections.setdefault(scan_id, set()).add(websocket)
    def disconnect(self, websocket: WebSocket, scan_id: str):
        conns = self.active_connections.get(scan_id)
        if not conns:
            return
        conns.discard(websocket)
        if not conns:
            self.active_connections.pop(scan_id, None)
    async def send_progress(self, scan_id: str, data: dict):
        dead = set()
        for connection in list(self.active_connections.get(scan_id, set())):
            try:
                await connection.send_json(data)
            except Exception:
                dead.add(connection)
        for conn in dead:
            self.disconnect(conn, scan_id)

ws_manager = ConnectionManager()

@router.get("/")
async def root():
    return {"message": "PentestAI Platform API", "version": "2.0.0"}

@router.get("/scans/{scan_id}/export")
async def export_scan(scan_id: str, format: str = "json", current_user: dict = Depends(get_current_user)):
    scan = await db.scans.find_one({"id": scan_id, "user_id": current_user["id"]}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = scan.get("results") or {}
    if format.lower() == "csv":
        output = io.StringIO(); writer = csv.writer(output)
        writer.writerow(["Scan ID", scan.get("id")]); writer.writerow(["Target", scan.get("target")])
        return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.csv"})
    payload = {"scan": {k: scan.get(k) for k in ("id", "target", "scan_type", "status", "created_at")}, "results": results}
    return StreamingResponse(io.BytesIO(json.dumps(payload, indent=2).encode()), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.json"})

@router.get("/cve/{cve_id}")
async def get_cve_details(cve_id: str, current_user: dict = Depends(get_current_user)):
    if not cve_id.upper().startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    cve_id = cve_id.upper()
    cached = await db.cve_cache.find_one({"cve_id": cve_id}, {"_id": 0})
    if cached:
        return cached.get("data") or cached
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve_id})
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to fetch CVE data from NVD")
    vulnerabilities = response.json().get("vulnerabilities") or []
    if not vulnerabilities:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    descriptions = (vulnerabilities[0].get("cve") or {}).get("descriptions") or []
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available")
    result = {"cve_id": cve_id, "description": description, "source": "NVD"}
    await db.cve_cache.update_one({"cve_id": cve_id}, {"$set": {"cve_id": cve_id, "data": result, "cached_at": datetime.now(timezone.utc).isoformat()}}, upsert=True)
    return result

def parse_cidr(cidr: str) -> List[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > 256:
        raise HTTPException(status_code=400, detail="CIDR range too large. Maximum /24 (256 hosts) allowed")
    return [str(ip) for ip in network.hosts()][:256]

async def run_bulk_scan_job(bulk_scan_id: str, user_id: str, targets: List[str], scan_type: str, options: Optional[dict] = None):
    options = dict(options or {}); options.setdefault("preset", "fast")
    completed = 0; failed = 0; lock = asyncio.Lock(); semaphore = asyncio.Semaphore(5)
    async def scan_target(target: str) -> dict:
        nonlocal completed, failed
        async with semaphore:
            scan_id = str(uuid.uuid4()); now = datetime.now(timezone.utc).isoformat()
            try:
                scan_result = await run_scan_engine(scan_type, target, options)
                status = "failed" if (scan_result or {}).get("error") and not (scan_result or {}).get("ports") else "completed"
                await db.scans.insert_one({"id": scan_id, "user_id": user_id, "bulk_scan_id": bulk_scan_id, "scan_type": scan_type, "target": target, "options": options, "status": status, "progress": 100, "results": scan_result, "created_at": now})
                result = {"target": target, "scan_id": scan_id, "status": status, "scan_engine": (scan_result or {}).get("scan_engine")}
                async with lock:
                    completed += status == "completed"; failed += status != "completed"
                    await db.bulk_scans.update_one({"id": bulk_scan_id}, {"$set": {"completed": completed, "failed": failed, "status": "running"}})
                    await ws_manager.send_progress(bulk_scan_id, {"type": "progress", "scan_id": bulk_scan_id, "target": target, "completed": completed, "total": len(targets), "failed": failed, "status": "running", "result": result})
                return result
            except Exception as exc:
                async with lock:
                    failed += 1
                return {"target": target, "status": "failed", "error": str(exc)}
    await db.bulk_scans.update_one({"id": bulk_scan_id}, {"$set": {"status": "running"}})
    results = await asyncio.gather(*[scan_target(t) for t in targets])
    await db.bulk_scans.update_one({"id": bulk_scan_id}, {"$set": {"status": "completed", "completed": completed, "failed": failed, "results": results}})
    await ws_manager.send_progress(bulk_scan_id, {"type": "completed", "scan_id": bulk_scan_id, "completed": completed, "total": len(targets), "failed": failed, "status": "completed"})

@router.post("/bulk-scans", response_model=BulkScanResponse)
async def create_bulk_scan(scan_data: BulkScanCreate, background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    if scan_data.scan_type not in {"recon", "vuln", "network"}:
        raise HTTPException(status_code=400, detail="scan_type must be recon, vuln, or network")
    targets = list(scan_data.targets)
    if scan_data.cidr:
        targets.extend(parse_cidr(scan_data.cidr))
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")
    invalid = [t for t in targets if not is_valid_target(t)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid targets: {', '.join(invalid[:5])}")
    targets = list(dict.fromkeys(targets))[:256]
    options = dict(scan_data.options or {}); options.setdefault("preset", "fast")
    bulk_scan_id = str(uuid.uuid4()); now = datetime.now(timezone.utc).isoformat()
    await db.bulk_scans.insert_one({"id": bulk_scan_id, "user_id": current_user["id"], "scan_type": scan_data.scan_type, "targets": targets, "options": options, "total_targets": len(targets), "completed": 0, "failed": 0, "status": "pending", "created_at": now})
    background_tasks.add_task(run_bulk_scan_job, bulk_scan_id, current_user["id"], targets, scan_data.scan_type, options)
    return BulkScanResponse(id=bulk_scan_id, scan_type=scan_data.scan_type, total_targets=len(targets), completed=0, failed=0, status="pending", created_at=now)

@router.get("/bulk-scans")
async def list_bulk_scans(current_user: dict = Depends(get_current_user)):
    return {"bulk_scans": await db.bulk_scans.find({"user_id": current_user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(50)}

@router.get("/bulk-scans/{bulk_scan_id}")
async def get_bulk_scan(bulk_scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = await db.bulk_scans.find_one({"id": bulk_scan_id, "user_id": current_user["id"]}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Bulk scan not found")
    return scan

def calculate_next_run(schedule_type: str, schedule_time: str, schedule_day: Optional[int] = None) -> str:
    now = datetime.now(timezone.utc)
    hour, minute = map(int, schedule_time.split(":"))
    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if next_run <= now:
        next_run += timedelta(days=1)
    return next_run.isoformat()

async def check_scheduled_scans():
    now = datetime.now(timezone.utc)
    due = await db.scheduled_scans.find({"enabled": True, "next_run": {"$lte": now.isoformat()}}).to_list(100)
    for schedule in due:
        bulk_scan_id = str(uuid.uuid4()); options = {"preset": "fast"}
        await db.bulk_scans.insert_one({"id": bulk_scan_id, "user_id": schedule["user_id"], "scan_type": schedule["scan_type"], "targets": schedule["targets"], "options": options, "total_targets": len(schedule["targets"]), "completed": 0, "failed": 0, "status": "pending", "created_at": now.isoformat()})
        await db.scheduled_scans.update_one({"id": schedule["id"]}, {"$set": {"last_run": now.isoformat(), "next_run": calculate_next_run(schedule["schedule_type"], schedule["schedule_time"], schedule.get("schedule_day"))}})
        asyncio.create_task(run_bulk_scan_job(bulk_scan_id, schedule["user_id"], schedule["targets"], schedule["scan_type"], options))

@router.post("/scheduled-scans")
async def create_scheduled_scan(payload: ScheduledScanCreate, current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc).isoformat()
    doc = {"id": str(uuid.uuid4()), "user_id": current_user["id"], "name": payload.name, "scan_type": payload.scan_type, "targets": payload.targets, "schedule_type": payload.schedule_type, "schedule_time": payload.schedule_time, "schedule_day": payload.schedule_day, "enabled": payload.enabled, "last_run": None, "next_run": calculate_next_run(payload.schedule_type, payload.schedule_time, payload.schedule_day), "created_at": now}
    await db.scheduled_scans.insert_one(doc); doc.pop("_id", None); return doc

@router.get("/scheduled-scans")
async def list_scheduled_scans(current_user: dict = Depends(get_current_user)):
    return {"scheduled_scans": await db.scheduled_scans.find({"user_id": current_user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(50)}

@router.get("/scheduled-scans/{schedule_id}")
async def get_scheduled_scan(schedule_id: str, current_user: dict = Depends(get_current_user)):
    item = await db.scheduled_scans.find_one({"id": schedule_id, "user_id": current_user["id"]}, {"_id": 0})
    if not item:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    return item

@router.patch("/scheduled-scans/{schedule_id}")
async def patch_scheduled_scan(schedule_id: str, enabled: Optional[bool] = None, current_user: dict = Depends(get_current_user)):
    item = await db.scheduled_scans.find_one({"id": schedule_id, "user_id": current_user["id"]}, {"_id": 0})
    if not item:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    if enabled is not None:
        await db.scheduled_scans.update_one({"id": schedule_id}, {"$set": {"enabled": enabled}}); item["enabled"] = enabled
    return item

@router.delete("/scheduled-scans/{schedule_id}")
async def delete_scheduled_scan(schedule_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.scheduled_scans.delete_one({"id": schedule_id, "user_id": current_user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    return {"message": "Scheduled scan deleted"}

@router.post("/scheduled-scans/{schedule_id}/run")
async def run_scheduled_scan_now(schedule_id: str, background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    schedule = await db.scheduled_scans.find_one({"id": schedule_id, "user_id": current_user["id"]})
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    bulk_scan_id = str(uuid.uuid4()); now = datetime.now(timezone.utc).isoformat(); options = {"preset": "fast"}
    await db.bulk_scans.insert_one({"id": bulk_scan_id, "user_id": current_user["id"], "scan_type": schedule["scan_type"], "targets": schedule["targets"], "options": options, "total_targets": len(schedule["targets"]), "completed": 0, "failed": 0, "status": "pending", "created_at": now})
    background_tasks.add_task(run_bulk_scan_job, bulk_scan_id, current_user["id"], schedule["targets"], schedule["scan_type"], options)
    return {"message": "Scheduled scan started", "bulk_scan_id": bulk_scan_id}

@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    await ws_manager.connect(websocket, scan_id)
    try:
        scan = await db.bulk_scans.find_one({"id": scan_id}, {"_id": 0})
        if scan:
            await websocket.send_json({"type": "status", "scan_id": scan_id, "status": scan.get("status"), "completed": scan.get("completed", 0), "failed": scan.get("failed", 0), "total": scan.get("total_targets", 0)})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, scan_id)
    except Exception:
        ws_manager.disconnect(websocket, scan_id)
