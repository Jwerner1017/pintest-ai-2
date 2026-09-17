"""UI-compat routes. Bulk/scheduled jobs use scans.run_scan_engine."""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.db import db
from core.security import get_current_user

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
