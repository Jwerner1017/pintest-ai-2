"""Cron-style scan scheduler.

Runs a single asyncio task in the lifespan that ticks every SCHEDULER_TICK_SECONDS,
looks up any enabled schedules whose next_run_at <= now, dispatches the scan via
routers.scans.enqueue_scheduled_scan, and advances next_run_at using croniter.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from croniter import croniter

from core.db import db

logger = logging.getLogger(__name__)

SCHEDULER_TICK_SECONDS = 20
_task: Optional[asyncio.Task] = None


def compute_next_run(cron_expr: str, base: Optional[datetime] = None) -> datetime:
    """Return the next fire time (UTC) for a 5-field cron expression."""
    base_dt = base or datetime.now(timezone.utc)
    itr = croniter(cron_expr, base_dt)
    nxt: datetime = itr.get_next(datetime)
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=timezone.utc)
    return nxt


def validate_cron(cron_expr: str) -> bool:
    return croniter.is_valid(cron_expr)


async def _tick() -> int:
    """Dispatch every schedule whose next_run_at <= now. Returns count dispatched."""
    from routers.scans import enqueue_scheduled_scan  # local import to avoid cycle at module load

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    cursor = db.schedules.find({"enabled": True, "next_run_at": {"$lte": now_iso}}, {"_id": 0})
    dispatched = 0
    async for sched in cursor:
        try:
            scan_id = await enqueue_scheduled_scan(
                user_id=sched["user_id"],
                scan_type=sched["scan_type"],
                target=sched["target"],
                options={"preset": sched.get("preset") or "fast"},
                source={"trigger": "schedule", "schedule_id": sched["id"]},
            )
            next_run = compute_next_run(sched["cron"], now)
            await db.schedules.update_one(
                {"id": sched["id"]},
                {"$set": {
                    "last_run_at": now_iso,
                    "last_scan_id": scan_id,
                    "next_run_at": next_run.isoformat(),
                }},
            )
            dispatched += 1
        except Exception as e:  # noqa: BLE001
            logger.exception("scheduler: failed to dispatch schedule %s: %s", sched.get("id"), e)
            # Push next_run forward to avoid a hot-loop on a bad schedule.
            try:
                next_run = compute_next_run(sched["cron"], now)
                await db.schedules.update_one(
                    {"id": sched["id"]},
                    {"$set": {"next_run_at": next_run.isoformat()}},
                )
            except Exception:  # noqa: BLE001
                await db.schedules.update_one({"id": sched["id"]}, {"$set": {"enabled": False}})
    return dispatched


async def _loop():
    logger.info("scheduler: loop started (tick=%ss)", SCHEDULER_TICK_SECONDS)
    while True:
        try:
            n = await _tick()
            if n:
                logger.info("scheduler: dispatched %d scan(s)", n)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("scheduler: unexpected tick error")
        await asyncio.sleep(SCHEDULER_TICK_SECONDS)


def start():
    global _task
    if _task and not _task.done():
        return
    _task = asyncio.create_task(_loop())


async def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
    _task = None
