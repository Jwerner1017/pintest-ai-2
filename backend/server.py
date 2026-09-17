"""PentestAI FastAPI entrypoint."""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

if not os.environ.get("JWT_SECRET"):
    raise RuntimeError("JWT_SECRET environment variable is required")
if not os.environ.get("MONGO_URL"):
    raise RuntimeError("MONGO_URL environment variable is required")
if not os.environ.get("DB_NAME"):
    raise RuntimeError("DB_NAME environment variable is required")

from core.db import client  # noqa: E402
from routers import auth, chat, compat, dashboard, distros, reports, scans, schedules  # noqa: E402
from services import scheduler as scheduler_service  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
_legacy_task: asyncio.Task | None = None


async def _legacy_schedule_loop():
    while True:
        try:
            await compat.check_scheduled_scans()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("legacy scheduled-scan checker failed")
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _legacy_task
    disable_scheduler = os.environ.get("PENTESTAI_DISABLE_SCHEDULER", "").lower() in {"1", "true", "yes"}
    if not disable_scheduler:
        scheduler_service.start()
        _legacy_task = asyncio.create_task(_legacy_schedule_loop())
        logger.info("Scheduler started")
    try:
        yield
    finally:
        if _legacy_task and not _legacy_task.done():
            _legacy_task.cancel()
            try:
                await _legacy_task
            except asyncio.CancelledError:
                pass
        if not disable_scheduler:
            await scheduler_service.stop()
        client.close()


app = FastAPI(title="PentestAI Platform", version="2.0.0", lifespan=lifespan)
for module in (auth, scans, reports, chat, dashboard, distros, schedules, compat):
    app.include_router(module.router, prefix="/api")
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
