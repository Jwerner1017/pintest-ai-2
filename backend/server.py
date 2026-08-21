"""PentestAI backend entrypoint — composes routers + middleware + lifespan."""
import asyncio
import logging
import os
import shutil
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from core.db import client  # noqa: E402  (after env is loaded)
from routers import auth, scans, reports, chat, dashboard, distros, schedules  # noqa: E402
from services import scheduler as scheduler_service  # noqa: E402

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def _ensure_nmap_installed():
    """Self-heal: install nmap on startup if it's missing.

    The Emergent container doesn't persist apt packages across rebuilds, so we
    install it lazily on each cold start. Runs in <2s when already present, ~15s
    on first install.
    """
    if shutil.which("nmap"):
        return
    logger.warning("nmap not found — attempting apt-get install (one-time, ~15s)")
    try:
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", "nmap"],
            check=True, capture_output=True, timeout=120, env=env,
        )
        logger.info("nmap installed successfully")
    except FileNotFoundError:
        logger.warning("apt-get not available — nmap install skipped (will fall back to mock)")
    except subprocess.CalledProcessError as e:
        logger.warning("nmap install failed: %s", e.stderr.decode()[:200] if e.stderr else e)
    except Exception as e:  # noqa: BLE001
        logger.warning("nmap install error: %s", e)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Startup — offload blocking apt install so we don't block the event loop.
    await asyncio.to_thread(_ensure_nmap_installed)
    count = await scans.reap_orphaned_scans()
    if count:
        logger.info("Janitor: reaped %d orphaned 'running' scan(s)", count)
    scheduler_service.start()
    yield
    # Shutdown
    await scheduler_service.stop()
    client.close()


app = FastAPI(title="PentestAI Platform", version="1.8.0", lifespan=lifespan)

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(reports.router)
api_router.include_router(chat.router)
api_router.include_router(dashboard.router)
api_router.include_router(distros.router)
api_router.include_router(schedules.router)


@api_router.get("/")
async def root():
    return {"message": "PentestAI Platform API", "version": "1.8.0"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)
