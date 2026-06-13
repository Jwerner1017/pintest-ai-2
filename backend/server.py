"""PentestAI backend entrypoint — composes routers + middleware + lifespan."""
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from core.db import client  # noqa: E402  (after env is loaded)
from routers import auth, scans, reports, chat, dashboard, distros  # noqa: E402

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Startup
    count = await scans.reap_orphaned_scans()
    if count:
        logger.info("Janitor: reaped %d orphaned 'running' scan(s)", count)
    yield
    # Shutdown
    client.close()


app = FastAPI(title="PentestAI Platform", version="1.4.0", lifespan=lifespan)

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(reports.router)
api_router.include_router(chat.router)
api_router.include_router(dashboard.router)
api_router.include_router(distros.router)


@api_router.get("/")
async def root():
    return {"message": "PentestAI Platform API", "version": "1.4.0"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)
