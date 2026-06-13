"""Security-focused Linux distribution reference + recommendations."""
from fastapi import APIRouter, Depends, HTTPException

from core.security import get_current_user
from services import distros as distros_service

router = APIRouter()


@router.get("/distros")
async def list_distros(current_user: dict = Depends(get_current_user)):
    return {"distros": distros_service.list_distros()}


@router.get("/distros/recommend/{scan_type}")
async def recommend(scan_type: str, current_user: dict = Depends(get_current_user)):
    return distros_service.recommend_for(scan_type)


@router.get("/distros/{distro_id}")
async def get_distro(distro_id: str, current_user: dict = Depends(get_current_user)):
    d = distros_service.get_distro(distro_id)
    if not d:
        raise HTTPException(status_code=404, detail="Distro not found")
    return d
