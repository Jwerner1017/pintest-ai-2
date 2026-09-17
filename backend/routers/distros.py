"""Security-focused Linux distribution reference + recommendations."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from core.security import get_current_user
from services import distros as distros_service, launch_service

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


@router.get("/distros/{distro_id}/launch")
async def launch_script(
    distro_id: str,
    target: str = "",
    scan_id: str = "",
    current_user: dict = Depends(get_current_user),
):
    """Return a one-click bash launch script for the requested distro pre-loaded with target."""
    if not distros_service.get_distro(distro_id):
        raise HTTPException(status_code=404, detail="Distro not found")
    try:
        script, filename = launch_service.build_launch_script(distro_id, target, scan_id)
    except KeyError:
        raise HTTPException(status_code=400, detail="No launch script for this distro")
    return Response(
        content=script,
        media_type="text/x-shellscript; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
