"""Dashboard stats + trend routes."""
from fastapi import APIRouter, Depends

from core.db import db
from core.models import DashboardStats
from core.security import get_current_user

router = APIRouter()


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    total_scans = await db.scans.count_documents({"user_id": current_user["id"]})

    scans = await db.scans.find({"user_id": current_user["id"]}, {"_id": 0, "results": 1, "status": 1}).to_list(200)
    vuln_count = sum(len(s.get("results", {}).get("vulnerabilities", [])) for s in scans)
    critical_count = sum(
        1 for s in scans
        for v in s.get("results", {}).get("vulnerabilities", [])
        if v.get("severity") == "critical"
    )
    active_scans = sum(1 for s in scans if s.get("status") == "running")

    activity = await db.activity_log.find(
        {"user_id": current_user["id"]}, {"_id": 0},
    ).sort("created_at", -1).to_list(10)

    return DashboardStats(
        total_scans=total_scans,
        active_scans=active_scans,
        vulnerabilities_found=vuln_count,
        critical_alerts=critical_count,
        recent_activity=activity,
    )


@router.get("/dashboard/vulnerability-trends")
async def get_vulnerability_trends(current_user: dict = Depends(get_current_user)):
    return {
        "trends": [
            {"date": "2025-01-01", "critical": 2, "high": 5, "medium": 8, "low": 12},
            {"date": "2025-01-02", "critical": 1, "high": 4, "medium": 10, "low": 15},
            {"date": "2025-01-03", "critical": 3, "high": 6, "medium": 7, "low": 11},
            {"date": "2025-01-04", "critical": 0, "high": 3, "medium": 9, "low": 14},
            {"date": "2025-01-05", "critical": 2, "high": 5, "medium": 6, "low": 10},
            {"date": "2025-01-06", "critical": 1, "high": 4, "medium": 8, "low": 13},
            {"date": "2025-01-07", "critical": 4, "high": 7, "medium": 5, "low": 9},
        ]
    }
