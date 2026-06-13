"""Reports + PDF download routes."""
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from core.db import db
from core.security import get_current_user
from services import report_service, sarif_service

router = APIRouter()


@router.get("/reports")
async def list_reports(current_user: dict = Depends(get_current_user)):
    reports = await db.reports.find({"user_id": current_user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return {"reports": reports}


@router.post("/reports/generate")
async def generate_report(scan_ids: List[str], current_user: dict = Depends(get_current_user)):
    scans = await db.scans.find(
        {"id": {"$in": scan_ids}, "user_id": current_user["id"]}, {"_id": 0},
    ).to_list(100)
    if not scans:
        raise HTTPException(status_code=404, detail="No scans found")

    report_id = str(uuid.uuid4())
    report = {
        "id": report_id,
        "user_id": current_user["id"],
        "title": f"Security Assessment Report - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "scan_count": len(scans),
        "scans": scan_ids,
        "summary": {
            "total_vulnerabilities": sum(len(s.get("results", {}).get("vulnerabilities", [])) for s in scans),
            "critical": sum(1 for s in scans for v in s.get("results", {}).get("vulnerabilities", []) if v.get("severity") == "critical"),
            "high": sum(1 for s in scans for v in s.get("results", {}).get("vulnerabilities", []) if v.get("severity") == "high"),
            "medium": sum(1 for s in scans for v in s.get("results", {}).get("vulnerabilities", []) if v.get("severity") == "medium"),
            "low": sum(1 for s in scans for v in s.get("results", {}).get("vulnerabilities", []) if v.get("severity") == "low"),
        },
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.reports.insert_one(report)
    report.pop("_id", None)
    return report


@router.get("/reports/{report_id}/pdf")
async def download_report_pdf(report_id: str, current_user: dict = Depends(get_current_user)):
    report = await db.reports.find_one({"id": report_id, "user_id": current_user["id"]}, {"_id": 0})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    scan_ids = report.get("scans", [])
    scans = await db.scans.find(
        {"id": {"$in": scan_ids}, "user_id": current_user["id"]}, {"_id": 0},
    ).to_list(100)

    pdf_bytes = report_service.build_pdf(report, scans)
    filename = f"pentestai-report-{report_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/{report_id}/sarif")
async def download_report_sarif(report_id: str, current_user: dict = Depends(get_current_user)):
    """Download every scan in this report as a single SARIF 2.1 document."""
    report = await db.reports.find_one({"id": report_id, "user_id": current_user["id"]}, {"_id": 0})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    scan_ids = report.get("scans", [])
    scans = await db.scans.find(
        {"id": {"$in": scan_ids}, "user_id": current_user["id"]}, {"_id": 0},
    ).to_list(100)

    sarif = sarif_service.build_sarif_for_scans(scans)
    import json
    body = json.dumps(sarif, indent=2, default=str).encode("utf-8")
    filename = f"pentestai-report-{report_id}.sarif"
    return Response(
        content=body,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
