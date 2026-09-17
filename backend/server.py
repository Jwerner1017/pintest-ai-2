from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import json
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Set
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import ipaddress
import httpx
import asyncio
import io
from emergentintegrations.llm.chat import LlmChat, UserMessage
from scanner import perform_recon_scan, generate_vuln_scan_results, generate_network_scan_results, is_valid_target
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from core.db import client  # noqa: E402  (after env is loaded)
from routers import auth, scans, reports, chat, dashboard, distros, schedules  # noqa: E402
from services import scheduler as scheduler_service  # noqa: E402

# JWT Configuration
jwt_secret = os.environ.get('JWT_SECRET')
if not jwt_secret:
    raise RuntimeError("JWT_SECRET environment variable is required")
JWT_SECRET = jwt_secret
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Create the main app
app = FastAPI(title="PentestAI Platform", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== WEBSOCKET CONNECTION MANAGER ====================

class ConnectionManager:
    """Manages WebSocket connections for real-time scan progress updates"""
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}  # scan_id -> set of websockets
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)
        logger.info(f"WebSocket connected for scan {scan_id}")
    
    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    
    async def send_progress(self, scan_id: str, data: dict):
        if scan_id in self.active_connections:
            dead_connections = set()
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(data)
                except Exception:
                    dead_connections.add(connection)
            # Clean up dead connections
            for conn in dead_connections:
                self.active_connections[scan_id].discard(conn)

ws_manager = ConnectionManager()

# ==================== SCHEDULER SETUP ====================

scheduler = AsyncIOScheduler()

async def check_scheduled_scans():
    """Check and execute due scheduled scans"""
    try:
        now = datetime.now(timezone.utc)
        
        # Find enabled schedules where next_run is in the past
        due_schedules = await db.scheduled_scans.find({
            "enabled": True,
            "next_run": {"$lte": now.isoformat()}
        }).to_list(100)
        
        for schedule in due_schedules:
            logger.info(f"Executing scheduled scan: {schedule['name']}")
            
            # Create a bulk scan from the scheduled scan
            bulk_scan_id = str(uuid.uuid4())
            bulk_scan_doc = {
                "id": bulk_scan_id,
                "user_id": schedule["user_id"],
                "scheduled_scan_id": schedule["id"],
                "scan_type": schedule["scan_type"],
                "targets": schedule["targets"],
                "total_targets": len(schedule["targets"]),
                "completed": 0,
                "failed": 0,
                "status": "pending",
                "created_at": now.isoformat()
            }
            await db.bulk_scans.insert_one(bulk_scan_doc)
            
            # Calculate next run time
            next_run = calculate_next_run(
                schedule["schedule_type"],
                schedule["schedule_time"],
                schedule.get("schedule_day")
            )
            
            # Update schedule with last_run and next_run
            await db.scheduled_scans.update_one(
                {"id": schedule["id"]},
                {"$set": {
                    "last_run": now.isoformat(),
                    "next_run": next_run
                }}
            )
            
            # Execute the scan in background
            asyncio.create_task(run_bulk_scan_job(
                bulk_scan_id,
                schedule["user_id"],
                schedule["targets"],
                schedule["scan_type"]
            ))
            
            # Log activity
            await db.activity_log.insert_one({
                "id": str(uuid.uuid4()),
                "user_id": schedule["user_id"],
                "action": f"Auto-executed scheduled scan: {schedule['name']}",
                "target": f"{len(schedule['targets'])} targets",
                "created_at": now.isoformat()
            })
            
    except Exception as e:
        logger.error(f"Scheduler error: {e}")

# ==================== MODELS ====================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    username: str
    role: str = "tester"

def _ensure_nmap_installed():
    """Self-heal: install nmap on startup if it's missing.

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    role: str
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    session_id: str

class ScanCreate(BaseModel):
    scan_type: str  # recon, vuln, network
    target: str
    options: Optional[dict] = {}

class ScanResponse(BaseModel):
    id: str
    scan_type: str
    target: str
    status: str
    created_at: str
    results: Optional[dict] = None

class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    vulnerabilities_found: int
    critical_alerts: int
    recent_activity: List[dict]

# Bulk Scan Models
class BulkScanCreate(BaseModel):
    scan_type: str = "recon"
    targets: List[str] = []  # List of IPs/domains
    cidr: Optional[str] = None  # CIDR notation like 192.168.1.0/24
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

# Scheduled Scan Models
class ScheduledScanCreate(BaseModel):
    name: str
    scan_type: str = "recon"
    targets: List[str]
    schedule_type: str  # daily, weekly, monthly
    schedule_time: str  # HH:MM format
    schedule_day: Optional[int] = None  # Day of week (0-6) or day of month (1-31)
    enabled: bool = True

class ScheduledScanResponse(BaseModel):
    id: str
    name: str
    scan_type: str
    targets: List[str]
    schedule_type: str
    schedule_time: str
    schedule_day: Optional[int]
    enabled: bool
    last_run: Optional[str]
    next_run: Optional[str]
    created_at: str

# ==================== AUTH HELPERS ====================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", "nmap"],
            check=True, capture_output=True, timeout=120, env=env,
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["email"], user["role"])
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            username=user["username"],
            role=user["role"],
            created_at=user["created_at"]
        )
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

# ==================== AI CHAT ENDPOINTS ====================

@api_router.post("/chat", response_model=ChatResponse)
async def chat_with_ai(message: ChatMessage, current_user: dict = Depends(get_current_user)):
    session_id = message.session_id or str(uuid.uuid4())
    
    try:
        api_key = os.environ.get('EMERGENT_LLM_KEY')
        if not api_key:
            raise HTTPException(status_code=500, detail="AI service not configured")
        
        system_prompt = """You are PentestAI, an advanced AI assistant for ethical penetration testing and cybersecurity. You help security professionals with:

1. **Reconnaissance**: Suggest tools (Nmap, Shodan, whois, dig, recon-ng) and interpret scan results
2. **Vulnerability Assessment**: Identify potential vulnerabilities from scan data, suggest exploits
3. **Network Analysis**: Help analyze traffic patterns, identify anomalies
4. **Exploitation Guidance**: Provide ethical guidance on Metasploit, Empire, and other frameworks
5. **Reporting**: Help generate professional security reports

IMPORTANT RULES:
- Only assist with AUTHORIZED penetration testing
- Always emphasize legal and ethical considerations
- Provide educational content for learning purposes
- Suggest proper authorization before any testing
- Format responses with clear headers and bullet points
- Include command examples when relevant

When suggesting commands, format them in code blocks for easy copying."""

        chat = LlmChat(
            api_key=api_key,
            session_id=f"{current_user['id']}_{session_id}",
            system_message=system_prompt
        ).with_model("anthropic", "claude-sonnet-4-5-20250929")
        
        user_message = UserMessage(text=message.message)
        response = await chat.send_message(user_message)
        
        # Store chat history
        await db.chat_history.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": current_user["id"],
            "session_id": session_id,
            "message": message.message,
            "response": response,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        
        return ChatResponse(response=response, session_id=session_id)
        
    except Exception as e:
        logger.error(f"AI Chat error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI service error: {str(e)}")

@api_router.get("/chat/history")
async def get_chat_history(session_id: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {"user_id": current_user["id"]}
    if session_id:
        query["session_id"] = session_id
    
    history = await db.chat_history.find(query, {"_id": 0}).sort("created_at", -1).to_list(50)
    return {"history": history}

# ==================== SCAN ENDPOINTS ====================

@api_router.post("/scans", response_model=ScanResponse)
async def create_scan(scan_data: ScanCreate, current_user: dict = Depends(get_current_user)):
    scan_id = str(uuid.uuid4())
    
    # Validate target
    if not is_valid_target(scan_data.target):
        raise HTTPException(status_code=400, detail="Invalid target format. Use domain name or IP address.")
    
    # Perform real scan based on type
    try:
        if scan_data.scan_type == "recon":
            scan_results = await perform_recon_scan(scan_data.target)
        elif scan_data.scan_type == "vuln":
            # First do a quick port scan, then vulnerability analysis
            recon_results = await perform_recon_scan(scan_data.target)
            scan_results = generate_vuln_scan_results(scan_data.target, recon_results.get("ports", []))
        elif scan_data.scan_type == "network":
            scan_results = generate_network_scan_results(scan_data.target)
        else:
            scan_results = {"target": scan_data.target, "message": "Unknown scan type"}
    except Exception as e:
        logger.error(f"Scan failed for {scan_data.target}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    
    scan_doc = {
        "id": scan_id,
        "user_id": current_user["id"],
        "scan_type": scan_data.scan_type,
        "target": scan_data.target,
        "options": scan_data.options,
        "status": "completed",
        "results": scan_results,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.scans.insert_one(scan_doc)
    
    # Log activity
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "action": f"Created {scan_data.scan_type} scan",
        "target": scan_data.target,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    return ScanResponse(
        id=scan_id,
        scan_type=scan_data.scan_type,
        target=scan_data.target,
        status="completed",
        created_at=scan_doc["created_at"],
        results=scan_results
    )

@api_router.get("/scans", response_model=List[ScanResponse])
async def list_scans(current_user: dict = Depends(get_current_user)):
    scans = await db.scans.find(
        {"user_id": current_user["id"]}, 
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return [ScanResponse(**scan) for scan in scans]

@api_router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = await db.scans.find_one(
        {"id": scan_id, "user_id": current_user["id"]},
        {"_id": 0}
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(**scan)

@api_router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.scans.delete_one({"id": scan_id, "user_id": current_user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan deleted"}

# ==================== SCAN EXPORT ENDPOINTS ====================

@api_router.get("/scans/{scan_id}/export")
async def export_scan(scan_id: str, format: str = "json", current_user: dict = Depends(get_current_user)):
    """Export scan results as JSON or CSV"""
    scan = await db.scans.find_one(
        {"id": scan_id, "user_id": current_user["id"]},
        {"_id": 0}
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if format.lower() == "csv":
        # Generate CSV export
        import csv
        output = io.StringIO()
        
        results = scan.get("results", {})
        
        # Write metadata
        writer = csv.writer(output)
        writer.writerow(["# PentestAI Scan Export"])
        writer.writerow(["Scan ID", scan.get("id")])
        writer.writerow(["Target", scan.get("target")])
        writer.writerow(["Scan Type", scan.get("scan_type")])
        writer.writerow(["Status", scan.get("status")])
        writer.writerow(["Created", scan.get("created_at")])
        writer.writerow([])
        
        # Write ports section
        ports = results.get("ports", [])
        if ports:
            writer.writerow(["# Open Ports"])
            writer.writerow(["Port", "Service", "State", "Version", "Source"])
            for port in ports:
                writer.writerow([
                    port.get("port"),
                    port.get("service"),
                    port.get("state"),
                    port.get("version", ""),
                    port.get("source", "local")
                ])
            writer.writerow([])
        
        # Write DNS records
        dns_records = results.get("dns_records", [])
        if dns_records:
            writer.writerow(["# DNS Records"])
            writer.writerow(["Type", "Value"])
            for record in dns_records:
                writer.writerow([record.get("type"), record.get("value")])
            writer.writerow([])
        
        # Write vulnerabilities section
        vulns = results.get("vulnerabilities", [])
        if vulns:
            writer.writerow(["# Vulnerabilities"])
            writer.writerow(["ID", "Severity", "CVSS", "Description", "Remediation", "Source"])
            for vuln in vulns:
                writer.writerow([
                    vuln.get("id"),
                    vuln.get("severity"),
                    vuln.get("cvss", ""),
                    vuln.get("description", "")[:200],
                    vuln.get("remediation", ""),
                    vuln.get("source", "local")
                ])
            writer.writerow([])
        
        # Write Shodan data if available
        shodan = results.get("shodan")
        if shodan and "error" not in shodan:
            writer.writerow(["# Shodan Intelligence"])
            writer.writerow(["Field", "Value"])
            writer.writerow(["Organization", shodan.get("organization", "")])
            writer.writerow(["ISP", shodan.get("isp", "")])
            writer.writerow(["ASN", shodan.get("asn", "")])
            writer.writerow(["Country", shodan.get("country", "")])
            writer.writerow(["City", shodan.get("city", "")])
            writer.writerow([])
        
        csv_content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(csv_content.encode('utf-8')),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.csv"
            }
        )
    
    else:  # JSON format
        # Return clean JSON export
        export_data = {
            "export_info": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "platform": "PentestAI",
                "version": "1.0"
            },
            "scan": {
                "id": scan.get("id"),
                "target": scan.get("target"),
                "scan_type": scan.get("scan_type"),
                "status": scan.get("status"),
                "created_at": scan.get("created_at"),
            },
            "results": scan.get("results", {})
        }
        
        json_content = json.dumps(export_data, indent=2)
        return StreamingResponse(
            io.BytesIO(json_content.encode('utf-8')),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.json"
            }
        )

# ==================== DASHBOARD ENDPOINTS ====================

@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    total_scans = await db.scans.count_documents({"user_id": current_user["id"]})
    
    # Get vulnerability count from scan results
    scans = await db.scans.find({"user_id": current_user["id"]}, {"_id": 0, "results": 1}).to_list(100)
    vuln_count = sum(len(s.get("results", {}).get("vulnerabilities", [])) for s in scans)
    critical_count = sum(
        1 for s in scans 
        for v in s.get("results", {}).get("vulnerabilities", [])
        if v.get("severity") == "critical"
    )
    
    # Recent activity
    activity = await db.activity_log.find(
        {"user_id": current_user["id"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(10)
    
    return DashboardStats(
        total_scans=total_scans,
        active_scans=0,
        vulnerabilities_found=vuln_count,
        critical_alerts=critical_count,
        recent_activity=activity
    )

@api_router.get("/dashboard/vulnerability-trends")
async def get_vulnerability_trends(current_user: dict = Depends(get_current_user)):
    # Mock trend data for visualization
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

# ==================== REPORTS ENDPOINTS ====================

@api_router.get("/reports")
async def list_reports(current_user: dict = Depends(get_current_user)):
    reports = await db.reports.find(
        {"user_id": current_user["id"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    return {"reports": reports}

@api_router.post("/reports/generate")
async def generate_report(scan_ids: List[str], current_user: dict = Depends(get_current_user)):
    # Fetch scans
    scans = await db.scans.find(
        {"id": {"$in": scan_ids}, "user_id": current_user["id"]},
        {"_id": 0}
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
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.reports.insert_one(report)
    report.pop("_id", None)
    return report

# ==================== CVE DETAILS ENDPOINT ====================

@api_router.get("/cve/{cve_id}")
async def get_cve_details(cve_id: str, current_user: dict = Depends(get_current_user)):
    """Fetch CVE details from NVD (National Vulnerability Database)"""
    # Validate CVE format
    if not cve_id.upper().startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE format. Expected CVE-YYYY-NNNNN")
    
    cve_id = cve_id.upper()
    
    # Check cache first
    cached = await db.cve_cache.find_one({"cve_id": cve_id}, {"_id": 0})
    if cached:
        # Return cached if less than 24 hours old
        cached_time = datetime.fromisoformat(cached.get("cached_at", "2000-01-01"))
        if datetime.now(timezone.utc) - cached_time < timedelta(hours=24):
            return cached["data"]
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # NVD API 2.0
            response = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id}
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail="Failed to fetch CVE data from NVD")
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
            
            cve_data = vulnerabilities[0].get("cve", {})
            
            # Extract relevant information
            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available")
            
            # Get CVSS scores
            metrics = cve_data.get("metrics", {})
            cvss_v3 = None
            cvss_v2 = None
            
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_v3 = {
                    "version": "3.1",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                    "attack_vector": cvss_data.get("attackVector"),
                    "attack_complexity": cvss_data.get("attackComplexity"),
                    "privileges_required": cvss_data.get("privilegesRequired"),
                    "user_interaction": cvss_data.get("userInteraction"),
                    "scope": cvss_data.get("scope"),
                    "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                    "integrity_impact": cvss_data.get("integrityImpact"),
                    "availability_impact": cvss_data.get("availabilityImpact")
                }
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_v3 = {
                    "version": "3.0",
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString")
                }
            
            if "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_v2 = {
                    "version": "2.0",
                    "score": cvss_data.get("baseScore"),
                    "vector": cvss_data.get("vectorString")
                }
            
            # Get references
            references = [
                {"url": ref.get("url"), "source": ref.get("source"), "tags": ref.get("tags", [])}
                for ref in cve_data.get("references", [])[:10]
            ]
            
            # Get affected configurations/products
            configurations = cve_data.get("configurations", [])
            affected_products = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            cpe = match.get("criteria", "")
                            # Parse CPE string to get product info
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                affected_products.append({
                                    "vendor": parts[3] if len(parts) > 3 else "unknown",
                                    "product": parts[4] if len(parts) > 4 else "unknown",
                                    "version_start": match.get("versionStartIncluding"),
                                    "version_end": match.get("versionEndExcluding") or match.get("versionEndIncluding")
                                })
            
            # Get weakness (CWE)
            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_ids.append(desc.get("value"))
            
            # Helper function to derive severity from CVSS v2 score
            def get_severity_from_v2_score(score):
                if score is None:
                    return "UNKNOWN"
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            
            # Determine severity - prefer v3, fall back to v2-derived
            if cvss_v3:
                severity = cvss_v3["severity"]
            elif cvss_v2:
                severity = get_severity_from_v2_score(cvss_v2["score"])
            else:
                severity = "UNKNOWN"
            
            result = {
                "cve_id": cve_id,
                "description": description,
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "severity": severity,
                "score": cvss_v3["score"] if cvss_v3 else (cvss_v2["score"] if cvss_v2 else None),
                "weaknesses": cwe_ids,
                "affected_products": affected_products[:20],
                "references": references,
                "source": "NVD"
            }
            
            # Cache the result
            await db.cve_cache.update_one(
                {"cve_id": cve_id},
                {"$set": {"cve_id": cve_id, "data": result, "cached_at": datetime.now(timezone.utc).isoformat()}},
                upsert=True
            )
            
            return result
            
    except HTTPException:
        raise  # Re-raise HTTP exceptions (404, 400, etc.) without modification
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="NVD API timeout")
    except Exception as e:
        logger.error(f"CVE lookup error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch CVE details: {str(e)}")

# ==================== BULK SCAN ENDPOINTS ====================

def parse_cidr(cidr: str) -> List[str]:
    """Parse CIDR notation and return list of IPs (limited to 256 for safety)"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Limit to /24 or smaller for safety
        if network.num_addresses > 256:
            raise ValueError("CIDR range too large. Maximum /24 (256 hosts) allowed")
        return [str(ip) for ip in network.hosts()][:256]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {str(e)}")

async def run_bulk_scan_job(bulk_scan_id: str, user_id: str, targets: List[str], scan_type: str):
    """Background task to run bulk scans with concurrent execution"""
    results = []
    completed = 0
    failed = 0
    lock = asyncio.Lock()
    
    # Semaphore to limit concurrent scans (max 5 at a time)
    semaphore = asyncio.Semaphore(5)
    
    async def scan_target(target: str) -> dict:
        """Scan a single target with semaphore control"""
        nonlocal completed, failed
        
        async with semaphore:
            try:
                # Perform scan based on type
                if scan_type == "recon":
                    scan_result = await perform_recon_scan(target)
                elif scan_type == "vuln":
                    recon_result = await perform_recon_scan(target)
                    scan_result = generate_vuln_scan_results(target, recon_result.get("ports", []))
                else:
                    scan_result = {"target": target, "error": "Unknown scan type"}
                
                # Store individual scan result
                scan_id = str(uuid.uuid4())
                scan_doc = {
                    "id": scan_id,
                    "user_id": user_id,
                    "bulk_scan_id": bulk_scan_id,
                    "scan_type": scan_type,
                    "target": target,
                    "status": "completed" if "error" not in scan_result else "failed",
                    "results": scan_result,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                await db.scans.insert_one(scan_doc)
                
                result = {
                    "target": target,
                    "scan_id": scan_id,
                    "status": "completed" if "error" not in scan_result else "failed",
                    "vulnerabilities_count": len(scan_result.get("vulnerabilities", []))
                }
                
                # Update progress with lock
                async with lock:
                    completed += 1
                    await db.bulk_scans.update_one(
                        {"id": bulk_scan_id},
                        {"$set": {"completed": completed, "status": "running"}}
                    )
                    
                    # Send WebSocket progress update
                    await ws_manager.send_progress(bulk_scan_id, {
                        "type": "progress",
                        "scan_id": bulk_scan_id,
                        "target": target,
                        "completed": completed,
                        "total": len(targets),
                        "failed": failed,
                        "status": "running",
                        "result": result
                    })
                
                return result
                
            except Exception as e:
                logger.error(f"Bulk scan error for {target}: {e}")
                async with lock:
                    failed += 1
                    await ws_manager.send_progress(bulk_scan_id, {
                        "type": "error",
                        "scan_id": bulk_scan_id,
                        "target": target,
                        "error": str(e),
                        "completed": completed,
                        "total": len(targets),
                        "failed": failed
                    })
                return {"target": target, "status": "failed", "error": str(e)}
    
    # Mark as running
    await db.bulk_scans.update_one(
        {"id": bulk_scan_id},
        {"$set": {"status": "running"}}
    )
    
    # Send initial WebSocket notification
    await ws_manager.send_progress(bulk_scan_id, {
        "type": "started",
        "scan_id": bulk_scan_id,
        "total": len(targets),
        "status": "running"
    })
    
    # Run all scans concurrently with semaphore limiting
    results = await asyncio.gather(*[scan_target(target) for target in targets])
    
    # Update final status
    await db.bulk_scans.update_one(
        {"id": bulk_scan_id},
        {
            "$set": {
                "status": "completed",
                "completed": completed,
                "failed": failed,
                "results": results,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Send completion WebSocket notification
    await ws_manager.send_progress(bulk_scan_id, {
        "type": "completed",
        "scan_id": bulk_scan_id,
        "completed": completed,
        "total": len(targets),
        "failed": failed,
        "status": "completed"
    })
    
    # Log activity
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "action": f"Completed bulk {scan_type} scan",
        "target": f"{completed} targets scanned",
        "created_at": datetime.now(timezone.utc).isoformat()
    })

@api_router.post("/bulk-scans", response_model=BulkScanResponse)
async def create_bulk_scan(
    scan_data: BulkScanCreate, 
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Create a bulk scan for multiple targets"""
    targets = list(scan_data.targets)
    
    # Parse CIDR if provided
    if scan_data.cidr:
        cidr_targets = parse_cidr(scan_data.cidr)
        targets.extend(cidr_targets)
    
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")
    
    # Validate all targets
    invalid_targets = [t for t in targets if not is_valid_target(t)]
    if invalid_targets:
        raise HTTPException(status_code=400, detail=f"Invalid targets: {', '.join(invalid_targets[:5])}")
    
    # Limit total targets
    if len(targets) > 256:
        raise HTTPException(status_code=400, detail="Maximum 256 targets allowed per bulk scan")
    
    # Remove duplicates
    targets = list(set(targets))
    
    bulk_scan_id = str(uuid.uuid4())
    bulk_scan_doc = {
        "id": bulk_scan_id,
        "user_id": current_user["id"],
        "scan_type": scan_data.scan_type,
        "targets": targets,
        "total_targets": len(targets),
        "completed": 0,
        "failed": 0,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.bulk_scans.insert_one(bulk_scan_doc)
    
    # Start background task
    background_tasks.add_task(
        run_bulk_scan_job, 
        bulk_scan_id, 
        current_user["id"], 
        targets, 
        scan_data.scan_type
    )
    
    return BulkScanResponse(
        id=bulk_scan_id,
        scan_type=scan_data.scan_type,
        total_targets=len(targets),
        completed=0,
        failed=0,
        status="pending",
        created_at=bulk_scan_doc["created_at"]
    )

@api_router.get("/bulk-scans")
async def list_bulk_scans(current_user: dict = Depends(get_current_user)):
    """List all bulk scans for the current user"""
    scans = await db.bulk_scans.find(
        {"user_id": current_user["id"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    return {"bulk_scans": scans}

@api_router.get("/bulk-scans/{bulk_scan_id}")
async def get_bulk_scan(bulk_scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get details of a specific bulk scan"""
    scan = await db.bulk_scans.find_one(
        {"id": bulk_scan_id, "user_id": current_user["id"]},
        {"_id": 0}
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Bulk scan not found")
    return scan

# ==================== SCHEDULED SCAN ENDPOINTS ====================

def calculate_next_run(schedule_type: str, schedule_time: str, schedule_day: Optional[int] = None) -> str:
    """Calculate the next run time based on schedule configuration"""
    now = datetime.now(timezone.utc)
    hour, minute = map(int, schedule_time.split(":"))
    
    if schedule_type == "daily":
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
    
    elif schedule_type == "weekly":
        day_of_week = schedule_day or 0  # Monday by default
        days_ahead = day_of_week - now.weekday()
        if days_ahead < 0 or (days_ahead == 0 and now.hour >= hour):
            days_ahead += 7
        next_run = now + timedelta(days=days_ahead)
        next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
    
    elif schedule_type == "monthly":
        day_of_month = schedule_day or 1
        next_run = now.replace(day=min(day_of_month, 28), hour=hour, minute=minute, second=0, microsecond=0)
        if next_run <= now:
            # Move to next month
            if now.month == 12:
                next_run = next_run.replace(year=now.year + 1, month=1)
            else:
                next_run = next_run.replace(month=now.month + 1)
    
    else:
        next_run = now + timedelta(days=1)
    
    return next_run.isoformat()

@api_router.post("/scheduled-scans", response_model=ScheduledScanResponse)
async def create_scheduled_scan(
    scan_data: ScheduledScanCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new scheduled scan"""
    # Validate schedule_time format
    try:
        hour, minute = map(int, scan_data.schedule_time.split(":"))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError()
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid schedule_time format. Use HH:MM")
    
    # Validate schedule_type
    if scan_data.schedule_type not in ["daily", "weekly", "monthly"]:
        raise HTTPException(status_code=400, detail="schedule_type must be daily, weekly, or monthly")
    
    # Validate targets
    if not scan_data.targets:
        raise HTTPException(status_code=400, detail="At least one target required")
    
    invalid_targets = [t for t in scan_data.targets if not is_valid_target(t)]
    if invalid_targets:
        raise HTTPException(status_code=400, detail=f"Invalid targets: {', '.join(invalid_targets)}")
    
    schedule_id = str(uuid.uuid4())
    next_run = calculate_next_run(scan_data.schedule_type, scan_data.schedule_time, scan_data.schedule_day)
    
    schedule_doc = {
        "id": schedule_id,
        "user_id": current_user["id"],
        "name": scan_data.name,
        "scan_type": scan_data.scan_type,
        "targets": scan_data.targets,
        "schedule_type": scan_data.schedule_type,
        "schedule_time": scan_data.schedule_time,
        "schedule_day": scan_data.schedule_day,
        "enabled": scan_data.enabled,
        "last_run": None,
        "next_run": next_run,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.scheduled_scans.insert_one(schedule_doc)
    
    return ScheduledScanResponse(**{k: v for k, v in schedule_doc.items() if k != "_id"})

@api_router.get("/scheduled-scans")
async def list_scheduled_scans(current_user: dict = Depends(get_current_user)):
    """List all scheduled scans for the current user"""
    schedules = await db.scheduled_scans.find(
        {"user_id": current_user["id"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    return {"scheduled_scans": schedules}

@api_router.get("/scheduled-scans/{schedule_id}")
async def get_scheduled_scan(schedule_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific scheduled scan"""
    schedule = await db.scheduled_scans.find_one(
        {"id": schedule_id, "user_id": current_user["id"]},
        {"_id": 0}
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    return schedule

@api_router.patch("/scheduled-scans/{schedule_id}")
async def update_scheduled_scan(
    schedule_id: str,
    enabled: Optional[bool] = None,
    current_user: dict = Depends(get_current_user)
):
    """Toggle a scheduled scan on/off"""
    schedule = await db.scheduled_scans.find_one(
        {"id": schedule_id, "user_id": current_user["id"]}
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    update_data = {}
    if enabled is not None:
        update_data["enabled"] = enabled
        if enabled:
            # Recalculate next run
            update_data["next_run"] = calculate_next_run(
                schedule["schedule_type"],
                schedule["schedule_time"],
                schedule.get("schedule_day")
            )
    
    if update_data:
        await db.scheduled_scans.update_one(
            {"id": schedule_id},
            {"$set": update_data}
        )
    
    updated = await db.scheduled_scans.find_one({"id": schedule_id}, {"_id": 0})
    return updated

@api_router.delete("/scheduled-scans/{schedule_id}")
async def delete_scheduled_scan(schedule_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a scheduled scan"""
    result = await db.scheduled_scans.delete_one(
        {"id": schedule_id, "user_id": current_user["id"]}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    return {"message": "Scheduled scan deleted"}

@api_router.post("/scheduled-scans/{schedule_id}/run")
async def run_scheduled_scan_now(
    schedule_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Manually trigger a scheduled scan to run now"""
    schedule = await db.scheduled_scans.find_one(
        {"id": schedule_id, "user_id": current_user["id"]}
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    # Create a bulk scan from the scheduled scan
    bulk_scan_id = str(uuid.uuid4())
    bulk_scan_doc = {
        "id": bulk_scan_id,
        "user_id": current_user["id"],
        "scheduled_scan_id": schedule_id,
        "scan_type": schedule["scan_type"],
        "targets": schedule["targets"],
        "total_targets": len(schedule["targets"]),
        "completed": 0,
        "failed": 0,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.bulk_scans.insert_one(bulk_scan_doc)
    
    # Update last_run and next_run
    next_run = calculate_next_run(
        schedule["schedule_type"],
        schedule["schedule_time"],
        schedule.get("schedule_day")
    )
    await db.scheduled_scans.update_one(
        {"id": schedule_id},
        {"$set": {
            "last_run": datetime.now(timezone.utc).isoformat(),
            "next_run": next_run
        }}
    )
    
    # Start background task
    background_tasks.add_task(
        run_bulk_scan_job,
        bulk_scan_id,
        current_user["id"],
        schedule["targets"],
        schedule["scan_type"]
    )
    
    return {"message": "Scheduled scan started", "bulk_scan_id": bulk_scan_id}

# ==================== WEBSOCKET ENDPOINT ====================

@api_router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress updates"""
    await ws_manager.connect(websocket, scan_id)
    try:
        # Send initial status
        scan = await db.bulk_scans.find_one({"id": scan_id}, {"_id": 0})
        if scan:
            await websocket.send_json({
                "type": "status",
                "scan_id": scan_id,
                "status": scan.get("status"),
                "completed": scan.get("completed", 0),
                "total": scan.get("total_targets", 0),
                "failed": scan.get("failed", 0)
            })
        
        # Keep connection alive and wait for messages
        while True:
            try:
                # Wait for any message (ping/pong or close)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, scan_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket, scan_id)

# ==================== PDF REPORT GENERATION ====================

def generate_pdf_report(report_data: dict) -> io.BytesIO:
    """Generate a PDF security report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Title2', parent=styles['Title'], fontSize=24, spaceAfter=30))
    styles.add(ParagraphStyle(name='Heading2Custom', parent=styles['Heading2'], fontSize=16, spaceAfter=12, textColor=colors.HexColor('#3b82f6')))
    styles.add(ParagraphStyle(name='BodySmall', parent=styles['Normal'], fontSize=10))
    
    story = []
    
    # Title
    story.append(Paragraph("PentestAI Security Report", styles['Title2']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['BodySmall']))
    story.append(Spacer(1, 30))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading2Custom']))
    summary = report_data.get("summary", {})
    summary_data = [
        ["Total Vulnerabilities", str(summary.get("total_vulnerabilities", 0))],
        ["Critical", str(summary.get("critical", 0))],
        ["High", str(summary.get("high", 0))],
        ["Medium", str(summary.get("medium", 0))],
        ["Low", str(summary.get("low", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#334155')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#0f172a'), colors.HexColor('#1e293b')]),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Scans Included
    story.append(Paragraph("Scans Included", styles['Heading2Custom']))
    scans = report_data.get("scans", [])
    for scan in scans[:10]:  # Limit to 10 scans
        story.append(Paragraph(f"• {scan.get('target', 'Unknown')} ({scan.get('scan_type', 'unknown')})", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Detailed Findings
    story.append(Paragraph("Vulnerability Details", styles['Heading2Custom']))
    
    all_vulns = []
    for scan in scans:
        results = scan.get("results", {})
        for vuln in results.get("vulnerabilities", [])[:20]:  # Limit per scan
            all_vulns.append({
                "target": scan.get("target", "Unknown"),
                "id": vuln.get("id", "Unknown"),
                "severity": vuln.get("severity", "unknown").upper(),
                "description": vuln.get("description", "No description")[:100],
                "cvss": vuln.get("cvss", "N/A")
            })
    
    if all_vulns:
        vuln_data = [["Target", "CVE/ID", "Severity", "CVSS"]]
        for v in all_vulns[:30]:  # Limit total
            vuln_data.append([
                v["target"][:20],
                v["id"][:20],
                v["severity"],
                str(v["cvss"])
            ])
        
        vuln_table = Table(vuln_data, colWidths=[120, 120, 80, 60])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#334155')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#0f172a'), colors.HexColor('#1e293b')]),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
        ]))
        story.append(vuln_table)
    else:
        story.append(Paragraph("No vulnerabilities found in the selected scans.", styles['Normal']))
    
    story.append(Spacer(1, 30))
    
    # Footer
    story.append(Paragraph("---", styles['Normal']))
    story.append(Paragraph("Report generated by PentestAI Platform", styles['BodySmall']))
    story.append(Paragraph(f"Report ID: {report_data.get('id', 'N/A')}", styles['BodySmall']))
    
    doc.build(story)
    buffer.seek(0)
    return buffer

@api_router.get("/reports/{report_id}/pdf")
async def download_report_pdf(report_id: str, current_user: dict = Depends(get_current_user)):
    """Download a report as PDF"""
    report = await db.reports.find_one(
        {"id": report_id, "user_id": current_user["id"]},
        {"_id": 0}
    )
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Fetch actual scan data for the report
    scan_ids = report.get("scans", [])
    scans = await db.scans.find(
        {"id": {"$in": scan_ids}},
        {"_id": 0}
    ).to_list(len(scan_ids))
    
    # Create enriched report data
    report_data = {
        **report,
        "scans": scans
    }
    
    pdf_buffer = generate_pdf_report(report_data)
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=security_report_{report_id[:8]}.pdf"
        }
    )


@api_router.get("/")
async def root():
    return {"message": "PentestAI Platform API", "version": "2.0.0"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Start the scheduler on app startup"""
    scheduler.add_job(
        check_scheduled_scans,
        IntervalTrigger(minutes=1),
        id="scheduled_scan_checker",
        replace_existing=True
    )
    scheduler.start()
    logger.info("Scheduler started - checking for due scans every minute")

@app.on_event("shutdown")
async def shutdown_db_client():
    scheduler.shutdown()
    client.close()
