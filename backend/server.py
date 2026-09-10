from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import ipaddress
import httpx
import asyncio
from emergentintegrations.llm.chat import LlmChat, UserMessage
from scanner import perform_recon_scan, generate_vuln_scan_results, generate_network_scan_results, is_valid_target

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

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

# ==================== MODELS ====================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    username: str
    role: str = "tester"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

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
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ==================== AUTH ENDPOINTS ====================

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "username": user_data.username,
        "password": hash_password(user_data.password),
        "role": user_data.role,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user_doc)
    
    token = create_token(user_id, user_data.email, user_data.role)
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            email=user_data.email,
            username=user_data.username,
            role=user_data.role,
            created_at=user_doc["created_at"]
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
    """Background task to run bulk scans"""
    results = []
    completed = 0
    failed = 0
    
    for target in targets:
        try:
            # Update progress
            await db.bulk_scans.update_one(
                {"id": bulk_scan_id},
                {"$set": {"completed": completed, "status": "running"}}
            )
            
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
            
            results.append({
                "target": target,
                "scan_id": scan_id,
                "status": "completed" if "error" not in scan_result else "failed",
                "vulnerabilities_count": len(scan_result.get("vulnerabilities", []))
            })
            completed += 1
            
            # Small delay to avoid overwhelming targets
            await asyncio.sleep(0.5)
            
        except Exception as e:
            logger.error(f"Bulk scan error for {target}: {e}")
            results.append({"target": target, "status": "failed", "error": str(e)})
            failed += 1
    
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

# ==================== ROOT ENDPOINT ====================

@api_router.get("/")
async def root():
    return {"message": "PentestAI Platform API", "version": "1.0.0"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
