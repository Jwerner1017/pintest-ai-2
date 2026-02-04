from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
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
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'pentestai-secret-key-change-in-production')
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
    
    # Simulate scan results based on type
    mock_results = generate_mock_scan_results(scan_data.scan_type, scan_data.target)
    
    scan_doc = {
        "id": scan_id,
        "user_id": current_user["id"],
        "scan_type": scan_data.scan_type,
        "target": scan_data.target,
        "options": scan_data.options,
        "status": "completed",
        "results": mock_results,
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
        results=mock_results
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
    return report

# ==================== HELPER FUNCTIONS ====================

def generate_mock_scan_results(scan_type: str, target: str):
    """Generate realistic mock scan results for demonstration"""
    
    if scan_type == "recon":
        return {
            "target": target,
            "scan_type": "reconnaissance",
            "ports": [
                {"port": 22, "service": "ssh", "state": "open", "version": "OpenSSH 8.9"},
                {"port": 80, "service": "http", "state": "open", "version": "nginx 1.24.0"},
                {"port": 443, "service": "https", "state": "open", "version": "nginx 1.24.0"},
                {"port": 3306, "service": "mysql", "state": "filtered", "version": "unknown"},
            ],
            "os_detection": "Linux 5.x",
            "hostnames": [target],
            "whois": {
                "registrar": "Example Registrar",
                "creation_date": "2020-01-15",
                "expiration_date": "2025-01-15"
            },
            "dns_records": [
                {"type": "A", "value": "192.168.1.100"},
                {"type": "MX", "value": "mail." + target},
                {"type": "NS", "value": "ns1." + target}
            ],
            "vulnerabilities": [
                {"id": "CVE-2024-1234", "severity": "high", "description": "SSH authentication bypass vulnerability", "cvss": 8.1},
                {"id": "CVE-2024-5678", "severity": "medium", "description": "HTTP server information disclosure", "cvss": 5.3},
            ]
        }
    
    elif scan_type == "vuln":
        return {
            "target": target,
            "scan_type": "vulnerability",
            "vulnerabilities": [
                {"id": "CVE-2024-1234", "severity": "critical", "description": "Remote code execution in web framework", "cvss": 9.8, "remediation": "Update to latest version"},
                {"id": "CVE-2024-2345", "severity": "high", "description": "SQL injection in login form", "cvss": 8.6, "remediation": "Use parameterized queries"},
                {"id": "CVE-2024-3456", "severity": "high", "description": "Cross-site scripting (XSS) vulnerability", "cvss": 7.5, "remediation": "Implement input sanitization"},
                {"id": "CVE-2024-4567", "severity": "medium", "description": "Missing security headers", "cvss": 5.0, "remediation": "Add Content-Security-Policy header"},
                {"id": "CVE-2024-5678", "severity": "low", "description": "Server version disclosure", "cvss": 3.1, "remediation": "Hide server version in responses"},
            ],
            "risk_score": 7.8,
            "compliance": {
                "pci_dss": "Non-compliant",
                "owasp_top10": ["A03:2021 - Injection", "A07:2021 - XSS"]
            }
        }
    
    elif scan_type == "network":
        return {
            "target": target,
            "scan_type": "network_analysis",
            "traffic_summary": {
                "total_packets": 15420,
                "protocols": {"TCP": 12500, "UDP": 2500, "ICMP": 420},
                "top_talkers": [
                    {"ip": "192.168.1.100", "packets": 5000, "bytes": 2500000},
                    {"ip": "192.168.1.101", "packets": 3500, "bytes": 1750000},
                ]
            },
            "anomalies": [
                {"type": "Port Scan Detected", "severity": "high", "source": "10.0.0.50", "timestamp": datetime.now(timezone.utc).isoformat()},
                {"type": "Unusual DNS Query", "severity": "medium", "query": "suspicious.domain.com", "timestamp": datetime.now(timezone.utc).isoformat()},
            ],
            "vulnerabilities": [
                {"id": "NET-001", "severity": "medium", "description": "Unencrypted traffic detected", "cvss": 5.5},
            ]
        }
    
    return {"message": "Scan completed", "target": target}

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
