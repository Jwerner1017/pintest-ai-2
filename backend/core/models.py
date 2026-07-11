"""Pydantic request/response models shared across routers."""
from typing import List, Optional
from pydantic import BaseModel, EmailStr


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
    access_token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional[UserResponse] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MFALogin(BaseModel):
    mfa_token: str
    code: str


class MFAVerify(BaseModel):
    code: str


class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    session_id: str


class ScanCreate(BaseModel):
    scan_type: str
    target: str
    options: Optional[dict] = {}


class ScanResponse(BaseModel):
    id: str
    scan_type: str
    target: str
    status: str
    created_at: str
    progress: int = 0
    stage: Optional[str] = None
    results: Optional[dict] = None


class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    vulnerabilities_found: int
    critical_alerts: int
    recent_activity: List[dict]


class ShodanRequest(BaseModel):
    target: str
