"""Auth & MFA routes."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from core.db import db
from core.models import (
    UserCreate, UserLogin, UserResponse, TokenResponse, MFALogin, MFAVerify,
)
from core.security import (
    hash_password, verify_password, create_token, create_mfa_token, decode_mfa_token, get_current_user,
)
from services import mfa_service

router = APIRouter()


@router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
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
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(user_doc)
    token = create_token(user_id, user_data.email, user_data.role)
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id, email=user_data.email, username=user_data.username,
            role=user_data.role, created_at=user_doc["created_at"],
        ),
    )


@router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.get("mfa_enabled"):
        return TokenResponse(mfa_required=True, mfa_token=create_mfa_token(user["id"]))

    token = create_token(user["id"], user["email"], user["role"])
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"], email=user["email"], username=user["username"],
            role=user["role"], created_at=user["created_at"],
        ),
    )


@router.post("/auth/login/mfa", response_model=TokenResponse)
async def login_mfa(payload: MFALogin):
    user_id = decode_mfa_token(payload.mfa_token)
    user = await db.users.find_one({"id": user_id})
    if not user or not user.get("mfa_enabled") or not user.get("totp_secret"):
        raise HTTPException(status_code=401, detail="MFA not enabled for this account")
    if not mfa_service.verify_code(user["totp_secret"], payload.code):
        raise HTTPException(status_code=401, detail="Invalid authentication code")
    token = create_token(user["id"], user["email"], user["role"])
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"], email=user["email"], username=user["username"],
            role=user["role"], created_at=user["created_at"],
        ),
    )


@router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**{k: current_user[k] for k in ("id", "email", "username", "role", "created_at")})


@router.get("/auth/mfa/status")
async def mfa_status(current_user: dict = Depends(get_current_user)):
    return {"mfa_enabled": bool(current_user.get("mfa_enabled"))}


@router.post("/auth/mfa/setup")
async def mfa_setup(current_user: dict = Depends(get_current_user)):
    if current_user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA already enabled")
    secret = mfa_service.generate_secret()
    uri = mfa_service.provisioning_uri(current_user["email"], secret)
    qr = mfa_service.qr_data_url(uri)
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"pending_totp_secret": secret}})
    return {"secret": secret, "otpauth_uri": uri, "qr_code": qr}


@router.post("/auth/mfa/enable")
async def mfa_enable(payload: MFAVerify, current_user: dict = Depends(get_current_user)):
    user = await db.users.find_one({"id": current_user["id"]})
    pending = user.get("pending_totp_secret")
    if not pending:
        raise HTTPException(status_code=400, detail="Run /mfa/setup first")
    if not mfa_service.verify_code(pending, payload.code):
        raise HTTPException(status_code=400, detail="Invalid code")
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {"mfa_enabled": True, "totp_secret": pending}, "$unset": {"pending_totp_secret": ""}},
    )
    return {"mfa_enabled": True}


@router.post("/auth/mfa/disable")
async def mfa_disable(payload: MFAVerify, current_user: dict = Depends(get_current_user)):
    user = await db.users.find_one({"id": current_user["id"]})
    if not user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA not enabled")
    if not mfa_service.verify_code(user.get("totp_secret", ""), payload.code):
        raise HTTPException(status_code=400, detail="Invalid code")
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {"mfa_enabled": False}, "$unset": {"totp_secret": "", "pending_totp_secret": ""}},
    )
    return {"mfa_enabled": False}
