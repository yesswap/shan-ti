"""
Auth API routes:
  POST /auth/register          — register with email, get verification email
  GET  /auth/verify            — verify email token, returns API key
  GET  /auth/me                — current user info + usage stats
  POST /auth/keys              — create additional API key
  DELETE /auth/keys/{key_id}  — revoke a key
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
from models import APIUser, APIKey, EmailVerificationToken, APIUsageLog
from core.auth import generate_api_key, generate_verification_token, get_current_user, PLAN_LIMITS
from core.email import send_verification_email, send_api_key_email

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    name: Optional[str] = None


class RegisterResponse(BaseModel):
    message: str
    email: str


class VerifyResponse(BaseModel):
    message: str
    api_key: str
    key_prefix: str
    plan: str
    rate_limits: dict


class UserMeResponse(BaseModel):
    email: str
    name: Optional[str]
    plan: str
    is_verified: bool
    created_at: datetime
    api_keys: list
    usage_today: int
    usage_this_minute: int
    rate_limits: dict


class CreateKeyRequest(BaseModel):
    name: Optional[str] = "API Key"


class CreateKeyResponse(BaseModel):
    message: str
    api_key: str
    key_prefix: str
    name: str


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """Register with email. Sends a verification link."""
    # Check if already registered
    existing = db.query(APIUser).filter(APIUser.email == req.email).first()

    if existing and existing.is_verified:
        raise HTTPException(
            status_code=409,
            detail={"error": "already_registered", "message": "Email already registered. Check your inbox for your API key or log in."},
        )

    if not existing:
        user = APIUser(email=req.email, name=req.name)
        db.add(user)
        db.flush()
    else:
        user = existing

    # Create/replace verification token
    old_token = db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.used == False,
    ).first()
    if old_token:
        db.delete(old_token)

    token = generate_verification_token()
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    vtoken = EmailVerificationToken(user_id=user.id, token=token, expires_at=expires)
    db.add(vtoken)
    db.commit()

    send_verification_email(req.email, token)

    return RegisterResponse(
        message="Verification email sent. Check your inbox and click the link to get your API key.",
        email=req.email,
    )


@router.get("/verify", response_model=VerifyResponse)
def verify_email(token: str = Query(...), db: Session = Depends(get_db)):
    """Verify email token — returns a new API key."""
    vtoken = db.query(EmailVerificationToken).filter(
        EmailVerificationToken.token == token,
        EmailVerificationToken.used == False,
    ).first()

    if not vtoken:
        raise HTTPException(status_code=400, detail={"error": "invalid_token", "message": "Token is invalid or already used."})

    if vtoken.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail={"error": "token_expired", "message": "Token expired. Register again to get a new link."})

    user = db.query(APIUser).filter(APIUser.id == vtoken.user_id).first()
    user.is_verified = True
    vtoken.used = True

    # Generate API key
    raw_key, key_hash, key_prefix = generate_api_key()
    api_key_record = APIKey(
        user_id=user.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name="Default Key",
    )
    db.add(api_key_record)
    db.commit()

    # Send key via email too (user may close the browser)
    send_api_key_email(user.email, raw_key)

    limits = PLAN_LIMITS[user.plan]
    return VerifyResponse(
        message="Email verified! Your API key is below. Save it — it won't be shown again.",
        api_key=raw_key,
        key_prefix=key_prefix,
        plan=user.plan,
        rate_limits=limits,
    )


@router.get("/me", response_model=UserMeResponse)
def get_me(auth=Depends(get_current_user), db: Session = Depends(get_db)):
    """Current user details and usage stats."""
    user, api_key = auth
    now = datetime.now(timezone.utc)

    usage_today = (
        db.query(func.count(APIUsageLog.id))
        .filter(APIUsageLog.user_id == user.id, APIUsageLog.created_at >= now - timedelta(days=1))
        .scalar() or 0
    )
    usage_minute = (
        db.query(func.count(APIUsageLog.id))
        .filter(APIUsageLog.user_id == user.id, APIUsageLog.created_at >= now - timedelta(minutes=1))
        .scalar() or 0
    )

    keys = db.query(APIKey).filter(APIKey.user_id == user.id, APIKey.is_active == True).all()
    keys_out = [{"id": k.id, "prefix": k.key_prefix, "name": k.name, "last_used": k.last_used_at} for k in keys]

    return UserMeResponse(
        email=user.email,
        name=user.name,
        plan=user.plan,
        is_verified=user.is_verified,
        created_at=user.created_at,
        api_keys=keys_out,
        usage_today=usage_today,
        usage_this_minute=usage_minute,
        rate_limits=PLAN_LIMITS[user.plan],
    )


@router.post("/keys", response_model=CreateKeyResponse)
def create_key(req: CreateKeyRequest, auth=Depends(get_current_user), db: Session = Depends(get_db)):
    """Create an additional API key (max 5 per free account)."""
    user, _ = auth

    max_keys = 5 if user.plan == "free" else 20
    existing_count = db.query(APIKey).filter(APIKey.user_id == user.id, APIKey.is_active == True).count()
    if existing_count >= max_keys:
        raise HTTPException(status_code=400, detail={"error": "max_keys", "message": f"Maximum {max_keys} active keys allowed on your plan."})

    raw_key, key_hash, key_prefix = generate_api_key()
    api_key_record = APIKey(user_id=user.id, key_hash=key_hash, key_prefix=key_prefix, name=req.name)
    db.add(api_key_record)
    db.commit()

    return CreateKeyResponse(
        message="New API key created. Save it now — it won't be shown again.",
        api_key=raw_key,
        key_prefix=key_prefix,
        name=req.name,
    )


@router.delete("/keys/{key_id}")
def revoke_key(key_id: int, auth=Depends(get_current_user), db: Session = Depends(get_db)):
    """Revoke an API key."""
    user, current_key = auth

    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    if key.id == current_key.id:
        raise HTTPException(status_code=400, detail={"error": "cannot_revoke_current", "message": "Cannot revoke the key you're currently using."})

    key.is_active = False
    db.commit()
    return {"message": f"Key {key.key_prefix}... revoked successfully."}
