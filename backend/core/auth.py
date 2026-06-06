"""
Core API key management — generation, hashing, validation, rate limiting.
"""
import hashlib
import secrets
import string
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import HTTPException, Security, Request, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
from models import APIKey, APIUser, APIUsageLog

# ─── Constants ────────────────────────────────────────────────────────────────

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Rate limits per plan (requests per minute, requests per day)
PLAN_LIMITS = {
    "free":       {"per_minute": 10,  "per_day": 500},
    "pro":        {"per_minute": 60,  "per_day": 10_000},
    "enterprise": {"per_minute": 300, "per_day": 100_000},
}

KEY_PREFIX = "tl_"  # ThreatLens prefix — makes keys recognizable


# ─── Key Generation ───────────────────────────────────────────────────────────

def generate_api_key() -> Tuple[str, str, str]:
    """
    Returns (raw_key, key_hash, key_prefix)
    raw_key   — shown to user ONCE, never stored
    key_hash  — stored in DB (SHA-256)
    key_prefix — first 8 chars after prefix, stored for display
    """
    alphabet = string.ascii_letters + string.digits
    random_part = "".join(secrets.choice(alphabet) for _ in range(40))
    raw_key = f"{KEY_PREFIX}{random_part}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]  # "tl_XXXXX" portion
    return raw_key, key_hash, key_prefix


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_verification_token() -> str:
    return secrets.token_urlsafe(32)


# ─── Rate Limiting (DB-backed, Redis-optional) ────────────────────────────────

def _count_requests(db: Session, api_key_id: int, since: datetime) -> int:
    return (
        db.query(func.count(APIUsageLog.id))
        .filter(
            APIUsageLog.api_key_id == api_key_id,
            APIUsageLog.created_at >= since,
        )
        .scalar()
        or 0
    )


def check_rate_limit(db: Session, api_key: APIKey, user: APIUser):
    """Raises 429 if the key has exceeded its rate limits."""
    limits = PLAN_LIMITS.get(user.plan, PLAN_LIMITS["free"])

    per_minute = api_key.rate_limit_per_minute or limits["per_minute"]
    per_day = api_key.rate_limit_per_day or limits["per_day"]

    now = datetime.now(timezone.utc)

    minute_count = _count_requests(db, api_key.id, now - timedelta(minutes=1))
    if minute_count >= per_minute:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": f"Rate limit: {per_minute} requests/minute. Upgrade your plan for higher limits.",
                "retry_after_seconds": 60,
            },
            headers={"Retry-After": "60"},
        )

    day_count = _count_requests(db, api_key.id, now - timedelta(days=1))
    if day_count >= per_day:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "daily_limit_exceeded",
                "message": f"Daily limit: {per_day} requests/day reached. Resets in 24h.",
                "retry_after_seconds": 86400,
            },
            headers={"Retry-After": "86400"},
        )

    return minute_count, day_count


# ─── Auth Dependency ──────────────────────────────────────────────────────────

def get_current_user(
    request: Request,
    raw_key: Optional[str] = Security(API_KEY_HEADER),
    db: Session = Depends(get_db),
) -> Tuple[APIUser, APIKey]:
    """FastAPI dependency — validates API key, enforces rate limits, logs usage."""
    if not raw_key:
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_api_key", "message": "Provide your API key in X-API-Key header."},
        )

    key_hash = hash_key(raw_key)
    api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash, APIKey.is_active == True).first()

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_api_key", "message": "API key is invalid or has been revoked."},
        )

    # Check expiry
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=401,
            detail={"error": "expired_api_key", "message": "Your API key has expired."},
        )

    user = db.query(APIUser).filter(APIUser.id == api_key.user_id, APIUser.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail={"error": "user_not_found"})

    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail={"error": "email_not_verified", "message": "Please verify your email before using the API."},
        )

    # Rate limit check
    minute_count, day_count = check_rate_limit(db, api_key, user)

    # Update last used
    api_key.last_used_at = datetime.now(timezone.utc)
    db.commit()

    # Log usage (async-ish — done after response ideally, but fine here for v1)
    log = APIUsageLog(
        user_id=user.id,
        api_key_id=api_key.id,
        endpoint=str(request.url.path),
        method=request.method,
        status_code=200,
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    db.commit()

    return user, api_key


def get_optional_user(
    request: Request,
    raw_key: Optional[str] = Security(API_KEY_HEADER),
    db: Session = Depends(get_db),
) -> Optional[Tuple[APIUser, APIKey]]:
    """Like get_current_user but doesn't raise — for public endpoints with optional auth."""
    if not raw_key:
        return None
    try:
        return get_current_user(request, raw_key, db)
    except HTTPException:
        return None


def _is_web_request(request: Request) -> bool:
    """True when the request originates from our own web app (browser sends an
    Origin/Referer header). Used to let users browse the site freely while
    still gating programmatic API access behind an API key."""
    allowed = [
        o.strip().rstrip("/")
        for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
        if o.strip()
    ]
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") in allowed:
        return True
    referer = request.headers.get("referer")
    if referer and any(referer.startswith(o) for o in allowed):
        return True
    return False


def get_viewer(
    request: Request,
    raw_key: Optional[str] = Security(API_KEY_HEADER),
    db: Session = Depends(get_db),
) -> Optional[Tuple[APIUser, APIKey]]:
    """Read-access dependency.

    - Requests from the web app (browser) are allowed WITHOUT a key, so anyone
      can browse and page through the data with no restriction.
    - Direct/programmatic API calls still require a valid API key (and get
      rate-limited + logged).
    """
    if _is_web_request(request):
        # Web app: key optional. If one is supplied, honor it (for logging /
        # rate limits), but never block browsing on it.
        if raw_key:
            try:
                return get_current_user(request, raw_key, db)
            except HTTPException:
                return None
        return None
    # No web origin -> treat as API consumer -> require a valid key.
    return get_current_user(request, raw_key, db)
