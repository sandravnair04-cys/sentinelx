"""Authentication, password hashing, JWT and role-based access control."""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# Simple in-process rate limiter. Production should use a shared store (Redis).
_rate_lock = threading.Lock()
_rate_attempts: dict[str, list[float]] = {}


def _password_bytes(password: str) -> bytes:
    """Pre-hash so bcrypt's 72-byte limit never silently truncates input."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_password_bytes(password), hashed.encode())
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str, role: str, expires_delta: timedelta | None = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": "sentinelx",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
            issuer="sentinelx",
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def check_rate_limit(key: str, limit: int | None = None, window: int | None = None) -> bool:
    """Return True when the request is allowed, False when rate-limited."""
    limit = settings.login_rate_limit if limit is None else limit
    window = settings.login_rate_window_seconds if window is None else window
    now = time.monotonic()
    with _rate_lock:
        attempts = _rate_attempts.setdefault(key, [])
        attempts[:] = [t for t in attempts if now - t < window]
        if len(attempts) >= limit:
            return False
        attempts.append(now)
        return True


def reset_rate_limit(key: str) -> None:
    with _rate_lock:
        _rate_attempts.pop(key, None)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_current_user(
    token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(token)
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive or unknown user")
    return user


def require_viewer(user: User = Depends(get_current_user)) -> User:
    """Read-only access: Administrator, SOC Analyst and Security Viewer."""
    if user.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=403, detail="Viewer role required")
    return user


def role_from_request(request: Request) -> str | None:
    """Best-effort role peek for the write guard. Never raises on bad tokens."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    try:
        return str(decode_token(header.split(" ", 1)[1]).get("role", ""))
    except HTTPException:
        return None


def require_analyst(user: User = Depends(get_current_user)) -> User:
    if user.role not in ("analyst", "admin"):
        raise HTTPException(status_code=403, detail="Analyst role required")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user
