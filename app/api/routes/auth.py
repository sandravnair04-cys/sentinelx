"""Authentication and user session endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...models import User
from ...schemas import LoginRequest, Token, UserCreate, UserOut
from ...security import (
    check_rate_limit,
    client_ip,
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    reset_rate_limit,
    verify_password,
)
from ...services.audit import log_action

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_admin),
) -> User:
    """Administrator-only registration. Self-registration cannot grant admin."""
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Username already exists")
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(
        email=str(payload.email),
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(
        db, actor.username, "user_created", actor_role=actor.role,
        target_type="user", target_id=user.username,
        details={"role": user.role}, ip_address=client_ip(request),
    )
    return user


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> Token:
    ip = client_ip(request)
    key = f"{ip}:{payload.username}"
    if not check_rate_limit(key):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again shortly.")
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(status_code=423, detail="Account temporarily locked")
    if not verify_password(payload.password, user.hashed_password):
        user.failed_logins += 1
        if user.failed_logins >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            user.failed_logins = 0
        db.commit()
        log_action(db, payload.username, "login_failed", target_type="user",
                   target_id=payload.username, ip_address=ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    db.commit()
    reset_rate_limit(key)
    log_action(db, user.username, "login_success", actor_role=user.role,
               target_type="user", target_id=user.username, ip_address=ip)
    return Token(
        access_token=create_access_token(user.username, user.role),
        expires_in=settings.access_token_expire_minutes * 60,
        role=user.role,
        username=user.username,
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    """Stateless JWT logout: the client discards the token; the event is audited."""
    log_action(db, user.username, "logout", actor_role=user.role,
               target_type="user", target_id=user.username, ip_address=client_ip(request))
    return {"status": "logged_out", "note": "Discard the bearer token in the client."}
