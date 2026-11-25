"""Administration, settings, audit log and health endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import __version__
from ...config import settings
from ...database import get_db
from ...models import AuditLog, User
from ...schemas import RoleUpdate, UserOut
from ...security import require_admin, require_analyst
from ...services.retention import apply_retention

router = APIRouter(tags=["Administration"])


@router.post("/retention")
def run_retention(
    payload: dict | None = None,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
) -> dict:
    """Age out raw telemetry. Audits and incidents are preserved."""
    payload = payload or {}
    days = payload.get("days")
    if days is not None:
        days = int(days)
    return apply_retention(
        db,
        days=days,
        dry_run=bool(payload.get("dry_run", False)),
        actor=admin.username,
    )


@router.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": __version__,
        "environment": settings.app_env,
        "database": settings.database_url.split("://")[0],
    }


@router.get("/users")
def list_users(limit: int = 100, db: Session = Depends(get_db), _admin=Depends(require_admin)) -> dict:
    rows = list(db.scalars(select(User).order_by(User.created_at.desc()).limit(min(500, limit))).all())
    return {"items": [UserOut.model_validate(u).model_dump(mode="json") for u in rows]}


@router.patch("/users/{user_id}")
def update_user(
    user_id: int, payload: RoleUpdate, db: Session = Depends(get_db), admin=Depends(require_admin)
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and (payload.role != "admin" or payload.is_active is False):
        raise HTTPException(status_code=400, detail="Cannot demote or disable the current administrator")
    user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    db.commit()
    from ...services.audit import log_action
    log_action(db, admin.username, "user_updated", actor_role=admin.role,
               target_type="user", target_id=user.username,
               details={"role": user.role, "is_active": user.is_active})
    return UserOut.model_validate(user).model_dump(mode="json")


@router.get("/settings")
def get_settings(_user=Depends(require_analyst)) -> dict:
    return settings.public_dict()


@router.get("/audit")
def audit_log(
    limit: int = 100,
    action: str | None = None,
    actor: str | None = None,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
) -> dict:
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action.like(f"%{action}%"))
    if actor:
        query = query.where(AuditLog.actor == actor)
    rows = list(db.scalars(query.order_by(AuditLog.created_at.desc()).limit(min(500, limit))).all())
    return {
        "items": [
            {
                "id": r.id,
                "actor": r.actor,
                "actor_role": r.actor_role,
                "action": r.action,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "details": r.details,
                "ip_address": r.ip_address,
                "created_at": r.created_at.isoformat() + "Z",
            }
            for r in rows
        ]
    }
