"""Audit logging helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditLog


def log_action(
    db: Session,
    actor: str,
    action: str,
    *,
    actor_role: str = "system",
    target_type: str = "",
    target_id: str = "",
    details: dict[str, Any] | None = None,
    ip_address: str = "",
) -> AuditLog:
    entry = AuditLog(
        actor=actor,
        actor_role=actor_role,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        details=details or {},
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
    return entry
