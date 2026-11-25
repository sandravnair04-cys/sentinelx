"""Human-approved incident response centre (simulated execution only)."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...models import (
    ApprovalRecord,
    AuditLog,
    Incident,
    ResponseRecommendation,
)
from ...schemas import ApprovalDecision
from ...security import client_ip, require_analyst, require_admin
from ...services.audit import log_action

router = APIRouter(prefix="/response", tags=["Response"])

HIGH_IMPACT = {"block_ip", "disable_account", "isolate_endpoint"}


def _rec_out(rec: ResponseRecommendation) -> dict:
    return {
        "id": rec.id,
        "incident_id": rec.incident.incident_id if rec.incident else None,
        "session_uid": rec.session_uid,
        "action_type": rec.action_type,
        "target": rec.target,
        "title": rec.title,
        "description": rec.description,
        "purpose": rec.purpose,
        "risk_if_ignored": rec.risk_if_ignored,
        "priority": rec.priority,
        "status": rec.status,
        "suggested_by": rec.suggested_by,
        "analyst": rec.analyst,
        "analyst_role": rec.analyst_role,
        "decided_at": rec.decided_at.isoformat() + "Z" if rec.decided_at else None,
        "decision_reason": rec.decision_reason,
        "execution_mode": rec.execution_mode,
        "execution_result": rec.execution_result,
        "created_at": rec.created_at.isoformat() + "Z",
    }


@router.get("/recommendations")
def list_recommendations(
    status: str | None = None, db: Session = Depends(get_db), _user=Depends(require_analyst)
) -> dict:
    query = select(ResponseRecommendation)
    if status:
        query = query.where(ResponseRecommendation.status == status)
    rows = list(db.scalars(query.order_by(ResponseRecommendation.created_at.desc())).all())
    return {"items": [_rec_out(r) for r in rows]}


def _decide(
    recommendation_id: int,
    decision: str,
    payload: ApprovalDecision,
    request: Request,
    db: Session,
    user,
) -> dict:
    rec = db.get(ResponseRecommendation, recommendation_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    if rec.status != "pending":
        raise HTTPException(status_code=409, detail="Recommendation already decided")
    if rec.action_type in HIGH_IMPACT and user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator role required for high-impact response actions",
        )
    if payload.analyst.strip().lower() != user.username.lower():
        raise HTTPException(status_code=403, detail="Analyst identity must match the authenticated user")

    rec.status = "approved" if decision == "approved" else "rejected"
    rec.analyst = payload.analyst
    rec.analyst_role = user.role
    rec.decided_at = datetime.utcnow()
    rec.decision_reason = payload.reason
    rec.execution_result = (
        "SIMULATED ONLY - no real action executed. "
        f"Action {decision} by {user.username}."
    )
    if not settings.response_execution_enabled:
        rec.execution_mode = "simulated"
    db.add(
        ApprovalRecord(
            recommendation_id=rec.id,
            action=decision,
            analyst=payload.analyst,
            analyst_role=user.role,
            reason=payload.reason,
        )
    )
    incident = db.get(Incident, rec.incident_fk)
    if incident:
        if decision == "approved":
            incident.status = "Contained"
        db.add(
            AuditLog(
                actor=user.username,
                actor_role=user.role,
                action=f"response_{decision}",
                target_type="response_recommendation",
                target_id=str(rec.id),
                details={"action_type": rec.action_type, "target": rec.target, "reason": payload.reason},
                ip_address=client_ip(request),
            )
        )
    db.commit()
    db.refresh(rec)
    return _rec_out(rec)


@router.post("/recommendations/{recommendation_id}/approve")
def approve(
    recommendation_id: int,
    payload: ApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    return _decide(recommendation_id, "approved", payload, request, db, user)


@router.post("/recommendations/{recommendation_id}/reject")
def reject(
    recommendation_id: int,
    payload: ApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    return _decide(recommendation_id, "rejected", payload, request, db, user)


@router.get("/history")
def history(db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    rows = list(
        db.scalars(
            select(ApprovalRecord).order_by(ApprovalRecord.created_at.desc()).limit(200)
        ).all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "recommendation_id": r.recommendation_id,
                "action": r.action,
                "analyst": r.analyst,
                "analyst_role": r.analyst_role,
                "reason": r.reason,
                "created_at": r.created_at.isoformat() + "Z",
            }
            for r in rows
        ]
    }
