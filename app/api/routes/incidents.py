"""Incident management with a complete audit trail."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...correlation.engine import correlate_and_create
from ...database import get_db
from ...models import (
    ApprovalRecord,
    AuditLog,
    Evidence,
    Incident,
    InvestigationSession,
    ResponseRecommendation,
    RiskAssessment,
)
from ...schemas import IncidentUpdate
from ...security import client_ip, require_analyst
from ...services.audit import log_action

router = APIRouter(prefix="/incidents", tags=["Incidents"])

VALID_STATUSES = {"New", "Investigating", "Pending Approval", "Contained", "Resolved", "False Positive"}


def _incident_out(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "title": incident.title,
        "category": incident.category,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "source_ip": incident.source_ip,
        "username": incident.username,
        "host": incident.host,
        "detection_time": incident.detection_time.isoformat() + "Z",
        "resolved_at": incident.resolved_at.isoformat() + "Z" if incident.resolved_at else None,
        "finding_summary": incident.finding_summary,
        "timeline": incident.timeline,
        "mitre": incident.mitre,
        "simulation": incident.simulation,
        "updated_at": incident.updated_at.isoformat() + "Z" if incident.updated_at else None,
    }


@router.get("")
def list_incidents(
    limit: int = 100,
    offset: int = 0,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
) -> dict:
    limit, offset = max(1, min(500, limit)), max(0, offset)
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity.upper())
    if search:
        term = f"%{search}%"
        query = query.where(
            (Incident.title.like(term)) | (Incident.incident_id.like(term)) | (Incident.username.like(term))
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(db.scalars(query.order_by(Incident.detection_time.desc()).offset(offset).limit(limit)).all())
    return {"total": total, "items": [_incident_out(i) for i in rows]}


@router.post("/correlate")
def correlate(request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)) -> dict:
    result = correlate_and_create(db)
    log_action(db, user.username, "correlation_run", actor_role=user.role,
               target_type="incident", ip_address=client_ip(request), details=result)
    return result


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = list(db.scalars(select(Evidence).where(Evidence.incident_fk == incident.id)).all())
    assessments = list(
        db.scalars(
            select(RiskAssessment).where(RiskAssessment.incident_fk == incident.id)
            .order_by(RiskAssessment.created_at.desc())
        ).all()
    )
    recommendations = list(
        db.scalars(select(ResponseRecommendation).where(ResponseRecommendation.incident_fk == incident.id)).all()
    )
    approvals = list(
        db.scalars(
            select(ApprovalRecord)
            .where(ApprovalRecord.recommendation_id.in_([r.id for r in recommendations]))
            .order_by(ApprovalRecord.created_at.desc())
        ).all()
        if recommendations else []
    )
    audit = list(
        db.scalars(
            select(AuditLog)
            .where((AuditLog.target_type == "incident") & (AuditLog.target_id == incident_id))
            .order_by(AuditLog.created_at.desc())
            .limit(50)
        ).all()
    )
    sessions = list(
        db.scalars(
            select(InvestigationSession).where(InvestigationSession.incident_fk == incident.id)
            .order_by(InvestigationSession.started_at.desc())
        ).all()
    )
    return {
        **_incident_out(incident),
        "resolution_notes": incident.resolution_notes,
        "event_ids": incident.event_ids,
        "alert_ids": incident.alert_ids,
        "evidence": [
            {
                "id": e.id, "kind": e.kind, "description": e.description,
                "value": e.value, "hash_sha256": e.hash_sha256,
                "event_uid": e.event_uid,
                "created_at": e.created_at.isoformat() + "Z",
            }
            for e in evidence
        ],
        "risk_assessments": [
            {
                "score": a.score, "severity": a.severity, "factors": a.factors,
                "evidence": a.evidence, "recommendations": a.recommendations,
                "model_version": a.model_version, "created_at": a.created_at.isoformat() + "Z",
            }
            for a in assessments
        ],
        "recommendations": [
            {
                "id": r.id, "action_type": r.action_type, "target": r.target,
                "title": r.title, "description": r.description, "purpose": r.purpose,
                "risk_if_ignored": r.risk_if_ignored, "priority": r.priority,
                "status": r.status, "analyst": r.analyst, "analyst_role": r.analyst_role,
                "decided_at": r.decided_at.isoformat() + "Z" if r.decided_at else None,
                "decision_reason": r.decision_reason,
                "execution_result": r.execution_result,
            }
            for r in recommendations
        ],
        "approvals": [
            {
                "action": a.action, "analyst": a.analyst, "analyst_role": a.analyst_role,
                "reason": a.reason, "created_at": a.created_at.isoformat() + "Z",
            }
            for a in approvals
        ],
        "audit": [
            {
                "actor": a.actor, "actor_role": a.actor_role, "action": a.action,
                "details": a.details, "created_at": a.created_at.isoformat() + "Z",
            }
            for a in audit
        ],
        "sessions": [
            {
                "session_uid": s.session_uid, "status": s.status,
                "llm_mode": s.llm_mode, "current_step": s.current_step,
                "started_at": s.started_at.isoformat() + "Z",
                "finished_at": s.finished_at.isoformat() + "Z" if s.finished_at else None,
            }
            for s in sessions
        ],
    }


@router.patch("/{incident_id}")
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    changes: dict = {}
    if payload.status is not None:
        if payload.status not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Status must be one of {sorted(VALID_STATUSES)}")
        changes["status"] = payload.status
        incident.status = payload.status
        if payload.status in {"Resolved", "False Positive"}:
            incident.resolved_at = datetime.utcnow()
    for field_name in ("title", "severity", "resolution_notes", "finding_summary"):
        value = getattr(payload, field_name)
        if value is not None:
            if field_name == "severity" and value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise HTTPException(status_code=400, detail="Invalid severity")
            setattr(incident, field_name, value)
            changes[field_name] = value
    db.commit()
    log_action(db, user.username, "incident_updated", actor_role=user.role,
               target_type="incident", target_id=incident_id, details=changes,
               ip_address=client_ip(request))
    return _incident_out(incident)


@router.get("/{incident_id}/timeline")
def timeline(incident_id: str, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident_id, "timeline": incident.timeline or []}
