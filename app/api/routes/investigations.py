"""AI investigation centre endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...agents.orchestrator import resume_investigation, start_investigation
from ...database import get_db
from ...models import AgentExecution, Incident, InvestigationSession
from ...schemas import ApprovalDecision, InvestigationStart
from ...security import client_ip, require_analyst
from ...services.audit import log_action

router = APIRouter(prefix="/investigations", tags=["Investigations"])


def _session_out(session: InvestigationSession) -> dict:
    return {
        "id": session.id,
        "session_uid": session.session_uid,
        "incident_id": (
            session.incident.incident_id if session.incident else None
        ),
        "status": session.status,
        "llm_mode": session.llm_mode,
        "current_step": session.current_step,
        "state": session.state,
        "error": session.error,
        "started_by": session.started_by,
        "started_at": session.started_at.isoformat() + "Z",
        "finished_at": session.finished_at.isoformat() + "Z" if session.finished_at else None,
    }


@router.post("/start")
def start(
    payload: InvestigationStart, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    try:
        result = start_investigation(db, payload.incident_id, user.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    log_action(db, user.username, "investigation_started", actor_role=user.role,
               target_type="incident", target_id=payload.incident_id,
               ip_address=client_ip(request), details={"session_uid": result["session_uid"]})
    return {
        "session_uid": result["session_uid"],
        "status": result["status"],
        "llm_mode": result["state"].get("llm_mode"),
    }


@router.get("")
def list_sessions(limit: int = 50, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    rows = list(
        db.scalars(
            select(InvestigationSession).order_by(InvestigationSession.started_at.desc()).limit(min(100, limit))
        ).all()
    )
    return {"items": [_session_out(s) for s in rows]}


@router.get("/incident/{incident_id}")
def for_incident(incident_id: str, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    rows = list(
        db.scalars(
            select(InvestigationSession)
            .join(InvestigationSession.incident)
            .where(Incident.incident_id == incident_id)
            .order_by(InvestigationSession.started_at.desc())
        ).all()
    )
    return {"items": [_session_out(s) for s in rows]}


@router.get("/{session_uid}")
def get_session(session_uid: str, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    session = db.scalar(
        select(InvestigationSession).where(InvestigationSession.session_uid == session_uid)
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Investigation session not found")
    executions = list(
        db.scalars(
            select(AgentExecution).where(AgentExecution.session_uid == session_uid)
            .order_by(AgentExecution.started_at.asc())
        ).all()
    )
    return {
        **_session_out(session),
        "executions": [
            {
                "agent_key": e.agent_key,
                "agent_name": e.agent_name,
                "role": e.role,
                "status": e.status,
                "started_at": e.started_at.isoformat() + "Z",
                "finished_at": e.finished_at.isoformat() + "Z" if e.finished_at else None,
                "duration_ms": e.duration_ms,
                "success": e.success,
                "error": e.error,
            }
            for e in executions
        ],
    }


@router.post("/{session_uid}/resume")
def resume(
    session_uid: str,
    payload: ApprovalDecision,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    try:
        result = resume_investigation(
            db, session_uid, payload.decision,
            payload.analyst, payload.role, payload.reason,
        )
    except (LookupError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_action(db, user.username, "investigation_resumed", actor_role=user.role,
               target_type="investigation", target_id=session_uid,
               ip_address=client_ip(request), details={"reason": payload.reason})
    return {"session_uid": result["session_uid"], "status": result["status"]}
