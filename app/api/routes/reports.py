"""PDF incident report generation and download."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import ApprovalRecord, Incident, InvestigationSession, ReportRecord, ResponseRecommendation
from ...reports.pdf import REPORT_DIR, generate_report
from ...security import client_ip, require_analyst
from ...services.audit import log_action
from ...utils.helpers import sha256_text

router = APIRouter(prefix="/reports", tags=["Reports"])


def _build_state(db: Session, incident: Incident) -> dict:
    session = db.scalar(
        select(InvestigationSession)
        .where(InvestigationSession.incident_fk == incident.id)
        .order_by(InvestigationSession.started_at.desc())
        .limit(1)
    )
    state = dict(session.state or {}) if session else {}
    evidence = [
        {
            "type": e.kind,
            "description": e.description,
            "event_uid": e.event_uid,
            "hash": e.hash_sha256,
        }
        for e in incident.evidence
    ]
    approvals = []
    for rec in incident.recommendations:
        for approval in rec.approvals:
            approvals.append(
                {
                    "title": rec.title,
                    "action_type": rec.action_type,
                    "decision": approval.action,
                    "analyst": approval.analyst,
                    "analyst_role": approval.analyst_role,
                    "reason": approval.reason,
                    "time": approval.created_at.isoformat() + "Z",
                }
            )
    state.setdefault("evidence", evidence)
    state.setdefault("approvals", approvals)
    if not state.get("risk_assessment") and incident.assessments:
        assessment = incident.assessments[0]
        state["risk_assessment"] = {
            "score": assessment.score,
            "severity": assessment.severity,
            "factors": assessment.factors,
            "recommendations": assessment.recommendations,
        }
    return state


@router.post("/generate/{incident_id}")
def generate(
    incident_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    state = _build_state(db, incident)
    path: Path = generate_report(incident, state)
    digest = sha256_text(path.read_bytes())
    record = ReportRecord(
        incident_fk=incident.id,
        file_name=path.name,
        generated_by=user.username,
        sha256=digest,
    )
    db.add(record)
    log_action(db, user.username, "report_generated", actor_role=user.role,
               target_type="incident", target_id=incident_id,
               details={"file": path.name, "sha256": digest}, ip_address=client_ip(request))
    db.commit()
    return {
        "incident_id": incident_id,
        "file_name": path.name,
        "sha256": digest,
        "download_url": f"/api/reports/{incident_id}/download",
        "size_bytes": path.stat().st_size,
    }


@router.get("")
def list_reports(limit: int = 50, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    rows = list(
        db.scalars(select(ReportRecord).order_by(ReportRecord.created_at.desc()).limit(min(200, limit))).all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "incident_id": r.incident.incident_id if r.incident else None,
                "file_name": r.file_name,
                "generated_by": r.generated_by,
                "sha256": r.sha256,
                "created_at": r.created_at.isoformat() + "Z",
                "download_url": f"/api/reports/{r.incident.incident_id}/download" if r.incident else None,
            }
            for r in rows
        ]
    }


@router.get("/{incident_id}/json")
def export_json(
    incident_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    """Machine-readable investigation report for API/SIEM consumers."""
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    state = _build_state(db, incident)
    sessions = db.scalars(
        select(InvestigationSession)
        .where(InvestigationSession.incident_fk == incident.id)
        .order_by(InvestigationSession.started_at.desc())
    ).all()
    assessments = [
        {
            "score": item.score,
            "severity": item.severity,
            "factors": item.factors,
            "evidence": item.evidence,
            "model_version": item.model_version,
            "created_at": item.created_at.isoformat() + "Z",
        }
        for item in incident.assessments
    ]
    recommendations = [
        {
            "action_type": item.action_type,
            "title": item.title,
            "target": item.target,
            "priority": item.priority,
            "status": item.status,
            "decision_reason": item.decision_reason,
            "analyst": item.analyst,
            "execution_mode": item.execution_mode,
            "execution_result": item.execution_result,
            "approvals": [
                {
                    "action": approval.action,
                    "analyst": approval.analyst,
                    "reason": approval.reason,
                    "created_at": approval.created_at.isoformat() + "Z",
                }
                for approval in item.approvals
            ],
        }
        for item in incident.recommendations
    ]
    return {
        "report_type": "SENTINELX incident export",
        "schema_version": "1.0",
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "generated_by": user.username,
        "incident": {
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
            "finding_summary": incident.finding_summary,
            "mitre": incident.mitre,
            "timeline": incident.timeline,
            "simulation": incident.simulation,
        },
        "evidence": state.get("evidence", []),
        "risk_assessment": state.get("risk_assessment"),
        "agent_findings": {
            session.session_uid: {
                "status": session.status,
                "llm_mode": session.llm_mode,
                "findings": session.state,
                "started_at": session.started_at.isoformat() + "Z",
                "finished_at": session.finished_at.isoformat() + "Z" if session.finished_at else None,
            }
            for session in sessions
        },
        "risk_assessments": assessments,
        "response_recommendations": recommendations,
        "approval_history": state.get("approvals", []),
        "disclaimer": "Rule matches and agent findings are investigatory leads, not proof of compromise. Response actions are simulated.",
    }


@router.get("/{incident_id}/download")
def download(incident_id: str, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> FileResponse:
    record = db.scalar(
        select(ReportRecord)
        .join(ReportRecord.incident)
        .where(Incident.incident_id == incident_id)
        .order_by(ReportRecord.created_at.desc())
        .limit(1)
    )
    if record is None:
        raise HTTPException(status_code=404, detail="No report generated for this incident")
    path = REPORT_DIR / record.file_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report file missing")
    return FileResponse(
        str(path),
        media_type="application/pdf",
        filename=record.file_name,
    )
