"""Agent tools: read-only evidence access and state/execution persistence."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AgentExecution,
    Alert,
    Incident,
    InvestigationSession,
    ResponseRecommendation,
    SecurityEvent,
    ThreatIntelResult,
)


def _event_dict(event: SecurityEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "event_uid": event.event_uid,
        "source_type": event.source_type,
        "event_code": event.event_code,
        "action": event.action,
        "username": event.username,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "host": event.host,
        "timestamp": event.timestamp.isoformat() + "Z",
        "message": event.message[:500],
        "confidence": event.confidence,
    }


def _alert_dict(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "alert_uid": alert.alert_uid,
        "rule_name": alert.rule_name,
        "category": alert.category,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "title": alert.title,
        "description": alert.description,
        "evidence": alert.evidence,
        "mitre": alert.mitre,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "host": alert.host,
    }


def gather_context(db: Session, incident: Incident) -> dict[str, Any]:
    """Collect all evidence available for an investigation (read-only)."""
    uids = set(incident.event_ids or [])
    events = list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.event_uid.in_(uids))
            .order_by(SecurityEvent.timestamp.asc())
        ).all()
    ) if uids else []
    if not events:
        # Fallback: correlate by IP/user/host when explicit links are absent.
        query = select(SecurityEvent)
        clauses = []
        if incident.source_ip:
            clauses.append(SecurityEvent.source_ip == incident.source_ip)
        if incident.username:
            clauses.append(SecurityEvent.username == incident.username)
        if clauses:
            from sqlalchemy import or_
            events = list(db.scalars(query.where(or_(*clauses)).order_by(SecurityEvent.timestamp.asc())).all())

    alert_uids = set(incident.alert_ids or [])
    alerts = list(
        db.scalars(select(Alert).where(Alert.alert_uid.in_(alert_uids))).all()
    ) if alert_uids else list(db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(50)).all())

    indicators = {incident.source_ip} if incident.source_ip else set()
    for event in events:
        if event.source_ip:
            indicators.add(event.source_ip)
        if event.destination_ip:
            indicators.add(event.destination_ip)
    intel_rows = []
    if indicators:
        intel_rows = list(
            db.scalars(select(ThreatIntelResult).where(ThreatIntelResult.indicator.in_(indicators))).all()
        )
    return {
        "events": [_event_dict(e) for e in events],
        "alerts": [_alert_dict(a) for a in alerts],
        "intel": [
            {
                "indicator": r.indicator,
                "verdict": r.verdict,
                "score": r.score,
                "provider": r.provider,
                "details": r.details,
            }
            for r in intel_rows
        ],
    }


def persist_state(
    db: Session,
    session_uid: str,
    state: dict[str, Any],
    status: str | None = None,
    current_step: str | None = None,
    finished: bool = False,
) -> None:
    session = db.scalar(
        select(InvestigationSession).where(InvestigationSession.session_uid == session_uid)
    )
    if session is None:
        return
    session.state = json.loads(json.dumps(state, default=str))
    if status:
        session.status = status
    if current_step:
        session.current_step = current_step
    if finished:
        session.finished_at = datetime.utcnow()
    db.commit()


def run_recorded_agent(
    db: Session,
    state: dict[str, Any],
    key: str,
    name: str,
    role: str,
    fn: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Execute an agent, recording real start/end times, status and findings."""
    started = time.perf_counter()
    execution = AgentExecution(
        session_uid=state.get("session_uid", ""),
        agent_key=key,
        agent_name=name,
        role=role,
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(execution)
    db.commit()
    try:
        update = fn(state)
        findings = update.get(key, {}) if isinstance(update, dict) else {}
        if isinstance(update, list):
            findings = {"items": update}
        execution.status = "completed"
        execution.success = True
        execution.findings = json.loads(json.dumps(findings, default=str))
    except Exception as exc:  # Agent failures must not abort the workflow.
        update = {}
        execution.status = "failed"
        execution.error = f"{type(exc).__name__}: {str(exc)[:500]}"
        state.setdefault("errors", []).append(f"{name}: {execution.error}")
    execution.finished_at = datetime.utcnow()
    execution.duration_ms = int((time.perf_counter() - started) * 1000)
    db.commit()

    if isinstance(update, dict):
        for field, value in update.items():
            if field == "workflow":
                state.setdefault("workflow", []).extend(value)
            else:
                state[field] = value
    persist_state(db, state.get("session_uid", ""), state)
    return state


def create_response_records(
    db: Session, incident: Incident, session_uid: str, actions: list[dict[str, Any]]
) -> None:
    for action in actions:
        db.add(
            ResponseRecommendation(
                incident_fk=incident.id,
                session_uid=session_uid,
                action_type=str(action.get("action_type", "collect_evidence")),
                target=str(action.get("target", ""))[:255],
                title=str(action.get("title", "Recommended action"))[:255],
                description=str(action.get("description", "")),
                purpose=str(action.get("purpose", "")),
                risk_if_ignored=str(action.get("risk_if_ignored", "")),
                priority=str(action.get("priority", "medium")),
                status="pending",
                suggested_by="incident-response-agent",
                execution_mode="simulated",
            )
        )
    db.commit()
