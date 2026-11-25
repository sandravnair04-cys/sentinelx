"""Overview dashboard statistics (all values read from the database)."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import Integer, func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...models import AgentExecution, Alert, Incident, InvestigationSession, SecurityEvent
from ...security import require_analyst

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
def stats(db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    total_events = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    total_alerts = db.scalar(select(func.count()).select_from(Alert)) or 0
    severity_rows = db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()
    severity = {str(row[0]): int(row[1]) for row in severity_rows}
    critical = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.severity == "CRITICAL")
    ) or 0
    high_risk = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.risk_score >= 60)
    ) or 0
    active_investigations = db.scalar(
        select(func.count()).select_from(InvestigationSession).where(
            InvestigationSession.status.in_(["running", "waiting_approval"])
        )
    ) or 0
    resolved = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.status == "Resolved")
    ) or 0
    pending_approvals = db.scalar(
        select(func.count()).select_from(AgentExecution)
    ) or 0
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_threats": critical,
        "high_risk_incidents": high_risk,
        "active_investigations": active_investigations,
        "resolved_incidents": resolved,
        "severity_distribution": {s: severity.get(s, 0) for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "total_incidents": db.scalar(select(func.count()).select_from(Incident)) or 0,
        "total_agent_executions": pending_approvals,
        "llm_mode": "api" if settings.llm_enabled else "fallback",
        "simulated_data": True,
    }


@router.get("/activity")
def activity(hours: int = 24, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    hours = max(1, min(720, hours))
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    rows = db.execute(
        select(SecurityEvent.timestamp, SecurityEvent.action)
        .where(SecurityEvent.timestamp >= cutoff)
    ).all()
    buckets: dict[str, dict[str, int]] = {}
    for ts, label in rows:
        key = ts.strftime("%Y-%m-%dT%H:00:00Z")
        bucket = buckets.setdefault(key, {"events": 0, "failures": 0, "successes": 0})
        bucket["events"] += 1
        if str(label) == "failure":
            bucket["failures"] += 1
        elif str(label) == "success":
            bucket["successes"] += 1
    series = [
        {"timestamp": key, **buckets[key]}
        for key in sorted(buckets)
    ]
    # Fill empty hourly buckets so charts have a continuous axis.
    filled = []
    current = cutoff.replace(minute=0, second=0, microsecond=0)
    end = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    by_key = {item["timestamp"]: item for item in series}
    while current <= end:
        key = current.strftime("%Y-%m-%dT%H:00:00Z")
        filled.append(by_key.get(key, {"timestamp": key, "events": 0, "failures": 0, "successes": 0}))
        current += timedelta(hours=1)
    return {"hours": hours, "series": filled[-168:]}


@router.get("/recent")
def recent(limit: int = 12, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    events = list(
        db.scalars(
            select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(min(100, limit))
        ).all()
    )
    incidents = list(
        db.scalars(select(Incident).order_by(Incident.detection_time.desc()).limit(min(50, limit))).all()
    )
    return {
        "events": [
            {
                "timestamp": e.timestamp.isoformat() + "Z",
                "event_code": e.event_code,
                "action": e.action,
                "username": e.username,
                "source_ip": e.source_ip,
                "host": e.host,
                "source_type": e.source_type,
                "message": e.message[:160],
            }
            for e in events
        ],
        "incidents": [
            {
                "incident_id": i.incident_id,
                "title": i.title,
                "severity": i.severity,
                "risk_score": i.risk_score,
                "status": i.status,
                "detection_time": i.detection_time.isoformat() + "Z",
            }
            for i in incidents
        ],
    }


@router.get("/agent-status")
def agent_status(db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    rows = db.execute(
        select(
            AgentExecution.agent_key,
            func.count().label("total"),
            func.sum(AgentExecution.success.cast(Integer)).label("successes"),
            func.max(AgentExecution.started_at),
        ).group_by(AgentExecution.agent_key)
    ).all()
    return {
        "agents": [
            {
                "agent_key": r[0],
                "executions": int(r[1] or 0),
                "successes": int(r[2] or 0),
                "last_run": r[3].isoformat() + "Z" if r[3] else None,
            }
            for r in rows
        ]
    }
