"""AI agent monitoring - real execution records only."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import Integer, func, select
from sqlalchemy.orm import Session

from ...agents.state import AGENT_SEQUENCE
from ...config import settings
from ...database import get_db
from ...models import AgentExecution, InvestigationSession
from ...security import require_analyst

router = APIRouter(prefix="/agents", tags=["Agents"])

DEFINITIONS = [
    {"key": key, "name": name, "role": role, "workflow_step": index + 1}
    for index, (key, name, role) in enumerate(AGENT_SEQUENCE)
]


@router.get("")
def list_agents(db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    rows = db.execute(
        select(
            AgentExecution.agent_key,
            func.count().label("executions"),
            func.sum(AgentExecution.success.cast(Integer)).label("successes"),
            func.avg(AgentExecution.duration_ms).label("avg_duration"),
            func.max(AgentExecution.started_at).label("last_run"),
        ).group_by(AgentExecution.agent_key)
    ).all()
    stats = {r[0]: r for r in rows}
    active_sessions = db.scalar(
        select(func.count()).select_from(InvestigationSession).where(
            InvestigationSession.status == "running"
        )
    ) or 0
    waiting = db.scalar(
        select(func.count()).select_from(InvestigationSession).where(
            InvestigationSession.status == "waiting_approval"
        )
    ) or 0
    agents = []
    for definition in DEFINITIONS:
        row = stats.get(definition["key"])
        recent = list(
            db.scalars(
                select(AgentExecution)
                .where(AgentExecution.agent_key == definition["key"])
                .order_by(AgentExecution.started_at.desc())
                .limit(10)
            ).all()
        )
        last = recent[0] if recent else None
        if active_sessions and last and last.status == "running":
            status = "Running"
        elif waiting and definition["key"] == "incident_response":
            status = "Waiting for Approval"
        elif last:
            status = "Failed" if not last.success else "Completed"
        else:
            status = "Idle"
        agents.append(
            {
                **definition,
                "status": status,
                "total_executions": int(row[1] or 0) if row else 0,
                "successes": int(row[2] or 0) if row else 0,
                "failures": int((row[1] or 0) - (row[2] or 0)) if row else 0,
                "avg_duration_ms": round(float(row[3] or 0), 1) if row else 0,
                "last_execution": row[4].isoformat() + "Z" if row and row[4] else None,
                "recent_history": [
                    {
                        "status": e.status,
                        "duration_ms": e.duration_ms,
                        "started_at": e.started_at.isoformat() + "Z",
                        "error": e.error,
                    }
                    for e in recent
                ],
            }
        )
    return {"llm_mode": "api" if settings.llm_enabled else "fallback", "agents": agents}


@router.get("/{agent_key}/executions")
def executions(
    agent_key: str, limit: int = 50, db: Session = Depends(get_db), _user=Depends(require_analyst)
) -> dict:
    rows = list(
        db.scalars(
            select(AgentExecution)
            .where(AgentExecution.agent_key == agent_key)
            .order_by(AgentExecution.started_at.desc())
            .limit(min(200, limit))
        ).all()
    )
    return {
        "agent_key": agent_key,
        "items": [
            {
                "session_uid": e.session_uid,
                "status": e.status,
                "success": e.success,
                "started_at": e.started_at.isoformat() + "Z",
                "finished_at": e.finished_at.isoformat() + "Z" if e.finished_at else None,
                "duration_ms": e.duration_ms,
                "findings": e.findings,
                "error": e.error,
            }
            for e in rows
        ],
    }
