"""Shared, JSON-serialisable investigation state passed between agents."""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypedDict


class InvestigationState(TypedDict, total=False):
    incident_id: str
    session_uid: str
    started_by: str
    started_at: str
    status: str
    current_step: str
    llm_mode: str
    events: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    intel: list[dict[str, Any]]
    correlations: dict[str, Any]
    log_analysis: dict[str, Any]
    detection_analysis: dict[str, Any]
    detection_analysis_note: str
    investigation_findings: dict[str, Any]
    risk_assessment: dict[str, Any]
    response_recommendations: list[dict[str, Any]]
    report: dict[str, Any]
    messages: list[dict[str, str]]
    errors: list[str]
    requires_approval: bool
    approval_decision: str | None
    approval_analyst: str
    approval_role: str
    approval_reason: str
    finished_at: str
    workflow: list[dict[str, Any]]


AGENT_SEQUENCE = [
    ("log_analysis", "Log Analysis Agent", "Parses and structures raw security events"),
    ("threat_detection", "Threat Detection Agent", "Evaluates rule matches and enriches indicators"),
    ("investigation", "Investigation Agent", "Correlates events and builds an evidence timeline"),
    ("risk_assessment", "Risk Assessment Agent", "Computes an explainable deterministic risk score"),
    ("incident_response", "Incident Response Agent", "Recommends actions and requests human approval"),
    ("report_generation", "Report Generation Agent", "Produces the final incident report"),
]


def initial_state(incident_id: str, session_uid: str, started_by: str, llm_mode: str) -> InvestigationState:
    return InvestigationState(
        incident_id=incident_id,
        session_uid=session_uid,
        started_by=started_by,
        started_at=datetime.utcnow().isoformat() + "Z",
        status="running",
        current_step="log_analysis",
        llm_mode=llm_mode,
        events=[],
        alerts=[],
        intel=[],
        correlations={},
        log_analysis={},
        detection_analysis={},
        investigation_findings={},
        risk_assessment={},
        response_recommendations=[],
        report={},
        messages=[],
        errors=[],
        requires_approval=False,
        approval_decision=None,
        approval_analyst="",
        approval_role="analyst",
        approval_reason="",
        workflow=[],
    )


def add_message(state: dict, agent: str, content: str) -> None:
    state.setdefault("messages", []).append({"agent": agent, "content": content[:2000]})


def add_error(state: dict, agent: str, error: str) -> None:
    state.setdefault("errors", []).append(f"{agent}: {error}"[:1000])


def workflow_entry(step: str, agent: str, status: str, detail: str) -> dict[str, str]:
    return {
        "step": step,
        "agent": agent,
        "status": status,
        "detail": detail[:400],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
