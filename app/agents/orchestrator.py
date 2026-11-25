"""LangGraph orchestration of the SENTINELX multi-agent investigation.

Workflow:
    Log Analysis -> Threat Detection -> Investigation -> Risk Assessment
    -> Incident Response -> [human approval checkpoint]
    -> Report Generation

All conclusions are grounded in evidence collected by deterministic code.
The human approval checkpoint pauses the graph; it resumes only through an
authenticated API call that records the analyst decision.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from ._compat import install as _install_langgraph_compat

_install_langgraph_compat()

from langgraph.graph import END, StateGraph  # noqa: E402
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AuditLog, Incident, InvestigationSession, ResponseRecommendation
from ..utils.timeutil import iso
from . import (
    incident_response,
    investigation,
    log_analysis,
    report_generation,
    risk_assessment,
    threat_detection,
)
from .state import InvestigationState, initial_state, workflow_entry
from .tools import create_response_records, gather_context, persist_state, run_recorded_agent

AGENTS = [
    (log_analysis, log_analysis.AGENT_KEY, log_analysis.AGENT_NAME, log_analysis.AGENT_ROLE),
    (threat_detection, threat_detection.AGENT_KEY, threat_detection.AGENT_NAME, threat_detection.AGENT_ROLE),
    (investigation, investigation.AGENT_KEY, investigation.AGENT_NAME, investigation.AGENT_ROLE),
    (risk_assessment, risk_assessment.AGENT_KEY, risk_assessment.AGENT_NAME, risk_assessment.AGENT_ROLE),
    (incident_response, incident_response.AGENT_KEY, incident_response.AGENT_NAME, incident_response.AGENT_ROLE),
]


def _approval_node(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    state["status"] = "waiting_approval"
    persist_state(db, state["session_uid"], state, status="waiting_approval", current_step="approval_checkpoint")
    return {
        "workflow": [
            workflow_entry(
                "Human Approval Checkpoint", "Analyst", "Waiting for Approval",
                "Graph paused before any response action. Resume requires analyst decision.",
            )
        ]
    }


def _resume_node(db: Session, state: dict[str, Any]) -> dict[str, Any]:
    incident = db.scalar(
        select(Incident).where(Incident.incident_id == state["incident_id"])
    )
    decision = state.get("approval_decision", "rejected")
    analyst = state.get("approval_analyst", "unknown")
    reason = state.get("approval_reason", "")
    if incident:
        recommendations = list(
            db.scalars(
                select(ResponseRecommendation).where(
                    ResponseRecommendation.session_uid == state["session_uid"]
                )
            ).all()
        )
        for recommendation in recommendations:
            recommendation.status = "approved" if decision == "approved" else "rejected"
            recommendation.analyst = analyst
            recommendation.analyst_role = state.get("approval_role", "analyst")
            recommendation.decided_at = datetime.utcnow()
            recommendation.decision_reason = reason
            recommendation.execution_result = (
                "SIMULATED ONLY - no real action executed. "
                f"Action {decision} by {analyst}."
            )
            from ..models import ApprovalRecord
            db.add(
                ApprovalRecord(
                    recommendation_id=recommendation.id,
                    action=decision,
                    analyst=analyst,
                    analyst_role=state.get("approval_role", "analyst"),
                    reason=reason,
                )
            )
        incident.status = "Contained" if decision == "approved" else "Investigating"
        if decision == "approved" and not incident.resolved_at and "collect_evidence" not in [
            r.action_type for r in recommendations
        ]:
            incident.resolved_at = None
        db.add(
            AuditLog(
                actor=analyst,
                actor_role=state.get("approval_role", "analyst"),
                action="response_approval" if decision == "approved" else "response_rejection",
                target_type="incident",
                target_id=incident.incident_id,
                details={"reason": reason, "actions": [r.action_type for r in recommendations]},
            )
        )
        db.commit()
    state["status"] = "running"
    return {
        "workflow": [
            workflow_entry(
                "Human Approval Checkpoint", "Analyst",
                "Completed" if decision == "approved" else "Rejected",
                f"Decision {decision} recorded by {analyst}. No real action executed.",
            )
        ]
    }


def _route_after_response(state: dict[str, Any]) -> str:
    if state.get("requires_approval") and not state.get("approval_decision"):
        return "wait_for_approval"
    return "execute_response"


def build_graph(db: Session, resume: bool = False):
    """Compile the investigation graph (or its approval-resume subgraph)."""
    builder = StateGraph(InvestigationState)

    def make_node(agent_module, key: str, name: str, role: str):
        def node(state: dict[str, Any]) -> dict[str, Any]:
            def agent_fn(current: dict[str, Any]) -> dict[str, Any]:
                update = agent_module.run(current)
                if key == "incident_response":
                    # Persist recommendations as pending; nothing is executed.
                    incident = db.scalar(
                        select(Incident).where(Incident.incident_id == current["incident_id"])
                    )
                    if incident:
                        create_response_records(
                            db, incident, current["session_uid"],
                            update.get("response_recommendations", []),
                        )
                return update
            return run_recorded_agent(db, state, key, name, role, agent_fn)
        return node

    def node_name(key: str) -> str:
        # LangGraph reserves state keys; prefix node names to avoid collisions.
        return f"node_{key}"

    for module, key, name, role in AGENTS:
        builder.add_node(node_name(key), make_node(module, key, name, role))

    builder.add_node(
        node_name(report_generation.AGENT_KEY),
        make_node(report_generation, report_generation.AGENT_KEY, report_generation.AGENT_NAME, report_generation.AGENT_ROLE),
    )
    builder.add_node(node_name("wait_for_approval"), lambda state: _approval_node(db, state))
    builder.add_node(node_name("execute_response"), lambda state: _resume_node(db, state))

    if resume:
        builder.set_entry_point(node_name("execute_response"))
    else:
        builder.set_entry_point(node_name("log_analysis"))
        builder.add_edge(node_name("log_analysis"), node_name("threat_detection"))
        builder.add_edge(node_name("threat_detection"), node_name("investigation"))
        builder.add_edge(node_name("investigation"), node_name("risk_assessment"))
        builder.add_edge(node_name("risk_assessment"), node_name("incident_response"))
        builder.add_conditional_edges(
            node_name("incident_response"),
            _route_after_response,
            {
                "wait_for_approval": node_name("wait_for_approval"),
                "execute_response": node_name("execute_response"),
            },
        )
    builder.add_edge(node_name("wait_for_approval"), END)
    builder.add_edge(node_name("execute_response"), node_name("report_generation"))
    builder.add_edge(node_name("report_generation"), END)
    return builder.compile()


def start_investigation(db: Session, incident_id: str, started_by: str = "analyst") -> dict[str, Any]:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise LookupError(f"Incident {incident_id} not found")
    session_uid = uuid.uuid4().hex
    llm_mode = "api" if settings.llm_enabled else "fallback"
    state = initial_state(incident_id, session_uid, started_by, llm_mode)
    context = gather_context(db, incident)
    state.update(context)
    db.add(
        InvestigationSession(
            session_uid=session_uid,
            incident_fk=incident.id,
            status="running",
            llm_mode=llm_mode,
            current_step="log_analysis",
            state=state,
            started_by=started_by,
            started_at=datetime.utcnow(),
        )
    )
    incident.status = "Investigating"
    db.add(
        AuditLog(
            actor=started_by, actor_role="analyst", action="investigation_started",
            target_type="incident", target_id=incident_id,
            details={"session_uid": session_uid, "llm_mode": llm_mode},
        )
    )
    db.commit()

    graph = build_graph(db)
    final_state = graph.invoke(dict(state), config={"recursion_limit": 20})
    status = final_state.get("status", "waiting_approval")
    finished = status not in {"running", "waiting_approval"}
    persist_state(
        db, session_uid, final_state,
        status=status,
        current_step=final_state.get("current_step", "approval_checkpoint"),
        finished=finished,
    )
    return {"session_uid": session_uid, "status": status, "state": final_state}


def resume_investigation(
    db: Session,
    session_uid: str,
    decision: str,
    analyst: str,
    role: str = "analyst",
    reason: str = "",
) -> dict[str, Any]:
    if decision not in {"approved", "rejected"}:
        raise ValueError("Decision must be 'approved' or 'rejected'")
    session = db.scalar(
        select(InvestigationSession).where(InvestigationSession.session_uid == session_uid)
    )
    if session is None:
        raise LookupError("Investigation session not found")
    if session.status not in {"waiting_approval", "completed"}:
        raise ValueError("Investigation is not waiting for approval")
    state = dict(session.state or {})
    state.update(
        {
            "approval_decision": decision,
            "approval_analyst": analyst,
            "approval_role": role,
            "approval_reason": reason,
        }
    )
    persist_state(db, session_uid, state, status="running", current_step="execute_response")
    graph = build_graph(db, resume=True)
    final_state = graph.invoke(state, config={"recursion_limit": 10})
    final_state["finished_at"] = iso(datetime.utcnow())
    persist_state(
        db, session_uid, final_state, status="completed",
        current_step="report_generation", finished=True,
    )
    return {"session_uid": session_uid, "status": "completed", "state": final_state}
