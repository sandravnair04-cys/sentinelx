"""AI agent workflow tests (deterministic fallback mode)."""

from sqlalchemy import select

from app.agents import investigation as investigation_agent
from app.agents import log_analysis, report_generation, risk_assessment
from app.agents import threat_detection, incident_response
from app.agents.llm import structured_output
from app.agents.orchestrator import resume_investigation, start_investigation
from app.agents.schemas import LogAnalysisOutput, ResponseOutput
from app.models import AgentExecution, ApprovalRecord, Incident, InvestigationSession, ResponseRecommendation


def test_llm_fallback_returns_validated_output():
    output, mode, error = structured_output(
        "log_analysis", "system", {"events": []},
        {"summary": "fallback", "event_count": 0, "patterns": []},
    )
    assert mode == "fallback"
    assert LogAnalysisOutput.model_validate(output).event_count == 0


def test_agent_outputs_are_validated():
    state = {
        "incident_id": "INC-TEST", "session_uid": "x", "llm_mode": "fallback",
        "events": [{"event_uid": "e1", "action": "failure", "timestamp": "2026-11-19T08:00:00Z"}],
        "alerts": [{"severity": "HIGH", "confidence": 0.8, "title": "Brute force", "mitre": ["T1110"]}],
        "intel": [], "errors": [], "messages": [], "workflow": [],
        "investigation_findings": {}, "risk_assessment": {}, "correlations": {},
    }
    log_update = log_analysis.run(state)
    assert log_update["log_analysis"]["event_count"] == 1
    detect_update = threat_detection.run(state)
    assert detect_update["detection_analysis"]["preliminary_severity"] == "HIGH"
    inv_update = investigation_agent.run(state)
    assert "affected_users" in inv_update["investigation_findings"]
    risk_update = risk_assessment.run(state)
    assert 0 <= risk_update["risk_assessment"]["score"] <= 100
    response_update = incident_response.run(state)
    validated = ResponseOutput.model_validate({
        "actions": response_update["response_recommendations"],
        "summary": "x", "confidence": 0.9,
        "evidence_basis": [], "caveats": [], "approval_required": True,
    })
    assert all(a.action_type in {"block_ip", "disable_account", "isolate_endpoint",
                                  "collect_evidence", "investigate_process"}
               for a in validated.actions)
    report_update = report_generation.run(state)
    assert report_update["report"]["report_title"].startswith("SENTINELX")


def test_full_langgraph_investigation_with_approval(seeded_db):
    incident = list(seeded_db.scalars(select(Incident)).all())[0]
    result = start_investigation(seeded_db, incident.incident_id, "analyst")
    assert result["status"] == "waiting_approval"
    session = seeded_db.scalar(
        select(InvestigationSession).where(InvestigationSession.session_uid == result["session_uid"])
    )
    assert session.status == "waiting_approval"
    executions = list(
        seeded_db.scalars(
            select(AgentExecution).where(AgentExecution.session_uid == result["session_uid"])
        ).all()
    )
    assert len(executions) >= 5
    assert all(e.success for e in executions)
    assert all(e.duration_ms >= 0 for e in executions)
    recs = list(
        seeded_db.scalars(
            select(ResponseRecommendation).where(ResponseRecommendation.session_uid == result["session_uid"])
        ).all()
    )
    assert recs and all(r.status == "pending" for r in recs)

    resumed = resume_investigation(
        seeded_db, result["session_uid"], "approved", "admin", "admin", "lab test approval"
    )
    assert resumed["status"] == "completed"
    assert resumed["state"]["report"]["report_title"].startswith("SENTINELX")
    approvals = list(seeded_db.scalars(select(ApprovalRecord)).all())
    assert approvals and all(a.action == "approved" for a in approvals)
