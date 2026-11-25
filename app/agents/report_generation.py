"""Agent 6 - Report Generation Agent."""

from __future__ import annotations

from typing import Any

from .llm import SYSTEM_PROMPT, structured_output
from .state import add_error, workflow_entry

AGENT_KEY = "report_generation"
AGENT_NAME = "Report Generation Agent"
AGENT_ROLE = "Produces an evidence-based incident summary and downloadable PDF report."


def _fallback(state: dict[str, Any]) -> dict[str, Any]:
    risk = state.get("risk_assessment", {})
    investigation = state.get("investigation_findings", {})
    detection = state.get("detection_analysis", {})
    summary = (
        f"Incident {state.get('incident_id', 'unknown')}: "
        f"{investigation.get('correlation_explanation', 'No correlation summary available.')} "
        f"Deterministic risk score: {risk.get('score', 0)}/100 ({risk.get('severity', 'LOW')}). "
        f"Detection assessment: {detection.get('explanation', detection.get('summary', 'n/a'))}"
    )
    return {
        "summary": summary,
        "executive_summary": summary,
        "confidence": 0.85,
        "evidence_basis": investigation.get("evidence_basis", []),
        "caveats": [
            "AI-generated narrative is decision support only and does not replace analyst judgement."
        ],
        "remediation": risk.get("recommendations", []),
        "report_title": f"SENTINELX Incident Report {state.get('incident_id', '')}",
    }


def run(state: dict[str, Any]) -> dict[str, Any]:
    fallback = _fallback(state)
    output, mode, error = structured_output(
        AGENT_KEY,
        SYSTEM_PROMPT + " Return keys: summary, executive_summary, confidence, evidence_basis, "
        "caveats, remediation, report_title. Reference only the provided evidence.",
        {
            "alerts": state.get("alerts", []),
            "investigation": state.get("investigation_findings", {}),
            "risk": state.get("risk_assessment", {}),
            "events": state.get("events", [])[:10],
        },
        fallback,
    )
    if error:
        add_error(state, AGENT_NAME, error)
    output["remediation"] = fallback["remediation"] or output.get("remediation", [])
    return {
        "report": output,
        "messages": [{"agent": AGENT_NAME, "content": output.get("executive_summary", output["summary"])}],
        "workflow": [
            workflow_entry(
                "Report Generation", AGENT_NAME, "Completed",
                f"Report narrative generated; mode={mode}.",
            )
        ],
    }
