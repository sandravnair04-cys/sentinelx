"""Agent 2 - Threat Detection Agent."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ..utils.helpers import severity_rank
from .llm import SYSTEM_PROMPT, structured_output
from .state import add_error, workflow_entry

AGENT_KEY = "threat_detection"
AGENT_NAME = "Threat Detection Agent"
AGENT_ROLE = "Evaluates rule matches, enriches indicators and assigns preliminary severity."


def _fallback(state: dict[str, Any]) -> dict[str, Any]:
    alerts = state.get("alerts", [])
    counts = Counter(a.get("category", "Unknown") for a in alerts)
    severity = max((a.get("severity", "LOW") for a in alerts), key=severity_rank, default="LOW")
    malicious = [i for i in state.get("intel", []) if str(i.get("verdict", "")).lower() == "malicious"]
    rule_matches = [a.get("title", "") for a in alerts[:12]]
    categories = sorted(counts.keys())
    explanation = (
        f"{len(alerts)} deterministic detection alert(s) matched across "
        f"{len(categories)} category/categories. Highest rule severity: {severity}. "
        f"{len(malicious)} indicator(s) verified malicious by threat intelligence. "
        "These are leads requiring analyst corroboration, not confirmed attacks."
    )
    return {
        "summary": explanation,
        "explanation": explanation,
        "confidence": 0.85,
        "evidence_basis": [a.get("alert_uid", "") for a in alerts[:10]],
        "caveats": ["Rule matches are indicators, not proof of compromise."],
        "attack_categories": categories,
        "preliminary_severity": severity,
        "rule_matches": rule_matches,
    }


def run(state: dict[str, Any]) -> dict[str, Any]:
    fallback = _fallback(state)
    output, mode, error = structured_output(
        AGENT_KEY,
        SYSTEM_PROMPT + " Return keys: summary, confidence, evidence_basis, caveats, "
        "attack_categories, preliminary_severity, rule_matches, explanation. "
        "preliminary_severity must be LOW, MEDIUM, HIGH or CRITICAL.",
        {"alerts": state.get("alerts", []), "intel": state.get("intel", [])},
        fallback,
    )
    if error:
        add_error(state, AGENT_NAME, error)
    if mode == "api":
        # Severity must remain grounded in deterministic results.
        output["preliminary_severity"] = fallback["preliminary_severity"]
    return {
        "detection_analysis": output,
        "messages": [{"agent": AGENT_NAME, "content": output.get("explanation", output.get("summary", ""))}],
        "workflow": [
            workflow_entry(
                "Threat Detection", AGENT_NAME, "Completed",
                f"{len(state.get('alerts', []))} rule match(es); severity "
                f"{output.get('preliminary_severity')}; mode={mode}.",
            )
        ],
    }
