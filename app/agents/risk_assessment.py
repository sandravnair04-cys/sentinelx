"""Agent 4 - Risk Assessment Agent (deterministic scoring, LLM phrasing only)."""

from __future__ import annotations

from typing import Any

from ..risk.scoring import score_risk
from ..utils.helpers import severity_from_score
from .llm import SYSTEM_PROMPT, structured_output
from .state import add_error, workflow_entry

AGENT_KEY = "risk_assessment"
AGENT_NAME = "Risk Assessment Agent"
AGENT_ROLE = "Computes a reproducible 0-100 risk score and explains each contributing factor."


def run(state: dict[str, Any]) -> dict[str, Any]:
    assessment = score_risk(
        alerts=state.get("alerts", []),
        events=state.get("events", []),
        intel=state.get("intel", []),
        context={
            "username": (state.get("investigation_findings", {}).get("affected_users") or [None])[0],
            "success_after_failures": state.get("correlations", {}).get("success_after_failures", False),
        },
    )
    # The LLM may only rephrase the explanation; it cannot change score/severity.
    fallback = {
        "summary": (
            f"Risk score {assessment['score']}/100 ({assessment['severity']}) derived from "
            f"{len(assessment['factors'])} documented factor(s)."
        ),
        "confidence": 1.0,
        "evidence_basis": [f["factor"] for f in assessment["factors"]],
        "caveats": ["Score is deterministic and reproducible from the listed factors."],
        "score": assessment["score"],
        "severity": assessment["severity"],
        "factors": [f"{f['factor']}: +{f['points']} ({f['reason']})" for f in assessment["factors"]],
    }
    output, mode, error = structured_output(
        AGENT_KEY,
        SYSTEM_PROMPT + " Return keys: summary, confidence, evidence_basis, caveats, score, severity, factors. "
        "You must repeat the score and severity provided in the input exactly.",
        {
            "score": assessment["score"],
            "severity": assessment["severity"],
            "factors": assessment["factors"],
        },
        fallback,
    )
    if error:
        add_error(state, AGENT_NAME, error)
    output["score"] = assessment["score"]
    output["severity"] = severity_from_score(assessment["score"])
    output["factors"] = fallback["factors"]
    return {
        "risk_assessment": {**assessment, "narrative": output.get("summary", fallback["summary"])},
        "messages": [{"agent": AGENT_NAME, "content": fallback["summary"]}],
        "workflow": [
            workflow_entry(
                "Risk Assessment", AGENT_NAME, "Completed",
                f"Score {assessment['score']}/100 ({assessment['severity']}); mode={mode}.",
            )
        ],
    }
