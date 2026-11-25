"""Agent 3 - Investigation Agent."""

from __future__ import annotations

from typing import Any

from .llm import SYSTEM_PROMPT, structured_output
from .state import add_error, workflow_entry
from ..correlation.mitre import MITRE_CATALOGUE

AGENT_KEY = "investigation"
AGENT_NAME = "Investigation Agent"
AGENT_ROLE = "Correlates activity, identifies affected assets and builds an evidence timeline."


def _fallback(state: dict[str, Any]) -> dict[str, Any]:
    events = sorted(state.get("events", []), key=lambda e: e.get("timestamp", ""))
    users = sorted({str(e["username"]) for e in events if e.get("username")})
    hosts = sorted({str(e["host"]) for e in events if e.get("host")})
    ips = sorted({str(e["source_ip"]) for e in events if e.get("source_ip")})
    techniques = sorted(
        {
            str(t)
            for a in state.get("alerts", [])
            for t in (a.get("mitre") or [])
        }
    )
    failures = [e for e in events if e.get("action") == "failure"]
    successes = [e for e in events if e.get("action") == "success"]
    if failures and successes and failures[-1]["timestamp"] <= successes[-1]["timestamp"]:
        correlation = (
            f"{len(failures)} failed authentication event(s) from {len(ips)} source(s) "
            f"precede {len(successes)} successful login(s). This is consistent with a "
            "password-guessing sequence, but must be confirmed with the account owner."
        )
    elif events:
        correlation = (
            f"{len(events)} events are linked by source IP, account and host across "
            f"{events[0].get('timestamp','?')} to {events[-1].get('timestamp','?')}."
        )
    else:
        correlation = "No directly linked events were available for correlation."
    return {
        "summary": correlation,
        "confidence": 0.8 if events else 0.2,
        "evidence_basis": [e.get("event_uid", "") for e in events[:15]],
        "caveats": ["Time correlation does not prove causation or attacker intent."],
        "affected_users": users,
        "affected_systems": hosts,
        "correlation_explanation": correlation,
        "timeline_summary": (
            f"Timeline covers {len(events)} event(s) from {events[0].get('timestamp','n/a')} "
            f"to {events[-1].get('timestamp','n/a')}." if events else "No timeline available."
        ),
        "mitre_techniques": techniques,
    }


def run(state: dict[str, Any]) -> dict[str, Any]:
    fallback = _fallback(state)
    output, mode, error = structured_output(
        AGENT_KEY,
        SYSTEM_PROMPT + " Return keys: summary, confidence, evidence_basis, caveats, "
        "affected_users, affected_systems, correlation_explanation, timeline_summary, "
        "mitre_techniques. Use only provided evidence.",
        {"events": state.get("events", [])[:40], "alerts": state.get("alerts", [])[:20]},
        fallback,
    )
    if error:
        add_error(state, AGENT_NAME, error)
    for key in ("affected_users", "affected_systems", "mitre_techniques"):
        if not output.get(key):
            output[key] = fallback[key]
    return {
        "investigation_findings": output,
        "messages": [{"agent": AGENT_NAME, "content": output.get("correlation_explanation", output.get("summary", ""))}],
        "workflow": [
            workflow_entry(
                "Investigation", AGENT_NAME, "Completed",
                f"Correlated {len(state.get('events', []))} event(s); "
                f"{len(output.get('affected_users', []))} user(s), "
                f"{len(output.get('affected_systems', []))} host(s); mode={mode}.",
            )
        ],
    }
