"""Agent 1 - Log Analysis Agent."""

from __future__ import annotations

from typing import Any

from .llm import SYSTEM_PROMPT, structured_output
from .state import add_error, workflow_entry

AGENT_KEY = "log_analysis"
AGENT_NAME = "Log Analysis Agent"
AGENT_ROLE = "Normalises collected logs and extracts security-relevant fields and patterns."


def _fallback(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    users: set[str] = set()
    ips: set[str] = set()
    hosts: set[str] = set()
    for event in events:
        counts[event.get("action", "unknown")] = counts.get(event.get("action", "unknown"), 0) + 1
        if event.get("username"):
            users.add(str(event["username"]))
        if event.get("source_ip"):
            ips.add(str(event["source_ip"]))
        if event.get("host"):
            hosts.add(str(event["host"]))
    patterns = [f"{count} {action} event(s)" for action, count in sorted(counts.items())]
    return {
        "summary": (
            f"Analysed {len(events)} collected events. Observed " + ", ".join(patterns)
            + f"; {len(users)} account(s), {len(ips)} source IP(s) and {len(hosts)} host(s)."
        ),
        "confidence": 0.9,
        "evidence_basis": [e.get("event_uid", "") for e in events[:10]],
        "caveats": ["Findings are based on collected log evidence; no external verification performed."],
        "key_fields": {
            "action_counts": counts,
            "usernames": sorted(users),
            "source_ips": sorted(ips),
            "hosts": sorted(hosts),
        },
        "patterns": patterns,
        "event_count": len(events),
    }


def run(state: dict[str, Any]) -> dict[str, Any]:
    events = state.get("events", [])
    fallback = _fallback(events)
    output, mode, error = structured_output(
        AGENT_KEY,
        SYSTEM_PROMPT + " Return keys: summary, confidence, evidence_basis, caveats, key_fields, patterns, event_count.",
        {"events": events[:40]},
        fallback,
    )
    if error:
        add_error(state, AGENT_NAME, error)
    return {
        "log_analysis": output,
        "llm_mode": mode if mode == "api" else state.get("llm_mode", "fallback"),
        "messages": [
            {
                "agent": AGENT_NAME,
                "content": output.get("summary", ""),
            }
        ],
        "workflow": [
            workflow_entry(
                "Log Analysis", AGENT_NAME, "Completed",
                f"Structured {len(events)} event(s); mode={mode}.",
            )
        ],
    }
