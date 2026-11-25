"""Agent 5 - Incident Response Agent (recommendations only; no execution)."""

from __future__ import annotations

from typing import Any

from ..utils.helpers import is_private_ip
from .llm import SYSTEM_PROMPT, structured_output
from .state import add_error, workflow_entry

AGENT_KEY = "incident_response"
AGENT_NAME = "Incident Response Agent"
AGENT_ROLE = "Recommends proportionate containment/remediation actions for human approval."

ALLOWED_ACTIONS = {
    "block_ip", "disable_account", "isolate_endpoint", "collect_evidence", "investigate_process"
}


def _deterministic_actions(state: dict[str, Any]) -> list[dict[str, Any]]:
    events = state.get("events", [])
    alerts = state.get("alerts", [])
    risk = state.get("risk_assessment", {})
    users = sorted({str(e["username"]) for e in events if e.get("username")})
    hosts = sorted({str(e["host"]) for e in events if e.get("host")})
    ips = sorted({str(e["source_ip"]) for e in events if e.get("source_ip")})
    privileged = [u for u in users if u.lower() in {"admin", "administrator", "root", "svc_admin"}]
    process_events = [e for e in events if e.get("action") == "process"]
    actions: list[dict[str, Any]] = []

    external = [ip for ip in ips if not is_private_ip(ip)]
    if external:
        actions.append(
            {
                "action_type": "block_ip",
                "target": external[0],
                "title": f"Block suspicious source IP {external[0]}",
                "description": "Add the source IP to the temporary block list pending review.",
                "purpose": "Stop further authentication attempts from this source while the incident is assessed.",
                "risk_if_ignored": "Repeated attempts may continue and could eventually succeed.",
                "priority": "high",
            }
        )
    if privileged or risk.get("severity") in {"HIGH", "CRITICAL"}:
        target = privileged[0] if privileged else (users[0] if users else "affected account")
        actions.append(
            {
                "action_type": "disable_account",
                "target": target,
                "title": f"Disable or reset credentials for {target}",
                "description": "Temporarily disable the account or force a credential reset after verification.",
                "purpose": "Prevent further use of credentials that may be compromised.",
                "risk_if_ignored": "An attacker retaining valid credentials may maintain access.",
                "priority": "high",
            }
        )
    if risk.get("severity") == "CRITICAL" and hosts:
        actions.append(
            {
                "action_type": "isolate_endpoint",
                "target": hosts[0],
                "title": f"Isolate endpoint {hosts[0]}",
                "description": "Network-isolate the endpoint using the approved playbook (simulated).",
                "purpose": "Contain possible lateral movement while preserving volatile evidence.",
                "risk_if_ignored": "A compromised host could be used to move laterally.",
                "priority": "critical",
            }
        )
    if process_events:
        actions.append(
            {
                "action_type": "investigate_process",
                "target": str(process_events[0].get("message", ""))[:120],
                "title": "Investigate suspicious process execution",
                "description": "Collect process metadata and verify the command with the system owner.",
                "purpose": "Determine whether the command is legitimate administrative activity.",
                "risk_if_ignored": "Malicious execution may persist undetected.",
                "priority": "medium",
            }
        )
    actions.append(
        {
            "action_type": "collect_evidence",
            "target": state.get("incident_id", "incident"),
            "title": "Preserve and collect additional evidence",
            "description": "Export related logs and retain hashes before remediation changes state.",
            "purpose": "Maintain an evidentiary record for investigation and reporting.",
            "risk_if_ignored": "Volatile evidence may be lost, weakening the investigation.",
            "priority": "medium",
        }
    )
    # Guard: never allow an action outside the whitelist, even from an LLM.
    return [a for a in actions if a["action_type"] in ALLOWED_ACTIONS]


def run(state: dict[str, Any]) -> dict[str, Any]:
    actions = _deterministic_actions(state)
    fallback = {
        "summary": (
            f"{len(actions)} response action(s) recommended. All require explicit analyst "
            "approval; no action has been executed."
        ),
        "confidence": 0.9,
        "evidence_basis": [a.get("target", "") for a in actions],
        "caveats": ["Recommendations are advisory and are never executed automatically."],
        "actions": actions,
        "approval_required": True,
    }
    output, mode, error = structured_output(
        AGENT_KEY,
        SYSTEM_PROMPT + " Return keys: summary, confidence, evidence_basis, caveats, actions, "
        "approval_required. actions must use only these action_type values: "
        "block_ip, disable_account, isolate_endpoint, collect_evidence, investigate_process.",
        {"risk": state.get("risk_assessment", {}), "events": state.get("events", [])[:20]},
        fallback,
    )
    if error:
        add_error(state, AGENT_NAME, error)
    # Deterministic actions are authoritative and sanitised.
    output["actions"] = actions
    output["approval_required"] = True
    return {
        "response_recommendations": actions,
        "detection_analysis_note": output.get("summary", ""),
        "requires_approval": True,
        "status": "waiting_approval",
        "current_step": "approval_checkpoint",
        "messages": [{"agent": AGENT_NAME, "content": output.get("summary", fallback["summary"])}],
        "workflow": [
            workflow_entry(
                "Incident Response", AGENT_NAME, "Waiting for Approval",
                f"{len(actions)} action(s) queued for human approval; mode={mode}.",
            )
        ],
    }
