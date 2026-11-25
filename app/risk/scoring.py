"""Transparent, deterministic 0-100 risk scoring.

The score is a reproducible weighted sum of observable factors. An LLM never
sets or overrides this score. Every point is explained in ``factors``.
"""

from __future__ import annotations

from typing import Any

from ..utils.helpers import clamp, severity_from_score, severity_rank

MODEL_VERSION = "deterministic-v1"

_SEVERITY_BASE = {"LOW": 8.0, "MEDIUM": 25.0, "HIGH": 48.0, "CRITICAL": 68.0}
_PRIVILEGED = {"administrator", "admin", "root", "svc_admin", "systems manager"}


def _max_severity(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "LOW"
    return max((a.get("severity", "LOW") for a in alerts), key=severity_rank)


def score_risk(
    alerts: list[dict[str, Any]] | None = None,
    events: list[dict[str, Any]] | None = None,
    intel: list[dict[str, Any]] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute an explainable risk assessment from observed evidence."""
    alerts = alerts or []
    events = events or []
    intel = intel or []
    context = context or {}
    factors: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    score = 0.0

    def add(name: str, points: float, reason: str, source: str = "detection") -> None:
        nonlocal score
        if points <= 0:
            return
        score += points
        factors.append(
            {
                "factor": name,
                "points": round(points, 2),
                "reason": reason,
                "source": source,
            }
        )

    highest = _max_severity(alerts)
    base = _SEVERITY_BASE.get(highest, 8.0)
    add(
        "Highest detection severity",
        base,
        f"Strongest matching detection rule severity is {highest}.",
    )

    count = len(events)
    event_points = min(18.0, count * 1.5)
    add("Volume of suspicious events", event_points, f"{count} events contribute to this incident.")

    usernames = {str(e.get("username")) for e in events if e.get("username")}
    hosts = {str(e.get("host")) for e in events if e.get("host")}
    ips = {str(e.get("source_ip")) for e in events if e.get("source_ip")}

    if any(u.lower() in _PRIVILEGED for u in usernames) or str(context.get("username", "")).lower() in _PRIVILEGED:
        add("Privileged account involved", 12.0, "An administrative account appears in the evidence.")

    rule_names = {str(a.get("rule_name", "")) for a in alerts}
    if any("Success After Repeated Failures" in n or "login_after_failures" in n for n in rule_names):
        add("Successful login after failures", 15.0, "A login succeeded after repeated failures.")
    elif context.get("success_after_failures"):
        add("Successful login after failures", 15.0, "A login succeeded after repeated failures.", "correlation")

    if len(usernames) >= 3:
        add("Multiple accounts targeted", 5.0, f"{len(usernames)} accounts were targeted.")

    malicious = [i for i in intel if str(i.get("verdict", "")).lower() == "malicious"]
    if malicious:
        add(
            "Threat intelligence match",
            min(20.0, len(malicious) * 12.0),
            f"{len(malicious)} indicator(s) verified as malicious.",
            "threat_intel",
        )
        for item in malicious[:5]:
            evidence.append({"type": "malicious_indicator", "value": item.get("indicator")})

    if len(hosts) > 1:
        add(
            "Multiple affected systems",
            min(18.0, (len(hosts) - 1) * 6.0),
            f"{len(hosts)} distinct hosts are involved.",
            "correlation",
        )

    confidences = [float(a.get("confidence", 0)) for a in alerts if a.get("confidence") is not None]
    if confidences:
        avg = sum(confidences) / len(confidences)
        add(
            "Evidence confidence",
            avg * 8.0,
            f"Average rule confidence is {avg:.2f}.",
        )

    mitre = set()
    for alert in alerts:
        mitre.update(str(t) for t in (alert.get("mitre") or []))
    if len(mitre) >= 3:
        add("Multiple ATT&CK techniques", 4.0, f"{len(mitre)} techniques observed.")

    final = clamp(score)
    severity = severity_from_score(final)

    recommendations: list[str] = []
    if final >= 80:
        recommendations = [
            "Escalate to the incident commander immediately.",
            "Isolate the affected endpoint after analyst approval.",
            "Disable or reset credentials for the affected account.",
            "Preserve all related logs and evidence before remediation.",
        ]
    elif final >= 60:
        recommendations = [
            "Prioritise investigation within the current shift.",
            "Verify the activity with the account owner.",
            "Block the suspicious source IP pending review.",
        ]
    elif final >= 30:
        recommendations = [
            "Review the correlated events and confirm business context.",
            "Increase monitoring for the affected account and host.",
        ]
    else:
        recommendations = ["Monitor and re-evaluate if additional events appear."]

    evidence.extend(
        [
            {"type": "source_ips", "value": sorted(ips)},
            {"type": "usernames", "value": sorted(usernames)},
            {"type": "hosts", "value": sorted(hosts)},
            {"type": "alerts", "value": [a.get("title") for a in alerts]},
        ]
    )

    return {
        "score": final,
        "severity": severity,
        "factors": factors,
        "evidence": evidence,
        "recommendations": recommendations,
        "model_version": MODEL_VERSION,
        "highest_detection_severity": highest,
    }
