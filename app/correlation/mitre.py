"""Mapping of observed behaviours to MITRE ATT&CK techniques.

Mappings are advisory: they describe the technique a pattern resembles, not a
confirmed adversary attribution.
"""

from __future__ import annotations

MITRE_CATALOGUE = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1136": "Create Account",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
    "T1571": "Non-Standard Port",
    "T1021": "Remote Services",
}

SIGNAL_TECHNIQUES = {
    "failed_logins": ["T1110.001"],
    "password_spraying": ["T1110.003"],
    "success_after_failures": ["T1078"],
    "privileged_activity": ["T1098"],
    "account_manipulation": ["T1136"],
    "suspicious_process": ["T1059"],
    "network_anomaly": ["T1071", "T1571"],
}


def techniques_for_signals(signals: dict[str, bool]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for signal, active in signals.items():
        if not active:
            continue
        for technique in SIGNAL_TECHNIQUES.get(signal, []):
            if technique in seen:
                continue
            seen.add(technique)
            result.append({"id": technique, "name": MITRE_CATALOGUE.get(technique, technique)})
    return result
