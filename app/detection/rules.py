"""Built-in detection rule catalogue with operator-configurable thresholds."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import settings


@dataclass(frozen=True)
class BuiltinRule:
    key: str
    name: str
    category: str
    severity: str
    description: str
    thresholds: dict = field(default_factory=dict)
    mitre: list[str] = field(default_factory=list)


BUILTIN_RULES: list[BuiltinRule] = [
    BuiltinRule(
        key="brute_force_source",
        name="Brute Force - Repeated Failed Logins from Source",
        category="Brute Force",
        severity="HIGH",
        description="Multiple failed authentication attempts from one source IP within a configurable window.",
        thresholds={
            "window_seconds": settings.brute_force_window_seconds,
            "threshold": settings.brute_force_threshold,
        },
        mitre=["T1110.001 - Password Guessing", "T1110.003 - Password Spraying"],
    ),
    BuiltinRule(
        key="brute_force_account",
        name="Brute Force - Repeated Failed Logins Against Account",
        category="Brute Force",
        severity="HIGH",
        description="Multiple failed authentication attempts against a single account across sources.",
        thresholds={"window_seconds": settings.brute_force_window_seconds, "threshold": 8},
        mitre=["T1110 - Brute Force"],
    ),
    BuiltinRule(
        key="password_spraying",
        name="Password Spraying - Multiple Accounts from One Source",
        category="Brute Force",
        severity="HIGH",
        description="One source targeted several different accounts in a short period.",
        thresholds={"window_seconds": settings.brute_force_window_seconds, "min_accounts": 3},
        mitre=["T1110.003 - Password Spraying"],
    ),
    BuiltinRule(
        key="login_after_failures",
        name="Suspicious Login - Success After Repeated Failures",
        category="Suspicious Login",
        severity="CRITICAL",
        description="A successful login followed a burst of failures from the same source/account.",
        thresholds={
            "window_seconds": settings.failed_success_window_seconds,
            "min_failures": 3,
        },
        mitre=["T1110 - Brute Force", "T1078 - Valid Accounts"],
    ),
    BuiltinRule(
        key="privileged_unusual_source",
        name="Suspicious Login - Privileged Account from New External Source",
        category="Suspicious Login",
        severity="MEDIUM",
        description="A privileged account authenticated from an external IP with no previous successful login.",
        thresholds={"lookback_days": 7},
        mitre=["T1078 - Valid Accounts"],
    ),
    BuiltinRule(
        key="network_malicious_destination",
        name="Network Anomaly - Connection to Known Malicious Destination",
        category="Network Anomaly",
        severity="CRITICAL",
        description="Outbound connection to an indicator previously verified as malicious by threat intelligence.",
        thresholds={},
        mitre=["T1071 - Application Layer Protocol"],
    ),
    BuiltinRule(
        key="network_outbound_volume",
        name="Network Anomaly - Unusual Outbound Connection Volume",
        category="Network Anomaly",
        severity="MEDIUM",
        description="A host produced an unusual burst of outbound connections.",
        thresholds={"window_seconds": 600, "threshold": 20},
        mitre=["T1071 - Application Layer Protocol"],
    ),
    BuiltinRule(
        key="network_suspicious_port",
        name="Network Anomaly - Connection to Suspicious Port",
        category="Network Anomaly",
        severity="HIGH",
        description="Outbound connection to a port commonly used for reverse shells or tunnels.",
        thresholds={"ports": [4444, 5555, 6666, 6667, 8888, 9999]},
        mitre=["T1571 - Non-Standard Port"],
    ),
    BuiltinRule(
        key="suspicious_process",
        name="Suspicious Process Execution",
        category="Suspicious Process",
        severity="HIGH",
        description="Command execution matching known suspicious patterns (encoded shell, credential access, download-and-execute).",
        thresholds={
            "patterns": [
                "powershell", "-enc", "-encodedcommand", "mimikatz", "whoami",
                "net user", "/etc/shadow", "curl", "wget", "nc -e", "chmod +s",
                "certutil", "rundll32", "invoke-expression",
            ]
        },
        mitre=["T1059 - Command and Scripting Interpreter"],
    ),
    BuiltinRule(
        key="privilege_assignment",
        name="Privilege Escalation - Administrative Privileges Assigned",
        category="Privilege Escalation",
        severity="MEDIUM",
        description="Special privileges assigned to a non-system account from an external source.",
        thresholds={},
        mitre=["T1098 - Account Manipulation"],
    ),
    BuiltinRule(
        key="account_manipulation",
        name="Privilege Escalation - Privileged Account or Group Created",
        category="Privilege Escalation",
        severity="CRITICAL",
        description="A new account was created or added to a privileged group.",
        thresholds={"privileged_groups": ["sudo", "root", "adm", "administrators", "wheel"]},
        mitre=["T1136 - Create Account", "T1098 - Account Manipulation"],
    ),
]

BUILTIN_BY_KEY = {r.key: r for r in BUILTIN_RULES}
