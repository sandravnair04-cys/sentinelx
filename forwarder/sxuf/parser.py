"""Untrusted log line → structured fields.

Purely local, deterministic pattern extraction. Forwarder code never treats log
content as instructions, and never executes anything found in a log line.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IPV6 = r"[0-9a-fA-F:]{4,}"
_IP_PATTERN = re.compile(rf"\b({_IPV4}|{_IPV6})\b")
_USER_PATTERNS = (
    re.compile(r"invalid user\s+([A-Za-z0-9._\\@-]{1,64})", re.I),
    re.compile(r"(?:for|user|account(?: name)?)\s+(?!invalid\b)([A-Za-z0-9._\\@-]{1,64})", re.I),
    re.compile(r"USER=(\S+)", re.I),
)
_EVENT_ID = re.compile(r"(?:EventID|Event ID|event_id|id)[=:\s]+(\d{3,6})", re.I)
_SYSLOG_TIME = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")

_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("failed_login", ("failed password", "failed login", "authentication failure",
                       "invalid user", "failed logon", "bad pwd", "login failed",
                       "eventid=4625", "event id 4625", "eventid=4771")),
    ("successful_login", ("accepted password", "session opened", "successful logon",
                           "eventid=4624", "event id 4624", "logged in")),
    ("privilege_escalation", ("sudo:", "privilege escalation", "elevated privilege",
                               "eventid=4672", "event id 4672", "special privileges assigned",
                               "eventid=4720", "eventid=4732")),
    ("process_creation", ("process created", "eventid=4688", "event id 4688",
                           "new process", "powershell", "cmd.exe", "execve")),
    ("network_connection", ("connection", "firewall", "outbound", "new socket",
                             "eventid=5156", "port scan")),
    ("account_change", ("user added", "account created", "password changed",
                         "eventid=4722", "eventid=4724")),
    ("audit_clear", ("log cleared", "eventid=1102", "audit log cleared")),
)

_SEVERITY = {
    "failed_login": "high",
    "privilege_escalation": "high",
    "account_change": "high",
    "audit_clear": "critical",
    "process_creation": "medium",
    "network_connection": "medium",
    "successful_login": "low",
    "other": "info",
}


def classify(text: str) -> str:
    lowered = text.lower()
    for event_type, needles in _RULES:
        if any(needle in lowered for needle in needles):
            return event_type
    return "other"


def severity_for(event_type: str) -> str:
    return _SEVERITY.get(event_type, "info")


def extract_ip(text: str) -> str | None:
    for match in _IP_PATTERN.finditer(text):
        candidate = match.group(1)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate.startswith(("0.", "255.", "127.")):
            continue
        return candidate
    return None


def extract_user(text: str) -> str | None:
    for pattern in _USER_PATTERNS:
        match = pattern.search(text)
        if match:
            value = match.group(1).strip("'\"")
            if value and value.lower() not in ("unknown", "invalid", "none"):
                return value[:255]
    return None


def extract_event_id(text: str) -> str:
    match = _EVENT_ID.search(text)
    return match.group(1) if match else ""


def parse_timestamp(text: str, fallback: datetime | None = None) -> str:
    """Best-effort timestamp extraction; always returns UTC ISO-8601."""
    now = fallback or datetime.now(timezone.utc)
    match = _ISO_TIME.search(text)
    if match:
        candidate = match.group(0).replace(" ", "T")
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    match = _SYSLOG_TIME.match(text)
    if match:
        try:
            parsed = parsedate_to_datetime(match.group(1) + f" {now.year}")
            if parsed:
                return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, TypeError):
            pass
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalised_fields(text: str, *, source: str, source_name: str) -> dict[str, Any]:
    event_type = classify(text)
    return {
        "event_code": extract_event_id(text),
        "event_type": event_type,
        "severity": severity_for(event_type),
        "message": text[:1000],
        "source": source,
        "source_name": source_name,
    }
