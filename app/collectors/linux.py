"""Linux authentication log collection/parsing.

Supports classic ``/var/log/auth.log`` (syslog) lines, ``journalctl`` output
(both short and ``-o json`` modes) and the bundled lab sample files.

The parser never reads real log files unless a path is explicitly supplied by
an authenticated operator; the API only accepts text or the bundled samples.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Iterable

from ..utils.timeutil import parse_timestamp, to_utc_naive
from .normalizer import NormalizedEvent
from .windows import iter_unique

_SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<process>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive) for "
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive) for (?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
_SUDO = re.compile(
    r"(?:sudo:\s*)?(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)
_SU = re.compile(r"\bsu:\s*(?:Successful authentication for|authentication failure;)\s*(?P<user>\S+)")
_NEW_USER = re.compile(r"new user:\s*name=(?P<user>\S+)", re.IGNORECASE)
_GROUP_ADD = re.compile(r"(?P<user>\S+)\s*:\s*added to group\s*(?P<group>\S+)", re.IGNORECASE)
_SESSION_OPEN = re.compile(r"session opened for user (?P<user>\S+)", re.IGNORECASE)
_GENERIC_IP = re.compile(r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


def _event(
    *,
    text: str,
    ts: datetime | str,
    code: str,
    action: str,
    host: str | None,
    user: str | None = None,
    ip: str | None = None,
    message: str = "",
    source_name: str = "linux-auth",
    extra: dict | None = None,
    confidence: float = 0.85,
) -> NormalizedEvent:
    return NormalizedEvent(
        source_type="linux",
        source_name=source_name,
        event_code=code,
        timestamp=to_utc_naive(ts),
        action=action,
        username=user,
        source_ip=ip,
        host=host,
        message=message or text[:300],
        raw_event=text[:4000],
        confidence=confidence,
        extra=extra or {},
    )


def _parse_message(msg: str, ts: datetime | str, host: str | None, raw: str, source_name: str) -> NormalizedEvent | None:
    m = _FAILED.search(msg)
    if m:
        return _event(
            text=raw, ts=ts, code="AUTH_FAILED", action="failure", host=host,
            user=m.group("user"), ip=m.group("ip"), message=msg,
            source_name=source_name, extra={"mechanism": "password/publickey"},
        )
    m = _ACCEPTED.search(msg)
    if m:
        return _event(
            text=raw, ts=ts, code="AUTH_SUCCESS", action="success", host=host,
            user=m.group("user"), ip=m.group("ip"), message=msg,
            source_name=source_name,
        )
    m = _SUDO.search(msg)
    if m:
        command = m.group("cmd").strip()
        return _event(
            text=raw, ts=ts, code="SUDO", action="process", host=host,
            user=m.group("user"), message=f"sudo USER={m.group('target')} COMMAND={command}",
            source_name=source_name,
            extra={"target_user": m.group("target"), "command": command},
            confidence=0.9,
        )
    m = _NEW_USER.search(msg)
    if m:
        return _event(
            text=raw, ts=ts, code="USER_CREATED", action="privilege", host=host,
            user=m.group("user"), message=msg, source_name=source_name, confidence=0.9,
        )
    m = _GROUP_ADD.search(msg)
    if m:
        return _event(
            text=raw, ts=ts, code="GROUP_ADD", action="privilege", host=host,
            user=m.group("user"), message=msg, source_name=source_name,
            extra={"group": m.group("group")}, confidence=0.9,
        )
    if _SU.search(msg) or "session opened for user root" in msg:
        m = _SU.search(msg) or _SESSION_OPEN.search(msg)
        return _event(
            text=raw, ts=ts, code="PRIVILEGE_SESSION", action="privilege", host=host,
            user=m.group("user") if m else None, message=msg,
            source_name=source_name, confidence=0.8,
        )
    # Keep unknown auth lines as low-confidence generic events for completeness.
    ip_match = _GENERIC_IP.search(msg)
    return _event(
        text=raw, ts=ts, code="AUTH_OTHER", action="unknown", host=host,
        ip=ip_match.group("ip") if ip_match else None, message=msg,
        source_name=source_name, confidence=0.3,
    )


def parse_linux_auth(text: str, source_name: str = "linux-auth", host: str | None = None) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SYSLOG_PREFIX.match(line)
        if m:
            ts = parse_timestamp(m.group("ts"))
            event = _parse_message(m.group("msg"), ts, m.group("host"), line, source_name)
            if event:
                events.append(event)
            continue
        # journalctl short output: 2026-11-19T10:22:31+00:00 host proc[pid]: msg
        m = re.match(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+[\w\-./]+(?:\[\d+\])?:\s*(?P<msg>.*)$", line)
        if m:
            event = _parse_message(m.group("msg"), m.group("ts"), m.group("host"), line, source_name)
            if event:
                events.append(event)
            continue
        # journalctl -o json / -o json-line, one JSON object per line
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = str(row.get("MESSAGE", ""))
            ts_us = row.get("__REALTIME_TIMESTAMP")
            ts = (
                to_utc_naive(int(ts_us) / 1_000_000)
                if ts_us
                else (row.get("__REALTIME_TIMESTAMP_STR") or datetime.utcnow())
            )
            event = _parse_message(
                message, ts, row.get("_HOSTNAME") or host, line,
                source_name=source_name,
            )
            if event:
                events.append(event)
    return iter_unique(events)
