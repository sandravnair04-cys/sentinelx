"""Windows Security Event Log collection/parsing.

Supports:
  * EVTX XML exports (Event Viewer "Save as XML" / wevtutil output)
  * Windows Event Forwarding JSON (WEF) rows
  * Plain-text event summaries used in the bundled lab samples

Only event IDs 4624 (logon), 4625 (failed logon) and 4672 (special privileges)
are normalised into authentication signals; other IDs are retained as generic
events so detection rules can still be demonstrated safely.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable

from ..utils.timeutil import to_utc_naive
from .normalizer import NormalizedEvent

WINDOWS_EVENT_ACTIONS = {
    "4624": "success",
    "4625": "failure",
    "4672": "privilege",
    "4634": "success",
    "4648": "success",
    "4720": "privilege",
    "4732": "privilege",
}

_TEXT_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"
    r".*?(?:EventID|Event ID)[=:\s]*(?P<id>\d{4})"
    r"(?P<rest>.*)$",
    re.IGNORECASE | re.DOTALL,
)

_KV_RE = re.compile(
    r"(?P<key>Account Name|TargetUserName|User|Username|Source Network Address|"
    r"IpAddress|SourceIp|Computer|Host|Workstation Name|Logon Type|Status)"
    r"[=:]\s*(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def parse_windows_xml(text: str, source_name: str = "windows-security-evtx") -> list[NormalizedEvent]:
    text = text.strip()
    if not text:
        return []
    wrapped = text if "<Events" in text or text.startswith("<Event") else f"<Events>{text}</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Invalid Windows event XML: {exc}") from exc

    events: list[NormalizedEvent] = []
    for node in root.iter():
        if _local(node.tag) != "Event":
            continue
        event_id = ""
        timestamp = None
        host = None
        data: dict[str, str] = {}
        for child in node.iter():
            tag = _local(child.tag)
            if tag == "EventID" and event_id == "":
                event_id = (child.text or "").strip()
            elif tag == "TimeCreated" and timestamp is None:
                timestamp = child.attrib.get("SystemTime")
            elif tag == "Computer" and host is None:
                host = (child.text or "").strip()
            elif tag == "Data":
                name = child.attrib.get("Name")
                if name:
                    data[name.lower()] = (child.text or "").strip()
        if not event_id or not timestamp:
            continue
        user = (
            data.get("targetusername")
            or data.get("subjectusername")
            or data.get("username")
            or None
        )
        ip = data.get("ipaddress") or data.get("sourceip") or None
        message_parts = [f"Windows event {event_id}"]
        if "logontype" in data:
            message_parts.append(f"logon type {data['logontype']}")
        if "status" in data:
            message_parts.append(f"status {data['status']}")
        events.append(
            NormalizedEvent(
                source_type="windows",
                source_name=source_name,
                event_code=event_id,
                timestamp=to_utc_naive(timestamp),
                action=WINDOWS_EVENT_ACTIONS.get(event_id, "unknown"),
                username=user,
                source_ip=ip,
                host=host,
                message="; ".join(message_parts),
                raw_event=ET.tostring(node, encoding="unicode")[:4000],
                confidence=0.95,
                extra={"logon_type": data.get("logontype"), "status": data.get("status")},
            )
        )
    return events


def parse_windows_text(
    text: str, source_name: str = "windows-security-sample", host: str | None = None
) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _TEXT_RE.search(line)
        if not match:
            continue
        event_id = match.group("id")
        kv = {m.group("key").lower().replace(" ", "_"): m.group("value") for m in _KV_RE.finditer(line)}
        user = kv.get("targetusername") or kv.get("account_name") or kv.get("user") or kv.get("username")
        ip = kv.get("source_network_address") or kv.get("ipaddress") or kv.get("sourceip")
        host_value = kv.get("computer") or kv.get("host") or host
        events.append(
            NormalizedEvent(
                source_type="windows",
                source_name=source_name,
                event_code=event_id,
                timestamp=to_utc_naive(match.group("ts")),
                action=WINDOWS_EVENT_ACTIONS.get(event_id, "unknown"),
                username=user,
                source_ip=ip,
                host=host_value,
                message=match.group("rest").strip()[:500] or f"Windows event {event_id}",
                raw_event=line,
                confidence=0.85,
                extra={"logon_type": kv.get("logon_type")},
            )
        )
    return events


def parse_windows_json(text: str, source_name: str = "windows-wef") -> list[NormalizedEvent]:
    payload: Any = json.loads(text)
    rows = payload if isinstance(payload, list) else payload.get("events", [payload])
    events: list[NormalizedEvent] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        event_id = str(row.get("EventID") or row.get("event_id") or "")
        timestamp = row.get("TimeCreated") or row.get("timestamp")
        if not timestamp:
            continue
        system = row.get("System", {})
        data = row.get("EventData", row.get("data", {}))
        if isinstance(data, list):
            data = {d.get("Name", ""): d.get("Text", "") for d in data if isinstance(d, dict)}
        data = {str(k).lower(): v for k, v in data.items()} if isinstance(data, dict) else {}
        events.append(
            NormalizedEvent(
                source_type="windows",
                source_name=source_name,
                event_code=event_id,
                timestamp=to_utc_naive(timestamp),
                action=WINDOWS_EVENT_ACTIONS.get(event_id, "unknown"),
                username=data.get("targetusername") or system.get("username"),
                source_ip=data.get("ipaddress") or data.get("sourceip"),
                host=system.get("computer") or row.get("host"),
                message=str(row.get("message", f"Windows event {event_id}"))[:500],
                raw_event=json.dumps(row)[:4000],
                confidence=0.9,
            )
        )
    return events


def parse_windows(text: str, source_name: str = "windows-security", host: str | None = None) -> list[NormalizedEvent]:
    """Auto-detect the Windows log format and return normalised events."""
    stripped = text.lstrip()
    if stripped.startswith("<"):
        return parse_windows_xml(text, source_name)
    if stripped.startswith("[") or stripped.startswith("{"):
        return parse_windows_json(text, source_name)
    return parse_windows_text(text, source_name, host)


def iter_unique(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Remove duplicate events while preserving first-seen order."""
    seen: set[str] = set()
    result: list[NormalizedEvent] = []
    for event in events:
        if event.event_uid in seen:
            continue
        seen.add(event.event_uid)
        result.append(event)
    return result
