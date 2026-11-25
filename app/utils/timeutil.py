"""Timestamp parsing/normalisation helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def to_utc_naive(value: Any) -> datetime:
    """Return a naive UTC datetime from a datetime, epoch number, or string.

    All timestamps in the database are stored as naive UTC for portability
    between SQLite and PostgreSQL. The UI displays them as UTC and labels them.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        # Heuristic: values > 1e11 are milliseconds.
        seconds = value / 1000 if abs(value) > 1e11 else value
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    elif isinstance(value, str):
        dt = parse_timestamp(value)
    else:
        dt = datetime.utcnow()
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

_ISO_CANDIDATES = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%d",
]


def parse_timestamp(text: str) -> datetime:
    """Best-effort parse of the timestamp formats found in auth/security logs.

    Always returns a naive UTC datetime (see to_utc_naive) for portability.
    """
    text = text.strip()
    # Epoch string
    if re.fullmatch(r"\d{10}(\.\d+)?", text):
        return to_utc_naive(float(text))
    # Windows Event Log timeCreated: 7 fractional digits and +/-HH:MM offsets.
    text = re.sub(r"\.(\d{6})\d+", r".\1", text)
    text = text.replace("Z", "+0000")
    text = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)
    for fmt in _ISO_CANDIDATES:
        try:
            return to_utc_naive(datetime.strptime(text, fmt))
        except ValueError:
            continue
    m = _SYSLOG_RE.match(text)
    if m:
        month = _MONTHS.get(m.group("mon").lower())
        if month:
            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            # Syslog has no year; use current year (documented limitation).
            return datetime(datetime.utcnow().year, month, int(m.group("day")), hh, mm, ss)
    raise ValueError(f"Unrecognised timestamp: {text!r}")


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat() + "Z"
