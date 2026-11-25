"""Shared normalised event representation and duplicate detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..utils.helpers import sha256_text
from ..utils.timeutil import to_utc_naive


@dataclass
class NormalizedEvent:
    source_type: str
    event_code: str
    timestamp: datetime
    action: str = "unknown"
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    host: str | None = None
    source_name: str = ""
    message: str = ""
    raw_event: str = ""
    confidence: float = 0.7
    extra: dict[str, Any] = field(default_factory=dict)
    event_uid: str = ""

    def __post_init__(self) -> None:
        self.timestamp = to_utc_naive(self.timestamp)
        if self.source_ip in ("", "-", "unknown"):
            self.source_ip = None
        if self.username in ("", "-", "unknown"):
            self.username = None
        if not self.event_uid:
            # Deterministic identity: same source + code + time + actor + IP is a
            # duplicate. The raw text is included for events without those fields.
            basis = "|".join(
                [
                    self.source_type,
                    self.event_code,
                    self.timestamp.isoformat(),
                    self.username or "",
                    self.source_ip or "",
                    self.host or "",
                    self.raw_event[:256],
                ]
            )
            self.event_uid = sha256_text(basis)[:40]

    @property
    def normalized(self) -> dict[str, Any]:
        return {
            "event_code": self.event_code,
            "action": self.action,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "host": self.host,
            "timestamp": self.timestamp.isoformat() + "Z",
            **self.extra,
        }

    def as_model_kwargs(self) -> dict[str, Any]:
        return {
            "event_uid": self.event_uid,
            "source_type": self.source_type,
            "source_name": self.source_name,
            "event_code": self.event_code,
            "action": self.action,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "host": self.host,
            "timestamp": self.timestamp,
            "message": self.message,
            "raw_event": self.raw_event,
            "normalized": self.normalized,
            "confidence": self.confidence,
        }
