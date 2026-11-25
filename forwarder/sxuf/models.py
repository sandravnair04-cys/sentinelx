"""Wire format for events sent by SXUF to the central ingestion API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class ForwardedEvent:
    event_id: str
    timestamp: str
    hostname: str
    source: str
    event_type: str
    source_ip: str | None = None
    username: str | None = None
    severity: str = "info"
    raw_event: str = ""
    normalized_event: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id[:128],
            "timestamp": self.timestamp,
            "hostname": self.hostname[:255],
            "source": self.source[:60],
            "event_type": self.event_type[:60],
            "source_ip": self.source_ip[:64] if self.source_ip else None,
            "username": self.username[:255] if self.username else None,
            "severity": self.severity[:20],
            "raw_event": self.raw_event[:200_000],
            "normalized_event": self.normalized_event,
            "agent_id": self.agent_id,
        }
