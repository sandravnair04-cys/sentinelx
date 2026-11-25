"""Lightweight view of a security event used by detection rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class DetectionEvent:
    id: int
    event_uid: str
    event_code: str
    action: str
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    host: str | None
    timestamp: datetime
    message: str
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_model(cls, event: Any) -> "DetectionEvent":
        payload = dict(event.normalized or {})
        payload.update(
            {
                "event_code": event.event_code,
                "action": event.action,
                "username": event.username,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "host": event.host,
                "message": event.message,
                "source_type": event.source_type,
                "event_uid": event.event_uid,
            }
        )
        return cls(
            id=event.id,
            event_uid=event.event_uid,
            event_code=event.event_code,
            action=event.action,
            username=event.username,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            host=event.host,
            timestamp=event.timestamp,
            message=event.message,
            payload=payload,
        )
