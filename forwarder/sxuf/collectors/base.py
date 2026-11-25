"""Collector contract and untrusted-line → ForwardedEvent conversion."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from ..config import Config
from ..models import ForwardedEvent
from ..parser import (
    classify,
    extract_event_id,
    extract_ip,
    extract_user,
    normalised_fields,
    parse_timestamp,
    severity_for,
)


@dataclass
class CollectedLine:
    text: str
    source: str
    source_name: str
    pointer: str
    event_time: datetime | None = None

    @property
    def dedupe_key(self) -> str:
        return f"{self.source}|{self.source_name}|{self.pointer}|{hash(self.text)}"


class Collector(Protocol):
    name: str

    def collect(self) -> list[CollectedLine]: ...

    def commit(self, lines: list[CollectedLine]) -> None: ...

    def close(self) -> None: ...


def build_event(config: Config, line: CollectedLine) -> ForwardedEvent:
    """Convert one collected line into the central ingestion wire format."""
    text = line.text.strip()
    event_type = classify(text)
    timestamp = parse_timestamp(text, line.event_time) if line.event_time else parse_timestamp(text)
    fields = normalised_fields(text, source=line.source, source_name=line.source_name)
    event_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{config.agent_id}|{line.source}|{line.source_name}|{line.pointer}|{text[:512]}",
        )
    )
    username = extract_user(text)
    source_ip = extract_ip(text)
    severity = severity_for(event_type)
    normalized: dict[str, Any] = {
        **fields,
        "event_id": extract_event_id(text),
        "event_type": event_type,
        "severity": severity,
        "username": username,
        "source_ip": source_ip,
        "hostname": config.hostname,
        "collector_pointer": line.pointer,
    }
    return ForwardedEvent(
        event_id=event_id,
        timestamp=timestamp,
        hostname=config.hostname,
        source=line.source_name,
        event_type=event_type,
        source_ip=source_ip,
        username=username,
        severity=severity,
        raw_event=text[:200_000],
        normalized_event=normalized,
        agent_id=config.agent_id,
    )


class CheckpointMixin:
    """Shared JSON checkpoint persistence for incremental collectors."""

    def __init__(self, state_dir: Path, filename: str):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path = state_dir / filename
        self.checkpoints: dict[str, Any] = {}
        if self.checkpoint_path.is_file():
            try:
                import json

                self.checkpoints = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                self.checkpoints = {}

    def save_checkpoint(self) -> None:
        import json

        self.checkpoint_path.write_text(
            json.dumps(self.checkpoints, ensure_ascii=False), encoding="utf-8"
        )
