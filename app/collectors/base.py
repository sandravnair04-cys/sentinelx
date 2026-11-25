"""Collection service: persistence, duplicate detection and source metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import BASE_DIR
from ..models import SecurityEvent
from .normalizer import NormalizedEvent

SAMPLE_DIR = BASE_DIR / "data" / "samples"


def ingest_events(db: Session, events: Iterable[NormalizedEvent]) -> dict[str, int]:
    """Insert events that are not already present (dedupe by event_uid)."""
    events = list(events)
    if not events:
        return {"received": 0, "inserted": 0, "duplicates": 0}
    uids = [e.event_uid for e in events]
    existing = set(
        db.scalars(select(SecurityEvent.event_uid).where(SecurityEvent.event_uid.in_(uids))).all()
    )
    inserted = 0
    for event in events:
        if event.event_uid in existing:
            continue
        db.add(SecurityEvent(**event.as_model_kwargs()))
        inserted += 1
        existing.add(event.event_uid)
    if inserted:
        db.commit()
    return {"received": len(events), "inserted": inserted, "duplicates": len(events) - inserted}


def read_sample(name: str) -> str:
    """Read a bundled lab sample file by name (path traversal safe)."""
    if Path(name).name != name:
        raise ValueError("Invalid sample name")
    path = SAMPLE_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"Sample log not found: {name}")
    return path.read_text(encoding="utf-8", errors="replace")


def available_samples() -> list[str]:
    if not SAMPLE_DIR.is_dir():
        return []
    return sorted(p.name for p in SAMPLE_DIR.glob("*.log"))
