"""Crash-safe, disk-backed event queue with acknowledgement support."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Iterable


class EventBuffer:
    def __init__(self, state_dir: Path, max_events: int = 50_000) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        self.path = state_dir / "buffer.jsonl"
        self.max_events = max_events
        self._lock = threading.RLock()
        self._dropped = 0
        if not self.path.exists():
            self.path.touch()

    def _read(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        records.append(record)
                except json.JSONDecodeError:
                    # A partially written final line is discarded on restart.
                    continue
        return records

    def _write(self, records: Iterable[dict[str, Any]]) -> None:
        temp = self.path.with_suffix(".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)

    def enqueue(self, events: Iterable[dict[str, Any]]) -> int:
        with self._lock:
            records = self._read()
            additions = list(events)
            records.extend(additions)
            overflow = len(records) - self.max_events
            if overflow > 0:
                self._dropped += overflow
                records = records[overflow:]
            self._write(records)
            return len(additions)

    def peek(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            return self._read()[:limit]

    def ack(self, event_ids: Iterable[str]) -> int:
        acknowledged = set(event_ids)
        if not acknowledged:
            return 0
        with self._lock:
            records = self._read()
            remaining = [r for r in records if r.get("event_id") not in acknowledged]
            removed = len(records) - len(remaining)
            if removed:
                self._write(remaining)
            return removed

    def requeue(self, events: Iterable[dict[str, Any]]) -> None:
        """Put failed events at the front so they are retried first."""
        with self._lock:
            records = list(events) + self._read()
            overflow = len(records) - self.max_events
            if overflow > 0:
                self._dropped += overflow
                records = records[overflow:]
            self._write(records)

    def depth(self) -> int:
        with self._lock:
            return len(self._read())

    @property
    def dropped(self) -> int:
        return self._dropped
