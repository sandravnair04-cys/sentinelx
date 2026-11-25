"""Local agent health status (written to state/health.json)."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Health:
    def __init__(self, state_dir: Path):
        state_dir.mkdir(parents=True, exist_ok=True)
        self.path = state_dir / "health.json"
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {
            "status": "starting",
            "started_at": _now(),
            "last_success_at": None,
            "last_error": "",
            "events_sent": 0,
            "events_failed": 0,
            "duplicates": 0,
            "buffer_depth": 0,
            "heartbeats_sent": 0,
            "errors": 0,
            "sources": [],
        }
        self.write()

    def update(self, **values: Any) -> None:
        with self._lock:
            self._data.update(values)
            self.write_unlocked()

    def record_send(self, *, sent: int = 0, duplicates: int = 0, failed: int = 0, error: str = "") -> None:
        with self._lock:
            self._data["events_sent"] += sent
            self._data["duplicates"] += duplicates
            self._data["events_failed"] += failed
            if error:
                self._data["last_error"] = error[:500]
                self._data["errors"] += 1
                self._data["status"] = "degraded"
            else:
                self._data["last_success_at"] = _now()
                self._data["status"] = "healthy"
            self.write_unlocked()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)

    def write(self) -> None:
        with self._lock:
            self.write_unlocked()

    def write_unlocked(self) -> None:
        self.path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
