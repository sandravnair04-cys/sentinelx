"""Persistent duplicate-event prevention using a local SQLite ledger."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path


class SeenStore:
    def __init__(self, state_dir: Path, retention_days: int = 30) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        self.path = state_dir / "dedupe.sqlite3"
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS receipts ("
            "event_id TEXT PRIMARY KEY, created_at REAL NOT NULL)"
        )
        self._connection.commit()
        self._prune(retention_days)

    def _prune(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            self._connection.execute("DELETE FROM receipts WHERE created_at < ?", (cutoff,))
            self._connection.commit()

    def is_new(self, event_id: str) -> bool:
        """Atomically claim an event id. True only the first time it is seen."""
        with self._lock:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO receipts(event_id, created_at) VALUES (?, ?)",
                (event_id, time.time()),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def count(self) -> int:
        with self._lock:
            return int(self._connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._connection.close()
