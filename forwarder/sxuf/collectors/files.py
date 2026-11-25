"""Incremental tailing of explicitly configured log files.

Offsets are stored per file and only committed after the server acknowledges
the batch, so an interrupted run resumes without gaps or duplicates.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from ..config import SourceConfig
from .base import CheckpointMixin, CollectedLine


class FileCollector(CheckpointMixin):
    name = "file"

    def __init__(self, source: SourceConfig, state_dir):
        super().__init__(state_dir, f"checkpoints-files-{source.name}.json")
        self.source = source
        self.path = source.path
        self._pending: dict[str, Any] = {}
        # source_name becomes the server-side event source label.
        self.source_name = source.name

    def _identity(self) -> str:
        try:
            stat = os.stat(self.path)
            return f"{stat.st_ino}:{stat.st_dev}"
        except OSError:
            return "missing"

    def collect(self) -> list[CollectedLine]:
        identity = self._identity()
        saved = self.checkpoints.get(self.path, {})
        offset = int(saved.get("offset", 0)) if saved.get("identity") == identity else 0
        lines: list[CollectedLine] = []
        try:
            with open(self.path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                if size < offset:  # file was truncated or rotated in place
                    offset = 0
                handle.seek(offset)
                while True:
                    raw = handle.readline()
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        # Partial line: leave it for the next poll.
                        break
                    offset = handle.tell()
                    text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if text.strip():
                        lines.append(
                            CollectedLine(
                                text=text,
                                source="linux" if "auth" in self.source_name or "syslog" in self.source_name else "file",
                                source_name=self.source_name,
                                pointer=str(offset),
                                event_time=datetime.utcnow(),
                            )
                        )
                self._pending = {"offset": offset, "identity": identity}
        except OSError:
            return []
        return lines[: self.source.batch_size]

    def commit(self, lines: list[CollectedLine]) -> None:
        if lines and self._pending:
            self.checkpoints[self.path] = {
                "offset": int(lines[-1].pointer),
                "identity": self._pending.get("identity", "missing"),
            }
            self.save_checkpoint()

    def close(self) -> None:
        self.save_checkpoint()
