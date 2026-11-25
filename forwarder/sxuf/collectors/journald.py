"""systemd journal collector using journalctl with fixed, allow-listed arguments."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone

from ..config import SourceConfig
from .base import CheckpointMixin, CollectedLine


class JournalCollector(CheckpointMixin):
    name = "journal"

    def __init__(self, source: SourceConfig, state_dir):
        super().__init__(state_dir, f"checkpoints-journal-{source.name}.json")
        self.source = source
        self.source_name = source.name
        self.cursor = str(self.checkpoints.get("cursor", ""))

    def collect(self) -> list[CollectedLine]:
        if shutil.which("journalctl") is None:
            return []
        command = ["journalctl", "-o", "json", "--no-pager", "-n", str(self.source.batch_size)]
        if self.cursor:
            command.extend(["--cursor", self.cursor])
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=30, check=False, shell=False
            )
        except (OSError, subprocess.SubprocessError):
            return []
        if completed.returncode != 0:
            self.cursor = ""
            return []

        lines: list[CollectedLine] = []
        for entry in completed.stdout.splitlines():
            try:
                record = json.loads(entry)
            except json.JSONDecodeError:
                continue
            message = str(record.get("MESSAGE", "")).strip()
            if not message:
                continue
            cursor = str(record.get("__CURSOR", ""))
            timestamp = None
            micros = record.get("__REALTIME_TIMESTAMP")
            if micros:
                try:
                    timestamp = datetime.fromtimestamp(int(micros) / 1_000_000, tz=timezone.utc).replace(tzinfo=None)
                except (ValueError, OSError):
                    timestamp = None
            lines.append(
                CollectedLine(
                    text=message,
                    source="linux",
                    source_name=self.source_name,
                    pointer=cursor or str(micros or message[:64]),
                    event_time=timestamp,
                )
            )
        return lines

    def commit(self, lines: list[CollectedLine]) -> None:
        if lines:
            self.cursor = lines[-1].pointer
            self.checkpoints["cursor"] = self.cursor
            self.save_checkpoint()

    def close(self) -> None:
        self.save_checkpoint()
