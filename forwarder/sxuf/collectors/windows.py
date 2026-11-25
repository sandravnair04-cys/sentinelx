"""Windows Event Log collector (pywin32 API with wevtutil fallback).

Both backends use fixed, non-shell command lines / documented APIs. Event IDs
are filtered to an explicit allow-list; no other Windows data is collected.
"""

from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

from ..config import SourceConfig
from .base import CheckpointMixin, CollectedLine

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_RECORD_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


class WindowsEventCollector(CheckpointMixin):
    name = "windows_event"

    def __init__(self, source: SourceConfig, state_dir):
        super().__init__(state_dir, f"checkpoints-win-{source.name}.json")
        self.source = source
        self.source_name = source.name
        self.channel = source.channel or "Security"
        self.allowed_ids = set(source.event_ids or [4624, 4625, 4672, 4688, 4720, 4732, 1102])
        self.last_record = int(self.checkpoints.get("last_record", 0))
        self._pywin32 = self._load_pywin32()

    @staticmethod
    def _load_pywin32():
        if sys.platform != "win32":
            return None
        try:
            import win32evtlog  # type: ignore

            return win32evtlog
        except ImportError:
            return None

    def collect(self) -> list[CollectedLine]:
        if self._pywin32 is not None:
            return self._collect_pywin32()
        if sys.platform == "win32":
            return self._collect_wevtutil()
        return []  # non-Windows lab hosts use configured 'file' sources instead

    # -- native API --------------------------------------------------------
    def _collect_pywin32(self) -> list[CollectedLine]:
        win32evtlog = self._pywin32
        flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
        lines: list[CollectedLine] = []
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, self.channel)
            while len(lines) < self.source.batch_size:
                records = win32evtlog.ReadEventLog(handle, flags, 0, self.source.batch_size)
                if not records:
                    break
                for record in records:
                    record_id = int(getattr(record, "RecordNumber", 0) or 0)
                    event_id = int(getattr(record, "EventID", 0) & 0xFFFF)
                    if record_id <= self.last_record or event_id not in self.allowed_ids:
                        continue
                    inserts = record.StringInserts or []
                    summary = " ".join(
                        [f"EventID={event_id}", f"Computer={getattr(record, 'ComputerName', '')}"]
                        + [str(value) for value in inserts if value]
                    )
                    when = getattr(record, "TimeGenerated", None)
                    timestamp = None
                    if when is not None:
                        try:
                            timestamp = when.isoformat()
                            timestamp = datetime.fromisoformat(timestamp).replace(tzinfo=None)
                        except (ValueError, AttributeError):
                            timestamp = None
                    lines.append(
                        CollectedLine(
                            text=summary[:20_000],
                            source="windows",
                            source_name=self.source_name,
                            pointer=str(record_id),
                            event_time=timestamp,
                        )
                    )
        except Exception:
            return []
        finally:
            if handle is not None:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass
        return lines[: self.source.batch_size]

    # -- wevtutil fallback -------------------------------------------------
    def _collect_wevtutil(self) -> list[CollectedLine]:
        command = [
            "wevtutil", "qe", self.channel,
            "/f:xml", f"/c:{max(self.source.batch_size, 100)}", "/rd:true",
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=45, check=False, shell=False
            )
        except (OSError, subprocess.SubprocessError):
            return []
        if completed.returncode != 0:
            return []
        try:
            root = ET.fromstring(f"<Events>{completed.stdout}</Events>")
        except ET.ParseError:
            return []

        lines: list[CollectedLine] = []
        for node in root.findall(f"{_NS}Event"):
            system = node.find(f"{_NS}System")
            if system is None:
                continue
            event_id = int((system.findtext(f"{_NS}EventID") or "0").strip())
            record_id = int((system.findtext(f"{_NS}EventRecordID") or "0").strip())
            if event_id not in self.allowed_ids or record_id <= self.last_record:
                continue
            computer = system.findtext(f"{_NS}Computer") or ""
            raw_time = (system.find(f"{_NS}TimeCreated").get("SystemTime")
                        if system.find(f"{_NS}TimeCreated") is not None else "")
            pairs = [f"EventID={event_id}", f"Computer={computer}"]
            event_data = node.find(f"{_NS}EventData")
            if event_data is not None:
                for data in event_data.findall(f"{_NS}Data"):
                    name = data.get("Name", "")
                    value = (data.text or "").strip()
                    if name and value:
                        pairs.append(f"{name}={value}")
            timestamp = None
            if raw_time:
                try:
                    timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    timestamp = None
            lines.append(
                CollectedLine(
                    text=" ".join(pairs)[:20_000],
                    source="windows",
                    source_name=self.source_name,
                    pointer=str(record_id),
                    event_time=timestamp,
                )
            )
        lines.sort(key=lambda item: int(item.pointer))
        return lines[: self.source.batch_size]

    def commit(self, lines: list[CollectedLine]) -> None:
        if lines:
            self.last_record = max(self.last_record, *(int(line.pointer) for line in lines))
            self.checkpoints["last_record"] = self.last_record
            self.save_checkpoint()

    def close(self) -> None:
        self.save_checkpoint()
