"""SXUF collectors: file, systemd journal and Windows Event Log."""

from .base import CollectedLine, Collector, build_event
from .files import FileCollector
from .journald import JournalCollector
from .windows import WindowsEventCollector

__all__ = [
    "CollectedLine",
    "Collector",
    "build_event",
    "FileCollector",
    "JournalCollector",
    "WindowsEventCollector",
]
