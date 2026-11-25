"""SXUF runtime: collection, buffering, forwarding, heartbeat and recovery."""

from __future__ import annotations

import logging
import signal
import threading
import time
from typing import Any

from . import __version__
from .buffer import EventBuffer
from .collectors import Collector, build_event
from .config import Config
from .dedupe import SeenStore
from .health import Health
from .transport import Transport, TransportError

log = logging.getLogger("sxuf.agent")


class ForwarderAgent:
    def __init__(self, config: Config, collectors: list[Collector]):
        self.config = config
        self.collectors = collectors
        self.state_dir = config.state_path
        self.health = Health(self.state_dir)
        self.seen = SeenStore(self.state_dir)
        self.buffer = EventBuffer(self.state_dir, config.max_buffer_events)
        self.transport = Transport(config, self.health)
        self._stop = threading.Event()
        self._last_heartbeat = 0.0

    # -- helpers -----------------------------------------------------------
    def _heartbeat_payload(self) -> dict[str, Any]:
        snapshot = self.health.snapshot()
        return {
            "agent_id": self.config.agent_id,
            "hostname": self.config.hostname,
            "version": __version__,
            "os_type": self.config.os_type or ("windows" if __import__("sys").platform == "win32" else "linux"),
            "os_version": "",
            "ip_address": "",
            "status": "degraded" if snapshot["status"] == "degraded" else "online",
            "buffer_depth": self.buffer.depth(),
            "events_sent": snapshot["events_sent"],
            "errors": snapshot["errors"],
            "sources": [collector.name for collector in self.collectors],
            "config_fingerprint": self.config.fingerprint(),
            "health": snapshot,
        }

    def heartbeat(self, *, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and now - self._last_heartbeat < self.config.heartbeat_seconds:
            return True
        try:
            self.transport.send_heartbeat(self._heartbeat_payload())
        except TransportError as exc:
            log.warning("Heartbeat failed: %s", exc)
            self.health.update(status="degraded", last_error=str(exc)[:500])
            return False
        self._last_heartbeat = now
        self.health.update(heartbeats_sent=self.health.snapshot()["heartbeats_sent"] + 1)
        return True

    def flush(self) -> bool:
        """Send as many buffered batches as possible; return True if all sent."""
        success = True
        while True:
            batch = self.buffer.peek(self.config.batch_size)
            if not batch:
                break
            try:
                result = self.transport.send_batch(batch)
            except TransportError as exc:
                log.warning("Batch send failed (%d events): %s", len(batch), exc)
                self.health.record_send(failed=len(batch), error=str(exc))
                success = False
                break
            outcomes = {str(item.get("event_id")): item.get("status") for item in result.get("results", [])}
            acked = [
                event_id for event_id, status in outcomes.items()
                if status in ("accepted", "duplicate")
            ]
            duplicates = sum(1 for status in outcomes.values() if status == "duplicate")
            rejected = len(batch) - len(acked)
            self.buffer.ack(acked)
            self.health.record_send(sent=len(acked), duplicates=duplicates, failed=rejected)
            if rejected:
                log.warning("%d events rejected by server (check agent id/credentials)", rejected)
            if len(batch) < self.config.batch_size:
                break
        self.health.update(buffer_depth=self.buffer.depth())
        return success

    def collect_once(self) -> int:
        discovered = 0
        for collector in self.collectors:
            if self._stop.is_set():
                break
            try:
                lines = collector.collect()
            except Exception as exc:  # a broken source must not kill the agent
                log.error("Collector %s failed: %s", collector.name, exc)
                self.health.update(status="degraded", last_error=f"collector {collector.name}: {exc}"[:500])
                continue
            if not lines:
                continue
            by_event: dict[str, Any] = {}
            new_events: list[dict[str, Any]] = []
            for line in lines:
                event = build_event(self.config, line)
                payload = event.to_dict()
                by_event[payload["event_id"]] = line
                if self.seen.is_new(payload["event_id"]):
                    new_events.append(payload)
            if not new_events:
                continue
            self.buffer.enqueue(new_events)
            discovered += len(new_events)
            if self.flush():
                remaining = {
                    pending["event_id"]
                    for pending in self.buffer.peek(self.config.max_buffer_events)
                }
                acked_lines = [
                    line for event_id, line in by_event.items() if event_id not in remaining
                ]
                if acked_lines:
                    collector.commit(acked_lines)
        return discovered

    def run(self) -> None:
        log.info("SXUF %s starting (%s sources)", __version__, len(self.collectors))
        self.health.update(status="healthy", sources=[c.name for c in self.collectors])
        self.heartbeat(force=True)
        while not self._stop.is_set():
            try:
                self.collect_once()
                self.flush()
                self.heartbeat()
            except Exception as exc:
                log.exception("Unexpected agent error: %s", exc)
                self.health.update(status="degraded", last_error=str(exc)[:500])
            self._stop.wait(self.config.flush_seconds)
        self.shutdown()

    def once(self) -> dict[str, Any]:
        discovered = self.collect_once()
        self.flush()
        self.heartbeat(force=True)
        return {"discovered": discovered, **self.status()}

    def status(self) -> dict[str, Any]:
        return {
            "agent_id": self.config.agent_id,
            "version": __version__,
            "hostname": self.config.hostname,
            "config_fingerprint": self.config.fingerprint(),
            "buffer_depth": self.buffer.depth(),
            "seen_events": self.seen.count(),
            "health": self.health.snapshot(),
        }

    def request_stop(self, *_args) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self.flush()
        finally:
            for collector in self.collectors:
                try:
                    collector.close()
                except Exception:
                    pass
            self.transport.close()
            self.seen.close()
            self.health.update(status="stopped")
            log.info("SXUF stopped cleanly")
