"""Tests for the SXUF forwarder (no real endpoints or external network)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sxuf.agent import ForwarderAgent
from sxuf.buffer import EventBuffer
from sxuf.collectors import FileCollector, build_event
from sxuf.config import Config, ConfigError, SourceConfig, load_config
from sxuf.dedupe import SeenStore
from sxuf.models import ForwardedEvent
from sxuf.parser import classify, extract_ip, extract_user, parse_timestamp
from sxuf.transport import Transport


class RecordingHandler(BaseHTTPRequestHandler):
    received: list[dict] = []
    heartbeats: list[dict] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path.endswith("/heartbeat"):
            self.heartbeats.append(payload)
            body = {"status": "ok"}
        else:
            self.received.append(payload)
            body = {
                "results": [
                    {"event_id": event["event_id"], "status": "accepted"}
                    for event in payload.get("events", [])
                ]
            }
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_server():
    RecordingHandler.received = []
    RecordingHandler.heartbeats = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _config(server_url: str, state_dir, sources=None) -> Config:
    return Config(
        agent_id="sxuf-test",
        agent_key="sxuf_test_key",
        server_url=server_url,
        hostname="LAB-01",
        os_type="linux",
        state_dir=str(state_dir),
        sources=sources or [],
    )


# --- configuration safety -------------------------------------------------


def test_config_rejects_sensitive_paths(tmp_path):
    with pytest.raises(ConfigError):
        SourceConfig(kind="file", name="secrets", path="/home/user/.ssh/id_rsa")


def test_config_rejects_plaintext_http_on_remote_host(tmp_path):
    with pytest.raises(ConfigError):
        Config(agent_id="sxuf-test", agent_key="k", server_url="http://siem.example.com")


def test_config_requires_explicit_sources(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "agent:\n  id: sxuf-test\n  key: k\nserver:\n  url: http://localhost:8000\nsources: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_and_fingerprint(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "agent:\n  id: sxuf-test\n  key: k\n"
        "server:\n  url: http://localhost:8000\n"
        "sources:\n  - kind: file\n    name: linux-auth\n    path: /var/log/auth.log\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.sources[0].name == "linux-auth"
    assert len(config.fingerprint()) == 64
    assert config.headers["X-Agent-ID"] == "sxuf-test"


# --- parsing --------------------------------------------------------------


def test_parser_extraction():
    line = "Nov 22 09:12:01 host sshd[123]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2"
    assert classify(line) == "failed_login"
    assert extract_ip(line) == "203.0.113.77"
    assert extract_user(line) in ("invalid", "admin")
    assert parse_timestamp(line).endswith("Z")


def test_windows_event_classification():
    assert classify("EventID=4625 Account Name=admin Source Network Address=10.0.0.9") == "failed_login"
    assert classify("EventID=4672 Special privileges assigned") == "privilege_escalation"


def test_build_event_is_stable_and_wired(tmp_path):
    config = _config("http://localhost:8000", tmp_path)
    from sxuf.collectors.base import CollectedLine

    line = CollectedLine(
        text="Failed password for admin from 203.0.113.77",
        source="linux",
        source_name="linux-auth",
        pointer="42",
    )
    first = build_event(config, line)
    second = build_event(config, line)
    assert first.event_id == second.event_id
    payload = first.to_dict()
    assert payload["agent_id"] == "sxuf-test"
    assert payload["normalized_event"]["event_type"] == "failed_login"
    assert payload["normalized_event"]["severity"] == "high"


# --- dedupe / buffer ------------------------------------------------------


def test_seen_store_claims_once(tmp_path):
    store = SeenStore(tmp_path)
    assert store.is_new("a") is True
    assert store.is_new("a") is False
    assert store.count() == 1
    store.close()


def test_buffer_ack_and_requeue(tmp_path):
    buffer = EventBuffer(tmp_path, max_events=5)
    events = [{"event_id": f"e-{i}"} for i in range(3)]
    buffer.enqueue(events)
    assert buffer.depth() == 3
    assert buffer.peek(2) == events[:2]
    assert buffer.ack(["e-0", "e-1"]) == 2
    assert buffer.peek(10) == [events[2]]
    buffer.requeue([{"event_id": "retry"}])
    assert buffer.peek(2)[0]["event_id"] == "retry"


def test_buffer_enforces_max(tmp_path):
    buffer = EventBuffer(tmp_path, max_events=2)
    buffer.enqueue([{"event_id": "a"}, {"event_id": "b"}, {"event_id": "c"}])
    assert buffer.depth() == 2
    assert buffer.dropped == 1


# --- transport and end-to-end --------------------------------------------


def test_transport_sends_batch_and_heartbeat(local_server, tmp_path):
    transport = Transport(_config(local_server, tmp_path))
    result = transport.send_batch([{"event_id": "t-1"}])
    assert result["results"][0]["status"] == "accepted"
    assert transport.send_heartbeat({"agent_id": "sxuf-test"}) == {"status": "ok"}
    transport.close()
    assert RecordingHandler.received[0]["events"][0]["event_id"] == "t-1"


def test_agent_end_to_end_file_to_server(local_server, tmp_path):
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "Nov 22 09:12:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2\n",
        encoding="utf-8",
    )
    source = SourceConfig(kind="file", name="linux-auth", path=str(log_path), batch_size=10)
    config = _config(local_server, tmp_path, sources=[source])
    agent = ForwarderAgent(config, [FileCollector(source, config.state_path)])

    first = agent.once()
    assert first["discovered"] == 1
    assert len(RecordingHandler.received) == 1
    assert RecordingHandler.received[0]["events"][0]["event_type"] == "failed_login"
    assert RecordingHandler.heartbeats[0]["agent_id"] == "sxuf-test"

    second = agent.once()
    assert second["discovered"] == 0  # checkpoint + dedupe prevent re-sending
    assert len(RecordingHandler.received) == 1
    assert agent.buffer.depth() == 0

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("Nov 22 09:13:01 host sshd[2]: Accepted password for admin from 203.0.113.77\n")
    third = agent.once()
    assert third["discovered"] == 1
    assert RecordingHandler.received[1]["events"][0]["event_type"] == "successful_login"
    agent.shutdown()


def test_agent_requeues_on_server_failure(tmp_path):
    config = _config("http://127.0.0.1:1", tmp_path)
    config.max_retries = 0
    agent = ForwarderAgent(config, [])
    agent.buffer.enqueue([{"event_id": "offline-1"}])
    assert agent.flush() is False
    assert agent.buffer.depth() == 1
    assert agent.health.snapshot()["events_failed"] == 1
    agent.shutdown()
