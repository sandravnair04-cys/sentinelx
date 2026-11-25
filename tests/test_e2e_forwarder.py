"""End-to-end: SXUF event shape → ingestion API → detection engine → alert."""

from __future__ import annotations

import sys
from pathlib import Path

FORWARDER_DIR = Path(__file__).resolve().parents[1] / "forwarder"
if str(FORWARDER_DIR) not in sys.path:
    sys.path.insert(0, str(FORWARDER_DIR))

from sxuf.agent import ForwarderAgent  # noqa: E402
from sxuf.collectors.base import CollectedLine, build_event  # noqa: E402
from sxuf.config import Config  # noqa: E402
from sxuf.transport import Transport  # noqa: E402

from app.models import Alert  # noqa: E402


def test_forwarder_to_detection_pipeline(client, auth_headers, monkeypatch, tmp_path):
    registration = client.post(
        "/api/agents/register",
        json={"agent_id": "sxuf-e2e", "hostname": "WIN-E2E-01"},
        headers=auth_headers,
    )
    assert registration.status_code == 201
    agent_info = registration.json()
    headers = {"X-Agent-ID": agent_info["agent_id"], "X-Agent-Key": agent_info["agent_key"]}

    def fake_post(self, path, payload):
        response = client.post(path, json=payload, headers=headers)
        assert response.status_code == 200, response.text
        return response.json()

    monkeypatch.setattr(Transport, "_post", fake_post)

    config = Config(
        agent_id="sxuf-e2e",
        agent_key=agent_info["agent_key"],
        server_url="http://localhost:8000",
        hostname="WIN-E2E-01",
        os_type="windows",
        state_dir=str(tmp_path),
    )
    agent = ForwarderAgent(config, [])

    events = []
    for index in range(6):
        line = CollectedLine(
            text=(
                f"2026-11-22T09:{index:02d}:00Z EventID=4625 "
                "Account Name=administrator Source Network Address=203.0.113.99 "
                "Computer=WIN-E2E-01 failed logon"
            ),
            source="windows",
            source_name="windows-security",
            pointer=str(index),
        )
        events.append(build_event(config, line).to_dict())

    agent.buffer.enqueue(events)
    assert agent.flush() is True
    assert agent.buffer.depth() == 0

    before = client.get("/api/alerts", headers=auth_headers).json()["total"]
    run = client.post("/api/detection/run", headers=auth_headers)
    assert run.status_code == 200, run.text
    after = client.get("/api/alerts?limit=500", headers=auth_headers).json()
    assert after["total"] > before

    brute = [
        alert for alert in after["items"]
        if "Brute Force" in alert.get("rule_name", "") and alert.get("source_ip") == "203.0.113.99"
    ]
    assert brute, "Expected a brute-force alert for the forwarded source IP"
    assert brute[0]["evidence"]
    assert brute[0]["mitre"]
    agent.shutdown()
