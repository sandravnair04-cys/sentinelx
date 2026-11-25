"""Tests for the SXUF ingestion gateway, registry and supporting APIs."""

from __future__ import annotations

from datetime import datetime, timezone

from app.models import AgentCredential, Endpoint, Forwarder, SecurityEvent, SavedSearch


def _event(event_id: str, **overrides) -> dict:
    payload = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": "WIN-LAB-01",
        "source": "windows-security",
        "event_type": "failed_login",
        "source_ip": "203.0.113.77",
        "username": "administrator",
        "severity": "high",
        "raw_event": "EventID=4625 failed logon",
        "normalized_event": {"event_code": "4625", "message": "failed logon"},
    }
    payload.update(overrides)
    return payload


def _register(client, auth_headers, agent_id="sxuf-win-01", hostname="WIN-LAB-01"):
    response = client.post(
        "/api/agents/register",
        json={"agent_id": agent_id, "hostname": hostname},
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _agent_headers(agent: dict) -> dict:
    return {"X-Agent-ID": agent["agent_id"], "X-Agent-Key": agent["agent_key"]}


# --- agent authentication -------------------------------------------------


def test_ingest_requires_agent_credentials(client):
    response = client.post("/api/ingest/events", json=_event("e-1"))
    assert response.status_code == 401


def test_wrong_agent_key_is_rejected(client, auth_headers):
    agent = _register(client, auth_headers)
    response = client.post(
        "/api/ingest/events",
        json=_event("e-1"),
        headers={"X-Agent-ID": agent["agent_id"], "X-Agent-Key": "wrong-key"},
    )
    assert response.status_code == 401


def test_agent_cannot_call_analyst_endpoints(client, auth_headers):
    agent = _register(client, auth_headers)
    response = client.get("/api/events", headers=_agent_headers(agent))
    assert response.status_code == 401


def test_agent_id_mismatch_is_rejected(client, auth_headers):
    agent = _register(client, auth_headers)
    response = client.post(
        "/api/ingest/events",
        json=_event("e-1", agent_id="someone-else"),
        headers=_agent_headers(agent),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"


# --- ingestion / dedupe ---------------------------------------------------


def test_single_ingest_and_duplicate(client, auth_headers, db):
    agent = _register(client, auth_headers)
    headers = _agent_headers(agent)

    first = client.post("/api/ingest/events", json=_event("evt-1"), headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "accepted"

    second = client.post("/api/ingest/events", json=_event("evt-1"), headers=headers)
    assert second.json()["status"] == "duplicate"

    stored = db.query(SecurityEvent).filter_by(event_uid=first.json()["event_uid"]).first()
    assert stored is not None
    assert stored.normalized["agent_id"] == agent["agent_id"]
    assert stored.normalized["client_event_id"] == "evt-1"
    assert stored.event_code == "4625"
    assert stored.action == "failure"
    endpoint = db.query(Endpoint).filter_by(agent_id=agent["agent_id"]).first()
    assert endpoint.hostname == "WIN-LAB-01"
    assert endpoint.events_received == 1


def test_batch_ingest_counts(client, auth_headers):
    agent = _register(client, auth_headers)
    events = [
        _event("b-1"),
        _event("b-2", event_type="successful_login", severity="medium"),
        _event("b-1"),
    ]
    response = client.post(
        "/api/ingest/batch",
        json={"batch_id": "batch-001", "events": events},
        headers=_agent_headers(agent),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["received"], body["accepted"], body["duplicates"], body["rejected"]) == (3, 2, 1, 0)
    assert len(body["results"]) == 3


def test_oversized_batch_is_rejected(client, auth_headers):
    agent = _register(client, auth_headers)
    response = client.post(
        "/api/ingest/batch",
        json={"events": [_event(f"x-{i}") for i in range(1001)]},
        headers=_agent_headers(agent),
    )
    assert response.status_code == 422


# --- heartbeat / registry -------------------------------------------------


def test_heartbeat_updates_registry_and_health(client, auth_headers):
    agent = _register(client, auth_headers)
    heartbeat = {
        "agent_id": agent["agent_id"],
        "hostname": "WIN-LAB-01",
        "version": "1.0.0",
        "os_type": "windows",
        "os_version": "11",
        "ip_address": "10.0.0.15",
        "buffer_depth": 3,
        "events_sent": 42,
        "sources": ["windows-security", "system"],
    }
    response = client.post("/api/ingest/heartbeat", json=heartbeat, headers=_agent_headers(agent))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "online"

    health = client.get("/api/ingest/health", headers=auth_headers).json()
    assert health["forwarders_online"] == 1
    forwarders = client.get("/api/forwarders", headers=auth_headers).json()["items"]
    assert forwarders[0]["version"] == "1.0.0"
    assert forwarders[0]["events_sent"] == 42

    endpoints = client.get("/api/endpoints", headers=auth_headers).json()["items"]
    assert endpoints[0]["ip_address"] == "10.0.0.15"
    assert endpoints[0]["health"]["buffer_depth"] == 3


def test_heartbeat_requires_heartbeat_scope(client, auth_headers, db):
    agent = _register(client, auth_headers)
    credential = db.query(AgentCredential).filter_by(agent_id=agent["agent_id"]).first()
    credential.scopes = ["ingest"]
    db.commit()
    response = client.post(
        "/api/ingest/heartbeat",
        json={"agent_id": agent["agent_id"], "hostname": "WIN-LAB-01"},
        headers=_agent_headers(agent),
    )
    assert response.status_code == 403


# --- credential lifecycle -------------------------------------------------


def test_credential_rotation_and_revocation(client, auth_headers):
    agent = _register(client, auth_headers)
    rotated = client.post(
        f"/api/agents/{agent['agent_id']}/rotate", headers=auth_headers
    )
    assert rotated.status_code == 200
    new_key = rotated.json()["agent_key"]
    old = client.post(
        "/api/ingest/events", json=_event("r-1"), headers=_agent_headers(agent)
    )
    assert old.status_code == 401
    new_headers = {"X-Agent-ID": agent["agent_id"], "X-Agent-Key": new_key}
    assert client.post("/api/ingest/events", json=_event("r-1"), headers=new_headers).status_code == 200

    revoked = client.post(
        f"/api/agents/{agent['agent_id']}/revoke", headers=auth_headers
    )
    assert revoked.status_code == 200
    assert client.post("/api/ingest/events", json=_event("r-2"), headers=new_headers).status_code == 401
    credentials = client.get("/api/agents/credentials", headers=auth_headers).json()["items"]
    assert credentials[0]["status"] == "revoked"
    assert "key_hash" not in credentials[0]
    assert "agent_key" not in credentials[0]


# --- RBAC, explorer and MITRE --------------------------------------------


def test_viewer_is_read_only(client, auth_headers):
    created = client.post(
        "/api/auth/register",
        json={
            "email": "viewer@example.com",
            "username": "viewer1",
            "password": "Viewer@123!",
            "role": "viewer",
        },
        headers=auth_headers,
    )
    assert created.status_code == 201, created.text
    token = client.post(
        "/api/auth/login", json={"username": "viewer1", "password": "Viewer@123!"}
    ).json()["access_token"]
    viewer_headers = {"Authorization": "Bearer " + token}
    assert client.get("/api/endpoints", headers=viewer_headers).status_code == 200
    assert client.get("/api/mitre/tactics", headers=viewer_headers).status_code == 200
    blocked = client.post(
        "/api/simulation/run",
        json={"scenario": "brute_force_login", "count": 1},
        headers=viewer_headers,
    )
    assert blocked.status_code == 403


def test_log_explorer_search_and_saved_search(client, auth_headers, db, seeded_db):
    agent = _register(client, auth_headers)
    client.post("/api/ingest/events", json=_event("s-1"), headers=_agent_headers(agent))
    response = client.get(
        "/api/events/search?q=severity:high%20user:administrator", headers=auth_headers
    )
    assert response.status_code == 200, response.text
    assert response.json()["total"] >= 1
    assert response.json()["parsed_terms"]

    bad = client.get("/api/events/search?q=bogus:value", headers=auth_headers)
    assert bad.status_code == 400

    saved = client.post(
        "/api/searches",
        json={"name": "High severity", "query_text": "severity:high", "filters": {}},
        headers=auth_headers,
    )
    assert saved.status_code == 201, saved.text
    assert client.get("/api/searches", headers=auth_headers).json()["total"] == 1
    assert db.query(SavedSearch).count() == 1
    assert client.delete(f"/api/searches/{saved.json()['id']}", headers=auth_headers).status_code == 200


def test_submit_event_auto_processes_pipeline(client, auth_headers):
    from datetime import datetime, timedelta

    lines = []
    for index in range(6):
        stamp = (datetime.utcnow() - timedelta(seconds=30 * index)).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(
            f"{stamp} EventID=4625 Account Name=administrator "
            "Source Network Address=203.0.113.222 Computer=WIN-SUBMIT failed logon"
        )
    response = client.post(
        "/api/events/submit",
        json={
            "mode": "raw",
            "format": "windows",
            "text": "\n".join(lines),
            "source_name": "manual-submit-test",
            "auto_process": True,
        },
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ingestion"]["inserted"] == 6
    assert body["auto_process"] is True
    assert body["detection"]["created"] >= 1
    assert body["alerts_created"] >= 1
    assert len(body["event_uids"]) == 6


def test_structured_submission(client, auth_headers):
    response = client.post(
        "/api/events/submit",
        json={
            "mode": "structured",
            "event": {
                "source_type": "linux",
                "event_code": "sshd",
                "action": "failure",
                "username": "root",
                "source_ip": "198.51.100.9",
                "host": "LAB-LINUX-01",
                "message": "Failed password for root from 198.51.100.9",
            },
            "auto_process": False,
        },
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["ingestion"]["inserted"] == 1
    assert response.json()["auto_process"] is False


def test_mitre_catalogue(client, auth_headers):
    tactics = client.get("/api/mitre/tactics", headers=auth_headers).json()
    assert any(tactic["id"] == "TA0006" for tactic in tactics["items"])
    techniques = client.get(
        "/api/mitre/techniques?tactic=TA0006", headers=auth_headers
    ).json()
    assert any(item["id"] == "T1110" for item in techniques["items"])
    assert client.get("/api/mitre/techniques/T1110", headers=auth_headers).status_code == 200
    coverage = client.get("/api/mitre/coverage", headers=auth_headers).json()
    assert coverage["catalogue_size"] >= 20
    assert all(item["name"] != "External / custom technique" for item in coverage["items"] if item["id"].startswith("T1110"))


def test_mitre_id_normalisation():
    from app.api.routes.mitre import _flatten_ids

    assert _flatten_ids("T1110.003 - Password Spraying") == ["T1110.003"]
    assert _flatten_ids("attack.credential-access") == []
    assert _flatten_ids([{"id": "T1078 - Valid Accounts"}]) == ["T1078"]
