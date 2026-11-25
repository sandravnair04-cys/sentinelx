"""JSON report export and retention policy tests."""

from __future__ import annotations

from datetime import datetime, timedelta

from app.models import SecurityEvent
from app.services.retention import apply_retention


def test_json_report_export(client, auth_headers):
    incidents = client.get("/api/incidents", headers=auth_headers).json()["items"]
    assert incidents
    incident_id = incidents[0]["incident_id"]
    response = client.get(f"/api/reports/{incident_id}/json", headers=auth_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "1.0"
    assert body["incident"]["incident_id"] == incident_id
    assert "evidence" in body and "response_recommendations" in body
    assert "not proof of compromise" in body["disclaimer"]


def test_retention_dry_run_then_apply(client, auth_headers, db):
    old = SecurityEvent(
        event_uid="retention-old-event",
        source_type="simulation",
        timestamp=datetime.utcnow() - timedelta(days=200),
        raw_event="old",
    )
    db.add(old)
    db.commit()

    preview = apply_retention(db, days=30, dry_run=True)
    assert preview["dry_run"] is True
    assert preview["deleted"]["security_events"] >= 1
    assert db.query(SecurityEvent).filter_by(event_uid="retention-old-event").count() == 1

    result = client.post("/api/retention", json={"days": 30, "dry_run": False}, headers=auth_headers)
    assert result.status_code == 200, result.text
    assert result.json()["deleted"]["security_events"] >= 1
    assert db.query(SecurityEvent).filter_by(event_uid="retention-old-event").count() == 0


def test_retention_rejects_invalid_days(db):
    try:
        apply_retention(db, days=0, dry_run=True)
    except ValueError:
        return
    raise AssertionError("Expected ValueError for zero-day retention")
