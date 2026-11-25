"""Incident management API tests."""

from app.models import AuditLog
from sqlalchemy import select


def test_list_and_get_incident(client, auth_headers):
    response = client.get("/api/incidents", headers=auth_headers)
    assert response.status_code == 200
    items = response.json()["items"]
    assert items
    incident_id = items[0]["incident_id"]
    detail = client.get("/api/incidents/" + incident_id, headers=auth_headers)
    assert detail.status_code == 200
    data = detail.json()
    assert data["incident_id"] == incident_id
    assert "risk_assessments" in data
    assert "evidence" in data
    assert "audit" in data


def test_status_update_creates_audit(client, auth_headers, db):
    incident_id = client.get("/api/incidents", headers=auth_headers).json()["items"][0]["incident_id"]
    response = client.patch(
        "/api/incidents/" + incident_id,
        headers=auth_headers,
        json={"status": "Resolved", "resolution_notes": "Verified false alarm in lab"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "Resolved"
    logs = list(db.scalars(select(AuditLog).where(AuditLog.target_id == incident_id)).all())
    assert any(log.action == "incident_updated" for log in logs)


def test_invalid_status_rejected(client, auth_headers):
    incident_id = client.get("/api/incidents", headers=auth_headers).json()["items"][0]["incident_id"]
    response = client.patch(
        "/api/incidents/" + incident_id, headers=auth_headers, json={"status": "Exploded"}
    )
    assert response.status_code == 400


def test_search_filter(client, auth_headers):
    response = client.get("/api/incidents?search=INC-", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["total"] > 0
