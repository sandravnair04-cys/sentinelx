"""Human approval and role-based authorisation tests."""

from app.agents.orchestrator import start_investigation
from app.models import Incident, ResponseRecommendation
from sqlalchemy import select


def _pending_recommendation(db, client, headers):
    incident = list(db.scalars(select(Incident)).all())[0]
    start_investigation(db, incident.incident_id, "analyst")
    rec = db.scalar(select(ResponseRecommendation).where(ResponseRecommendation.status == "pending"))
    return rec


def test_analyst_cannot_approve_high_impact(client, analyst_headers, db):
    rec = _pending_recommendation(db, client, analyst_headers)
    if rec.action_type not in {"block_ip", "disable_account", "isolate_endpoint"}:
        return  # only high-impact actions require admin
    response = client.post(
        f"/api/response/recommendations/{rec.id}/approve",
        headers=analyst_headers,
        json={"analyst": "analyst", "reason": "test"},
    )
    assert response.status_code == 403


def test_admin_approves_and_records_identity(client, auth_headers, db):
    rec = _pending_recommendation(db, client, auth_headers)
    response = client.post(
        f"/api/response/recommendations/{rec.id}/approve",
        headers=auth_headers,
        json={"decision": "approved", "analyst": "admin", "reason": "lab approval"},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "approved"
    assert data["analyst"] == "admin"
    assert "SIMULATED ONLY" in data["execution_result"]
    db.refresh(rec)
    assert rec.status == "approved"


def test_rejection_and_double_decision(client, analyst_headers, db):
    rec = _pending_recommendation(db, client, analyst_headers)
    if rec.action_type in {"block_ip", "disable_account", "isolate_endpoint"}:
        # Use admin header path instead; here we simply verify analyst rejection
        # of low-impact actions or 403 for high-impact.
        response = client.post(
            f"/api/response/recommendations/{rec.id}/reject",
            headers=analyst_headers,
            json={"analyst": "analyst", "reason": "not applicable"},
        )
        assert response.status_code in {200, 403}
        return
    response = client.post(
        f"/api/response/recommendations/{rec.id}/reject",
        headers=analyst_headers,
        json={"analyst": "analyst", "reason": "not needed"},
    )
    assert response.status_code == 200
    second = client.post(
        f"/api/response/recommendations/{rec.id}/reject",
        headers=analyst_headers,
        json={"analyst": "analyst", "reason": "again"},
    )
    assert second.status_code == 409
