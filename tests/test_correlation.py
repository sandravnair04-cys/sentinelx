"""Event correlation and incident construction tests."""

from sqlalchemy import select

from app.correlation.engine import build_correlations, correlate_and_create
from app.models import Alert, Evidence, Incident, RiskAssessment, SecurityEvent
from app.services.seed import seed_sample_events


def test_correlations_from_samples(seeded_db):
    events = list(seeded_db.scalars(select(SecurityEvent)).all())
    alerts = list(seeded_db.scalars(select(Alert)).all())
    correlations = build_correlations(events, alerts)
    assert len(correlations) >= 2
    assert all(c["timeline"] for c in correlations)
    assert all(c["evidence"] for c in correlations)
    assert any(c["signals"]["failed_logins"] for c in correlations)


def test_incident_creation_is_idempotent(seeded_db):
    # Seeding already creates incidents; a second pass must be idempotent.
    incidents_before = list(seeded_db.scalars(select(Incident)).all())
    assert len(incidents_before) >= 2
    second = correlate_and_create(seeded_db)
    assert second["incidents_created"] == 0
    incidents = list(seeded_db.scalars(select(Incident)).all())
    assert all(i.incident_id.startswith("INC-") for i in incidents)
    assert any(i.mitre for i in incidents)
    evidence = list(seeded_db.scalars(select(Evidence)).all())
    assert evidence and all(len(e.hash_sha256) == 64 for e in evidence)
    assessments = list(seeded_db.scalars(select(RiskAssessment)).all())
    assert assessments and all(0 <= a.score <= 100 for a in assessments)
