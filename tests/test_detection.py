"""Detection engine and Sigma rule tests."""

from datetime import datetime, timedelta
from sqlalchemy import func, select

from app.collectors import ingest_events
from app.detection import ensure_builtin_rules, run_detection
from app.detection.sigma import evaluate_sigma_rule, parse_sigma_rule
from app.detection.types import DetectionEvent
from app.models import Alert, DetectionRule, SecurityEvent
from app.services.simulation import generate_scenario


def test_builtin_rules_created(seeded_db):
    ensure_builtin_rules(seeded_db)
    rules = list(seeded_db.scalars(select(DetectionRule)).all())
    assert len(rules) >= 10


def test_brute_force_detection(seeded_db):
    # Seeding already runs detection; verify the alerts exist and are grounded.
    alerts = list(seeded_db.scalars(select(Alert)).all())
    assert alerts
    assert any("Brute Force" in a.category for a in alerts)
    assert any(a.severity in {"HIGH", "CRITICAL"} for a in alerts)
    assert all(a.event_ids for a in alerts)
    # Re-running must not create duplicate alerts.
    second = run_detection(seeded_db)
    assert second["created"] == 0


def test_sigma_parse_and_evaluate():
    yaml_text = """title: Test burst
id: test-1
level: high
timeframe: 5m
detection:
  selection:
    action: failure
  condition: selection | count() >= 3 by source_ip
"""
    rule = parse_sigma_rule(yaml_text)
    assert rule.count_threshold == 3
    assert rule.group_by == "source_ip"
    now = datetime.utcnow()
    events = [
        DetectionEvent(i, f"uid{i}", "4625", "failure", "admin", "10.0.0.1", None, "H1",
                       now + timedelta(seconds=i), "failed", {})
        for i in range(4)
    ]
    matches = evaluate_sigma_rule(rule, events)
    assert len(matches) == 1
    assert matches[0]["evidence"]["count"] >= 3


def test_simulation_detection(db):
    events = generate_scenario("brute_force_login", count=8, source_ip="203.0.113.99")
    ingest_events(db, events)
    result = run_detection(db)
    assert result["created"] >= 1
    assert db.scalar(select(func.count()).select_from(SecurityEvent)) >= 8
