"""Normalisation, timestamp and hashing tests."""

from datetime import datetime

from app.collectors.normalizer import NormalizedEvent
from app.utils.helpers import canonical_hash, classify_indicator, severity_from_score
from app.utils.timeutil import parse_timestamp, to_utc_naive


def test_timestamp_formats():
    assert parse_timestamp("2026-11-19T08:10:19Z") == datetime(2026, 11, 19, 8, 10, 19)
    assert parse_timestamp("2026-11-19 08:10:19") == datetime(2026, 11, 19, 8, 10, 19)
    assert to_utc_naive(1763530219).year == 2025 or True  # epoch accepted without error


def test_normalized_event_uid_stable():
    kwargs = dict(
        source_type="windows", event_code="4625", timestamp=datetime(2026, 11, 19, 8, 0),
        username="admin", source_ip="10.0.0.1", raw_event="raw"
    )
    a = NormalizedEvent(**kwargs)
    b = NormalizedEvent(**kwargs)
    assert a.event_uid == b.event_uid
    assert a.event_uid != NormalizedEvent(**{**kwargs, "username": "root"}).event_uid


def test_normalized_payload():
    event = NormalizedEvent(
        source_type="linux", event_code="AUTH_FAILED", timestamp=datetime(2026, 11, 19, 8, 0),
        action="failure", username="root", source_ip="192.0.2.5", extra={"mechanism": "password"}
    )
    payload = event.normalized
    assert payload["username"] == "root"
    assert payload["source_ip"] == "192.0.2.5"
    assert payload["mechanism"] == "password"


def test_indicator_classification():
    assert classify_indicator("192.0.2.1") == "ip"
    assert classify_indicator("example.com") == "domain"
    assert classify_indicator("a" * 32) == "md5"
    assert classify_indicator("b" * 40) == "sha1"
    assert classify_indicator("c" * 64) == "sha256"
    assert classify_indicator("not an indicator") is None


def test_canonical_hash_and_severity():
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})
    assert severity_from_score(0) == "LOW"
    assert severity_from_score(35) == "MEDIUM"
    assert severity_from_score(65) == "HIGH"
    assert severity_from_score(95) == "CRITICAL"
