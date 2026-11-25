"""Idempotent database bootstrap for a usable out-of-the-box demo.

All seeded logs and intelligence are explicitly simulated. Default accounts are
documented in the README and must be changed before any real deployment.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..collectors import ingest_events, parse_linux_auth, parse_windows, read_sample
from ..config import settings
from ..correlation.engine import correlate_and_create
from ..detection import ensure_builtin_rules, load_bundled_sigma, run_detection
from ..models import (
    Incident,
    SecurityEvent,
    ThreatIntelResult,
    User,
)
from ..security import hash_password

DEFAULT_USERS = [
    {
        "email": "admin@sentinelx.io",
        "username": "admin",
        "full_name": "SentinelX Administrator",
        "password": "Admin@123!",
        "role": "admin",
    },
    {
        "email": "analyst@sentinelx.io",
        "username": "analyst",
        "full_name": "SOC Analyst",
        "password": "Analyst@123!",
        "role": "analyst",
    },
]


def seed_users(db: Session) -> int:
    created = 0
    for spec in DEFAULT_USERS:
        if db.scalar(select(User).where(User.username == spec["username"])):
            continue
        db.add(
            User(
                email=spec["email"],
                username=spec["username"],
                full_name=spec["full_name"],
                hashed_password=hash_password(spec["password"]),
                role=spec["role"],
                is_active=True,
            )
        )
        created += 1
    db.commit()
    return created


def seed_sample_events(db: Session) -> int:
    if db.scalar(select(func.count()).select_from(SecurityEvent)):
        return 0
    events = []
    events += parse_windows(read_sample("windows_security_sample.log"), "windows-security-sample")
    events += parse_linux_auth(read_sample("linux_auth_sample.log"), "linux-auth-sample")
    return ingest_events(db, events)["inserted"]


def seed_simulated_intel(db: Session) -> int:
    """Add clearly-labelled simulated malicious indicators for demonstrations."""
    indicator = "198.51.100.11"
    if db.scalar(select(ThreatIntelResult).where(ThreatIntelResult.indicator == indicator)):
        return 0
    db.add(
        ThreatIntelResult(
            indicator=indicator,
            indicator_type="ip",
            provider="local-simulated",
            verdict="malicious",
            score=92.0,
            details={
                "reason": "SIMULATED intelligence for lab demonstrations only.",
                "source": "sentinelx-seed",
            },
            raw={"simulated": True},
            cached_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
        )
    )
    db.commit()
    return 1


def seed_database(db: Session, demo: bool | None = None) -> dict[str, int]:
    demo = settings.seed_demo_data if demo is None else demo
    result = {
        "users_created": seed_users(db),
        "sample_events_created": seed_sample_events(db) if demo else 0,
        "sigma_rules_loaded": load_bundled_sigma(db),
    }
    ensure_builtin_rules(db)
    result["simulated_intel_created"] = seed_simulated_intel(db)
    if demo:
        result["detection"] = run_detection(db)
        result["correlation"] = correlate_and_create(db)
    else:
        result["detection"] = {"created": 0}
        result["correlation"] = {"incidents_created": 0}
    return result
