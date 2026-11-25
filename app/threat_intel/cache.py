"""SQLite-backed cache for threat intelligence lookups."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import ThreatIntelResult


def get_cached(db: Session, indicator: str, indicator_type: str) -> ThreatIntelResult | None:
    row = db.scalar(
        select(ThreatIntelResult)
        .where(
            ThreatIntelResult.indicator == indicator,
            ThreatIntelResult.indicator_type == indicator_type,
        )
        .order_by(ThreatIntelResult.cached_at.desc())
        .limit(1)
    )
    if row and row.expires_at and row.expires_at < datetime.utcnow():
        return None
    return row


def put_cached(
    db: Session,
    indicator: str,
    indicator_type: str,
    provider: str,
    verdict: str,
    score: float,
    details: dict,
    raw: dict | None = None,
    ttl_seconds: int | None = None,
) -> ThreatIntelResult:
    ttl = settings.threat_intel_cache_ttl_seconds if ttl_seconds is None else ttl_seconds
    row = ThreatIntelResult(
        indicator=indicator,
        indicator_type=indicator_type,
        provider=provider,
        verdict=verdict,
        score=float(score),
        details=details,
        raw=raw or {},
        cached_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(seconds=ttl),
    )
    db.add(row)
    db.commit()
    return row
