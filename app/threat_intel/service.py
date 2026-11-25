"""Threat intelligence service with caching, fallbacks and safe defaults."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ThreatIntelResult
from ..utils.helpers import classify_indicator
from .cache import get_cached, put_cached
from .providers import AbuseIPDBProvider, LookupError_, VirusTotalProvider

PROVIDERS = [VirusTotalProvider(), AbuseIPDBProvider()]


def lookup(db: Session, indicator: str, indicator_type: str | None = None, force: bool = False) -> dict[str, Any]:
    indicator = indicator.strip()
    detected_type = indicator_type or classify_indicator(indicator)
    if detected_type not in {"ip", "domain", "md5", "sha1", "sha256"}:
        return {
            "indicator": indicator,
            "indicator_type": "unknown",
            "verdict": "unknown",
            "score": 0,
            "provider": "local",
            "details": {"reason": "Indicator is not a valid IP, domain or supported file hash."},
            "cached": False,
        }

    if not force:
        cached = get_cached(db, indicator, detected_type)
        if cached:
            return {
                "indicator": indicator,
                "indicator_type": detected_type,
                "verdict": cached.verdict,
                "score": cached.score,
                "provider": cached.provider,
                "details": cached.details,
                "cached": True,
                "cached_at": cached.cached_at.isoformat() + "Z",
            }

    errors: list[str] = []
    for provider in PROVIDERS:
        if not provider.enabled:
            continue
        try:
            result = provider.lookup(indicator, detected_type)
        except LookupError_ as exc:
            errors.append(str(exc))
            continue
        except Exception as exc:  # pragma: no cover - defensive against SDK surprises
            errors.append(f"{provider.name}: {type(exc).__name__}")
            continue
        put_cached(
            db, indicator, detected_type, provider.name,
            result["verdict"], result["score"], result["details"], result.get("raw", {}),
        )
        return {
            "indicator": indicator,
            "indicator_type": detected_type,
            "verdict": result["verdict"],
            "score": result["score"],
            "provider": provider.name,
            "details": result["details"],
            "cached": False,
        }

    details = {
        "reason": "No configured threat intelligence provider" if not errors else "; ".join(errors),
        "note": "Unknown does not mean clean. Configure API keys in .env to enable lookups.",
    }
    put_cached(
        db, indicator, detected_type, "local", "unknown", 0, details, {}, ttl_seconds=300
    )
    return {
        "indicator": indicator,
        "indicator_type": detected_type,
        "verdict": "unknown",
        "score": 0,
        "provider": "local",
        "details": details,
        "cached": False,
    }


def list_results(db: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(ThreatIntelResult)
        .order_by(ThreatIntelResult.cached_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "indicator": r.indicator,
            "indicator_type": r.indicator_type,
            "provider": r.provider,
            "verdict": r.verdict,
            "score": r.score,
            "details": r.details,
            "cached_at": r.cached_at.isoformat() + "Z",
        }
        for r in rows
    ]
