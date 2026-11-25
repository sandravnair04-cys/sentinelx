"""Configurable data-retention cleanup.

Audit logs and incidents are intentionally NOT deleted by the default policy:
they are the investigation record. Only raw event/alert/receipt data ages out.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Alert, IngestReceipt, SecurityEvent, ThreatIntelResult
from .audit import log_action


def retention_cutoff(days: int | None = None) -> datetime:
    days = settings.log_retention_days if days is None else days
    if days < 1:
        raise ValueError("Retention period must be at least one day")
    return datetime.utcnow() - timedelta(days=days)


def apply_retention(
    db: Session,
    *,
    days: int | None = None,
    dry_run: bool = False,
    actor: str = "system",
) -> dict:
    """Delete aged raw telemetry. Returns per-table counts."""
    cutoff = retention_cutoff(days)
    counts: dict[str, int] = {}

    for name, model, column in (
        ("security_events", SecurityEvent, SecurityEvent.timestamp),
        ("alerts", Alert, Alert.created_at),
        ("ingest_receipts", IngestReceipt, IngestReceipt.received_at),
    ):
        counts[name] = db.scalar(
            select(func.count()).select_from(model).where(column < cutoff)
        ) or 0

    counts["expired_threat_intel"] = db.scalar(
        select(func.count()).select_from(ThreatIntelResult).where(
            ThreatIntelResult.expires_at.is_not(None), ThreatIntelResult.expires_at < datetime.utcnow()
        )
    ) or 0

    if dry_run:
        return {"cutoff": cutoff.isoformat() + "Z", "dry_run": True, "deleted": counts}

    for name, model, column in (
        ("security_events", SecurityEvent, SecurityEvent.timestamp),
        ("alerts", Alert, Alert.created_at),
        ("ingest_receipts", IngestReceipt, IngestReceipt.received_at),
    ):
        db.execute(delete(model).where(column < cutoff))
    db.execute(
        delete(ThreatIntelResult).where(
            ThreatIntelResult.expires_at.is_not(None), ThreatIntelResult.expires_at < datetime.utcnow()
        )
    )
    log_action(
        db, actor, "retention_applied", actor_role="system",
        target_type="retention", details={"cutoff": cutoff.isoformat(), "deleted": counts},
    )
    db.commit()
    return {"cutoff": cutoff.isoformat() + "Z", "dry_run": False, "deleted": counts}
