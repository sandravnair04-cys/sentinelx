"""Normalisation, deduplication and persistence of forwarded events.

The event id supplied by a SXUF forwarder is the idempotency key. It is scoped
to the authenticated agent id, so two agents may legitimately use the same id.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..collectors import NormalizedEvent, ingest_events
from ..models import IngestReceipt
from ..schemas import ForwardedEvent, IngestBatch
from ..utils.helpers import sha256_text
from ..utils.timeutil import to_utc_naive
from .registry import upsert_endpoint, upsert_forwarder


def _action_for(event_type: str, severity: str) -> str:
    value = (event_type or "").lower()
    if "fail" in value or "invalid" in value:
        return "failure"
    if "success" in value or "logon" in value or "login" in value:
        return "success"
    if "privileg" in value or "escalat" in value:
        return "privilege"
    if "process" in value or "exec" in value:
        return "process"
    if "network" in value or "connect" in value or "firewall" in value:
        return "network"
    if severity.lower() in ("critical", "high") and "auth" in value:
        return "suspicious"
    return "unknown"


def _source_type_for(source: str) -> str:
    value = (source or "").lower()
    if "win" in value:
        return "windows"
    if "linux" in value or "auth" in value or "syslog" in value or "journal" in value:
        return "linux"
    if "wazuh" in value:
        return "wazuh"
    if value in ("simulation", "synthetic"):
        return "simulation"
    return value[:30] or "unknown"


def _event_code_for(event: ForwardedEvent) -> str:
    normalized = event.normalized_event or {}
    for key in ("event_code", "EventID", "event_id_code", "win_event_id", "eventid"):
        value = normalized.get(key)
        if value not in (None, ""):
            return str(value)[:64]
    return ""


def _to_normalized(event: ForwardedEvent, agent_id: str, event_uid: str) -> NormalizedEvent:
    normalized = event.normalized_event or {}
    agent_host = event.hostname
    normalized_event = NormalizedEvent(
        source_type=_source_type_for(event.source),
        source_name=event.source or "sxuf",
        event_code=_event_code_for(event),
        action=_action_for(event.event_type, event.severity),
        username=event.username,
        source_ip=event.source_ip,
        host=agent_host,
        timestamp=to_utc_naive(event.timestamp),
        message=str(normalized.get("message") or event.event_type)[:2000],
        raw_event=event.raw_event or str(normalized),
        confidence=0.85,
        event_uid=event_uid,
        extra={
            "agent_id": agent_id,
            "client_event_id": event.event_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "hostname": agent_host,
            "source": event.source,
            "forwarded": True,
            **{k: v for k, v in normalized.items() if k not in ("message",)},
        },
    )
    return normalized_event


def ingest_forwarded_batch(db: Session, agent_id: str, batch: IngestBatch) -> dict:
    """Insert new forwarded events; return a per-event acknowledgement list."""
    client_ids = [event.event_id for event in batch.events]
    existing: dict[str, str] = {}
    if client_ids:
        rows = db.execute(
            select(IngestReceipt.client_event_id, IngestReceipt.event_uid).where(
                IngestReceipt.agent_id == agent_id,
                IngestReceipt.client_event_id.in_(client_ids),
            )
        ).all()
        existing = {row[0]: row[1] for row in rows}

    new_events: list[NormalizedEvent] = []
    receipts: list[IngestReceipt] = []
    results: list[dict] = []
    accepted = duplicates = rejected = 0
    seen_in_batch: set[str] = set()

    for event in batch.events:
        if event.agent_id and event.agent_id != agent_id:
            rejected += 1
            results.append(
                {"event_id": event.event_id, "status": "rejected", "reason": "agent_id mismatch"}
            )
            continue
        event_uid = sha256_text(f"agent:{agent_id}|event:{event.event_id}")[:40]
        if event.event_id in existing or event.event_id in seen_in_batch:
            duplicates += 1
            results.append(
                {
                    "event_id": event.event_id,
                    "status": "duplicate",
                    "event_uid": existing.get(event.event_id, event_uid),
                }
            )
            continue
        seen_in_batch.add(event.event_id)
        normalized = _to_normalized(event, agent_id, event_uid)
        new_events.append(normalized)
        receipts.append(
            IngestReceipt(
                agent_id=agent_id,
                client_event_id=event.event_id,
                event_uid=event_uid,
                batch_id=batch.batch_id,
                status="accepted",
            )
        )
        accepted += 1
        results.append({"event_id": event.event_id, "status": "accepted", "event_uid": event_uid})

    insertion = ingest_events(db, new_events)
    for receipt in receipts:
        db.add(receipt)

    if batch.events:
        last = batch.events[-1]
        upsert_endpoint(
            db,
            last.hostname,
            agent_id=agent_id,
            seen_at=to_utc_naive(last.timestamp),
            increment_events=accepted,
        )
        upsert_forwarder(db, agent_id, last.hostname)
    db.commit()

    return {
        "batch_id": batch.batch_id,
        "received": len(batch.events),
        "accepted": accepted,
        "duplicates": duplicates,
        "rejected": rejected,
        "stored": insertion.get("inserted", 0),
        "server_time": datetime.utcnow().isoformat() + "Z",
        "results": results,
    }
