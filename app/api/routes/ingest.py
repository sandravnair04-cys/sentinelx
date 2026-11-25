"""SXUF-only ingestion endpoints (agent-scoped credentials required)."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...ingestion import ingest_forwarded_batch, require_agent
from ...ingestion.registry import apply_heartbeat, refresh_stale_forwarders
from ...models import AgentCredential, Forwarder, IngestReceipt, SecurityEvent
from ...schemas import ForwardedEvent, HeartbeatRequest, IngestBatch
from ...security import client_ip, require_viewer
from ...services.audit import log_action

router = APIRouter(tags=["SXUF Ingestion"])


def _auto_process(db: Session, result: dict) -> dict | None:
    """Splunk-like pipeline: detect and correlate each new forwarded batch."""
    if not settings.auto_process_forwarded or result.get("accepted", 0) == 0:
        return None
    from ...correlation import correlate_and_create
    from ...detection import run_detection

    detection = run_detection(db, since_minutes=15)
    correlation = correlate_and_create(db)
    return {"detection": detection, "correlation": correlation}


@router.post("/ingest/events")
def ingest_single(
    event: ForwardedEvent,
    request: Request,
    db: Session = Depends(get_db),
    credential=Depends(require_agent("ingest")),
) -> dict:
    """Accept one normalised event from an authenticated SXUF agent."""
    batch = IngestBatch(batch_id=f"single-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}", events=[event])
    result = ingest_forwarded_batch(db, credential.agent_id, batch)
    result["processing"] = _auto_process(db, result)
    log_action(
        db,
        f"agent:{credential.agent_id}",
        "agent_event_ingested",
        actor_role="agent",
        target_type="ingest",
        ip_address=client_ip(request),
        details={"accepted": result["accepted"], "duplicates": result["duplicates"]},
    )
    return result["results"][0] | {"batch_id": result["batch_id"]}


@router.post("/ingest/batch")
def ingest_batch(
    batch: IngestBatch,
    request: Request,
    db: Session = Depends(get_db),
    credential=Depends(require_agent("ingest")),
) -> dict:
    """Accept a bounded batch of events (max 1000) from a SXUF agent."""
    result = ingest_forwarded_batch(db, credential.agent_id, batch)
    result["processing"] = _auto_process(db, result)
    log_action(
        db,
        f"agent:{credential.agent_id}",
        "agent_batch_ingested",
        actor_role="agent",
        target_type="ingest",
        target_id=batch.batch_id,
        ip_address=client_ip(request),
        details={
            "received": result["received"],
            "accepted": result["accepted"],
            "duplicates": result["duplicates"],
            "rejected": result["rejected"],
        },
    )
    return result


@router.post("/ingest/heartbeat")
def heartbeat(
    payload: HeartbeatRequest,
    db: Session = Depends(get_db),
    credential=Depends(require_agent("heartbeat")),
) -> dict:
    """Update forwarder health. The payload agent_id must match the credential."""
    if payload.agent_id != credential.agent_id:
        raise HTTPException(status_code=403, detail="agent_id does not match credential")
    return apply_heartbeat(db, payload)


@router.get("/ingest/health")
def ingestion_health(
    db: Session = Depends(get_db), _user=Depends(require_viewer)
) -> dict:
    """Human-readable ingestion pipeline health for the dashboard."""
    refresh_stale_forwarders(db)
    since = datetime.utcnow() - timedelta(minutes=5)
    online = db.scalar(
        select(func.count()).select_from(Forwarder).where(Forwarder.status == "online")
    ) or 0
    offline = db.scalar(
        select(func.count()).select_from(Forwarder).where(Forwarder.status == "offline")
    ) or 0
    active_credentials = db.scalar(
        select(func.count()).select_from(AgentCredential).where(AgentCredential.status == "active")
    ) or 0
    ingested_5m = db.scalar(
        select(func.count()).select_from(IngestReceipt).where(IngestReceipt.received_at >= since)
    ) or 0
    events_5m = db.scalar(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.created_at >= since)
    ) or 0
    last = db.scalar(select(func.max(IngestReceipt.received_at)))
    return {
        "status": "healthy" if online or active_credentials == 0 else "degraded",
        "forwarders_online": online,
        "forwarders_offline": offline,
        "active_credentials": active_credentials,
        "events_last_5m": events_5m,
        "ingest_receipts_last_5m": ingested_5m,
        "last_ingest_at": last.isoformat() + "Z" if last else None,
        "offline_after_seconds": settings.forwarder_offline_after_seconds,
    }
