"""Endpoint and forwarder registry maintenance.

All writes are idempotent and derived from authenticated agent heartbeats or
ingested events. A forwarder is marked offline once its heartbeat is older
than the configured timeout (default five minutes).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Endpoint, Forwarder
from ..schemas import HeartbeatRequest


def offline_cutoff() -> datetime:
    return datetime.utcnow() - timedelta(seconds=settings.forwarder_offline_after_seconds)


def upsert_endpoint(
    db: Session,
    hostname: str,
    *,
    agent_id: str | None = None,
    os_type: str = "unknown",
    os_version: str = "",
    ip_address: str = "",
    seen_at: datetime | None = None,
    increment_events: int = 0,
) -> Endpoint:
    seen_at = seen_at or datetime.utcnow()
    endpoint = None
    if agent_id:
        endpoint = db.scalar(select(Endpoint).where(Endpoint.agent_id == agent_id))
    if endpoint is None:
        endpoint = db.scalar(select(Endpoint).where(Endpoint.hostname == hostname))
    if endpoint is None:
        endpoint = Endpoint(hostname=hostname, agent_id=agent_id, status="online")
        db.add(endpoint)
    endpoint.os_type = os_type or endpoint.os_type
    endpoint.os_version = os_version or endpoint.os_version
    endpoint.ip_address = ip_address or endpoint.ip_address
    endpoint.agent_id = agent_id or endpoint.agent_id
    endpoint.last_seen = max(endpoint.last_seen or seen_at, seen_at)
    endpoint.status = "online"
    if increment_events:
        endpoint.events_received = (endpoint.events_received or 0) + increment_events
    db.flush()
    return endpoint


def upsert_forwarder(db: Session, agent_id: str, hostname: str, version: str = "unknown") -> Forwarder:
    forwarder = db.scalar(select(Forwarder).where(Forwarder.agent_id == agent_id))
    if forwarder is None:
        forwarder = Forwarder(agent_id=agent_id, hostname=hostname, version=version, status="online")
        db.add(forwarder)
    else:
        forwarder.hostname = hostname or forwarder.hostname
        forwarder.version = version if version != "unknown" else forwarder.version
        forwarder.status = "online"
    db.flush()
    return forwarder


def apply_heartbeat(db: Session, payload: HeartbeatRequest) -> dict:
    """Persist a heartbeat and return the resulting registry state."""
    now = datetime.utcnow()
    endpoint = upsert_endpoint(
        db,
        payload.hostname,
        agent_id=payload.agent_id,
        os_type=payload.os_type,
        os_version=payload.os_version,
        ip_address=payload.ip_address,
        seen_at=now,
    )
    endpoint.last_heartbeat = now
    endpoint.health = {
        "status": payload.status,
        "buffer_depth": payload.buffer_depth,
        "events_sent": payload.events_sent,
        "errors": payload.errors,
        "sources": payload.sources,
    }

    forwarder = upsert_forwarder(db, payload.agent_id, payload.hostname, payload.version)
    forwarder.status = payload.status if payload.status in ("online", "offline", "degraded") else "online"
    forwarder.sources = payload.sources
    forwarder.config_fingerprint = payload.config_fingerprint
    forwarder.buffer_depth = payload.buffer_depth
    forwarder.events_sent = max(forwarder.events_sent or 0, payload.events_sent)
    forwarder.errors = payload.errors
    forwarder.last_heartbeat = now
    db.commit()
    return {
        "agent_id": payload.agent_id,
        "hostname": payload.hostname,
        "status": forwarder.status,
        "server_time": now.isoformat() + "Z",
        "offline_after_seconds": settings.forwarder_offline_after_seconds,
    }


def refresh_stale_forwarders(db: Session) -> int:
    """Mark forwarders/endpoints offline when their heartbeat has expired."""
    cutoff = offline_cutoff()
    changed = 0
    for forwarder in db.scalars(select(Forwarder).where(Forwarder.status == "online")).all():
        last = forwarder.last_heartbeat or forwarder.registered_at
        if last < cutoff:
            forwarder.status = "offline"
            changed += 1
    for endpoint in db.scalars(select(Endpoint).where(Endpoint.status == "online")).all():
        last = endpoint.last_heartbeat or endpoint.last_seen
        if last < cutoff:
            endpoint.status = "offline"
            changed += 1
    if changed:
        db.commit()
    return changed
