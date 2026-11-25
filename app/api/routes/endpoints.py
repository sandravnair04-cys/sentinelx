"""Endpoint, forwarder and agent-credential management (admin operations)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...ingestion.auth import generate_agent_key, hash_agent_key
from ...ingestion.registry import refresh_stale_forwarders, upsert_forwarder
from ...models import AgentCredential, Endpoint, Forwarder
from ...schemas import AgentRegistration
from ...security import client_ip, require_admin, require_viewer
from ...services.audit import log_action

router = APIRouter(tags=["Endpoints & Forwarders"])


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _endpoint_out(endpoint: Endpoint) -> dict[str, Any]:
    return {
        "id": endpoint.id,
        "hostname": endpoint.hostname,
        "os_type": endpoint.os_type,
        "os_version": endpoint.os_version,
        "ip_address": endpoint.ip_address,
        "agent_id": endpoint.agent_id,
        "status": endpoint.status,
        "first_seen": _dt(endpoint.first_seen),
        "last_seen": _dt(endpoint.last_seen),
        "last_heartbeat": _dt(endpoint.last_heartbeat),
        "events_received": endpoint.events_received,
        "health": endpoint.health or {},
    }


def _forwarder_out(forwarder: Forwarder) -> dict[str, Any]:
    return {
        "id": forwarder.id,
        "agent_id": forwarder.agent_id,
        "hostname": forwarder.hostname,
        "version": forwarder.version,
        "status": forwarder.status,
        "sources": forwarder.sources or [],
        "events_sent": forwarder.events_sent,
        "buffer_depth": forwarder.buffer_depth,
        "errors": forwarder.errors,
        "config_fingerprint": forwarder.config_fingerprint,
        "last_heartbeat": _dt(forwarder.last_heartbeat),
        "registered_at": _dt(forwarder.registered_at),
    }


def _credential_out(credential: AgentCredential) -> dict[str, Any]:
    # Deliberately excludes key_hash and any usable secret.
    return {
        "id": credential.id,
        "agent_id": credential.agent_id,
        "key_prefix": credential.key_prefix,
        "scopes": credential.scopes or [],
        "status": credential.status,
        "created_by": credential.created_by,
        "created_at": _dt(credential.created_at),
        "last_used_at": _dt(credential.last_used_at),
        "expires_at": _dt(credential.expires_at),
        "rotated_at": _dt(credential.rotated_at),
        "revoked_at": _dt(credential.revoked_at),
    }


@router.get("/endpoints")
def list_endpoints(db: Session = Depends(get_db), _user=Depends(require_viewer)) -> dict:
    refresh_stale_forwarders(db)
    rows = db.scalars(select(Endpoint).order_by(Endpoint.last_seen.desc())).all()
    return {"total": len(rows), "items": [_endpoint_out(row) for row in rows]}


@router.get("/forwarders")
def list_forwarders(db: Session = Depends(get_db), _user=Depends(require_viewer)) -> dict:
    refresh_stale_forwarders(db)
    rows = db.scalars(select(Forwarder).order_by(Forwarder.registered_at.desc())).all()
    return {"total": len(rows), "items": [_forwarder_out(row) for row in rows]}


@router.get("/forwarders/{agent_id}")
def get_forwarder(agent_id: str, db: Session = Depends(get_db), _user=Depends(require_viewer)) -> dict:
    forwarder = db.scalar(select(Forwarder).where(Forwarder.agent_id == agent_id))
    if forwarder is None:
        raise HTTPException(status_code=404, detail="Forwarder not found")
    return _forwarder_out(forwarder)


@router.post("/agents/register", status_code=201)
def register_agent(
    payload: AgentRegistration,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
) -> dict:
    """Register a SXUF agent. The plaintext key is returned exactly once."""
    if db.scalar(select(AgentCredential).where(AgentCredential.agent_id == payload.agent_id)):
        raise HTTPException(status_code=409, detail="Agent id already registered")
    allowed = {"ingest", "heartbeat"}
    scopes = [scope for scope in payload.scopes if scope in allowed]
    if not scopes:
        raise HTTPException(status_code=400, detail="At least one valid scope is required")

    key = generate_agent_key()
    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=payload.expires_in_days)
    credential = AgentCredential(
        agent_id=payload.agent_id,
        key_hash=hash_agent_key(key),
        key_prefix=key[:12],
        scopes=scopes,
        status="active",
        created_by=admin.username,
        expires_at=expires_at,
    )
    db.add(credential)
    upsert_forwarder(db, payload.agent_id, payload.hostname)
    log_action(
        db,
        admin.username,
        "agent_registered",
        actor_role=admin.role,
        target_type="agent",
        target_id=payload.agent_id,
        ip_address=client_ip(request),
        details={"scopes": scopes, "expires_at": _dt(expires_at)},
    )
    db.commit()
    return {
        "agent_id": payload.agent_id,
        "agent_key": key,  # shown once; never stored, logged or returned again
        "scopes": scopes,
        "expires_at": _dt(expires_at),
        "warning": "Store this key securely in the forwarder config. It cannot be retrieved later.",
    }


@router.get("/agents/credentials")
def list_credentials(db: Session = Depends(get_db), _admin=Depends(require_admin)) -> dict:
    rows = db.scalars(select(AgentCredential).order_by(AgentCredential.created_at.desc())).all()
    return {"total": len(rows), "items": [_credential_out(row) for row in rows]}


@router.post("/agents/{agent_id}/rotate")
def rotate_agent_key(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
) -> dict:
    credential = db.scalar(select(AgentCredential).where(AgentCredential.agent_id == agent_id))
    if credential is None:
        raise HTTPException(status_code=404, detail="Agent credential not found")
    key = generate_agent_key()
    credential.key_hash = hash_agent_key(key)
    credential.key_prefix = key[:12]
    credential.status = "active"
    credential.rotated_at = datetime.utcnow()
    credential.revoked_at = None
    log_action(
        db,
        admin.username,
        "agent_key_rotated",
        actor_role=admin.role,
        target_type="agent",
        target_id=agent_id,
        ip_address=client_ip(request),
    )
    db.commit()
    return {
        "agent_id": agent_id,
        "agent_key": key,
        "warning": "Previous key is invalid immediately. Update the forwarder config now.",
    }


@router.post("/agents/{agent_id}/revoke")
def revoke_agent_key(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
) -> dict:
    credential = db.scalar(select(AgentCredential).where(AgentCredential.agent_id == agent_id))
    if credential is None:
        raise HTTPException(status_code=404, detail="Agent credential not found")
    credential.status = "revoked"
    credential.revoked_at = datetime.utcnow()
    forwarder = db.scalar(select(Forwarder).where(Forwarder.agent_id == agent_id))
    if forwarder:
        forwarder.status = "offline"
    log_action(
        db,
        admin.username,
        "agent_revoked",
        actor_role=admin.role,
        target_type="agent",
        target_id=agent_id,
        ip_address=client_ip(request),
    )
    db.commit()
    return {"agent_id": agent_id, "status": "revoked"}


@router.patch("/forwarders/{agent_id}/config")
def update_forwarder_config(
    agent_id: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
) -> dict:
    """Store non-secret configuration metadata only."""
    forwarder = db.scalar(select(Forwarder).where(Forwarder.agent_id == agent_id))
    if forwarder is None:
        raise HTTPException(status_code=404, detail="Forwarder not found")
    fingerprint = str(payload.get("config_fingerprint", ""))[:64]
    sources = payload.get("sources", [])
    if not isinstance(sources, list):
        raise HTTPException(status_code=400, detail="sources must be a list")
    forwarder.config_fingerprint = fingerprint
    forwarder.sources = [str(source)[:120] for source in sources[:200]]
    log_action(
        db,
        admin.username,
        "forwarder_config_updated",
        actor_role=admin.role,
        target_type="forwarder",
        target_id=agent_id,
        ip_address=client_ip(request),
    )
    db.commit()
    return _forwarder_out(forwarder)
