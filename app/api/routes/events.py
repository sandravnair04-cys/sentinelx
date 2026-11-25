"""Security event collection and querying endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from ...collectors import (
    NormalizedEvent,
    available_samples,
    ingest_events,
    parse_linux_auth,
    parse_windows,
    read_sample,
)
from ...collectors.wazuh import WazuhClient, parse_wazuh_alerts
from ...database import get_db
from ...models import Alert, SecurityEvent
from ...schemas import EventIn, EventSubmission, EventsBatch, TextCollectionRequest
from ...security import client_ip, require_analyst
from ...services.audit import log_action
from ...utils.search import parse_query

router = APIRouter(tags=["Events & Collection"])


def _parse_dt(value: str | None, label: str):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {label} timestamp") from exc


def _event_out(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "event_uid": event.event_uid,
        "source_type": event.source_type,
        "source_name": event.source_name,
        "event_code": event.event_code,
        "action": event.action,
        "username": event.username,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "host": event.host,
        "timestamp": event.timestamp.isoformat() + "Z",
        "message": event.message,
        "raw_event": event.raw_event,
        "normalized": event.normalized,
        "confidence": event.confidence,
    }


@router.get("/events")
def list_events(
    limit: int = 50,
    offset: int = 0,
    action: str | None = None,
    source_type: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    search: str | None = None,
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
) -> dict:
    limit, offset = max(1, min(500, limit)), max(0, offset)
    query = select(SecurityEvent)
    if action:
        query = query.where(SecurityEvent.action == action)
    if source_type:
        query = query.where(SecurityEvent.source_type == source_type)
    if source_ip:
        query = query.where(SecurityEvent.source_ip == source_ip)
    if username:
        query = query.where(SecurityEvent.username == username)
    if search:
        term = f"%{search}%"
        query = query.where(
            or_(
                SecurityEvent.message.like(term),
                SecurityEvent.raw_event.like(term),
                SecurityEvent.event_code.like(term),
            )
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(db.scalars(query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit)).all())
    return {"total": total, "limit": limit, "offset": offset, "items": [_event_out(e) for e in rows]}


@router.post("/events", status_code=201)
def create_event(
    payload: EventIn, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    from ...utils.timeutil import to_utc_naive
    event = NormalizedEvent(
        source_type=payload.source_type,
        source_name=payload.source_name,
        event_code=payload.event_code,
        action=payload.action,
        username=payload.username,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        host=payload.host,
        timestamp=to_utc_naive(payload.timestamp) if payload.timestamp else datetime.utcnow(),
        message=payload.message,
        raw_event=payload.raw_event or payload.message,
        confidence=payload.confidence,
    )
    result = ingest_events(db, [event])
    log_action(db, user.username, "event_created", actor_role=user.role,
               target_type="event", target_id=event.event_uid, ip_address=client_ip(request))
    return {"event_uid": event.event_uid, **result}


@router.post("/events/batch")
def create_events_batch(
    payload: EventsBatch, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    from ...utils.timeutil import to_utc_naive
    events = [
        NormalizedEvent(
            source_type=e.source_type,
            source_name=e.source_name,
            event_code=e.event_code,
            action=e.action,
            username=e.username,
            source_ip=e.source_ip,
            destination_ip=e.destination_ip,
            host=e.host,
            timestamp=to_utc_naive(e.timestamp) if e.timestamp else datetime.utcnow(),
            message=e.message,
            raw_event=e.raw_event or e.message,
            confidence=e.confidence,
        )
        for e in payload.events
    ]
    result = ingest_events(db, events)
    log_action(db, user.username, "events_batch_created", actor_role=user.role,
               target_type="event", ip_address=client_ip(request), details=result)
    return result


@router.post("/events/submit")
def submit_event(
    payload: EventSubmission,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    """Submit one event and optionally run detection + correlation immediately.

    Accepts raw log text (parsed by the matching collector) or an already
    normalised event. This is the human-facing equivalent of the SXUF ingest
    path; forwarded events arrive through /api/ingest/* with agent credentials.
    """
    from ...correlation import correlate_and_create
    from ...detection import run_detection
    from ...models import Incident
    from ...utils.timeutil import to_utc_naive

    if payload.mode == "raw" and not payload.text.strip():
        raise HTTPException(status_code=400, detail="Raw mode requires text")
    if payload.mode == "structured" and payload.event is None:
        raise HTTPException(status_code=400, detail="Structured mode requires an event object")

    if payload.mode == "raw":
        if payload.format == "windows":
            events = parse_windows(payload.text, payload.source_name, payload.host)
        elif payload.format == "linux":
            events = parse_linux_auth(payload.text, payload.source_name, payload.host)
        else:
            try:
                events = parse_wazuh_alerts(payload.text, payload.source_name)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:
        item = payload.event
        events = [
            NormalizedEvent(
                source_type=item.source_type,
                source_name=item.source_name,
                event_code=item.event_code,
                action=item.action,
                username=item.username,
                source_ip=item.source_ip,
                destination_ip=item.destination_ip,
                host=item.host,
                timestamp=to_utc_naive(item.timestamp) if item.timestamp else datetime.utcnow(),
                message=item.message,
                raw_event=item.raw_event or item.message,
                confidence=item.confidence,
            )
        ]

    before_alerts = db.scalar(select(func.count()).select_from(Alert)) or 0
    before_incidents = set(db.scalars(select(Incident.incident_id)).all())
    ingestion = ingest_events(db, events)

    detection_result = None
    correlation_result = None
    new_incidents: list[str] = []
    if payload.auto_process:
        detection_result = run_detection(db, since_minutes=15)
        correlation_result = correlate_and_create(db)
        after_incidents = set(db.scalars(select(Incident.incident_id)).all())
        new_incidents = sorted(after_incidents - before_incidents)

    after_alerts = db.scalar(select(func.count()).select_from(Alert)) or 0
    log_action(
        db,
        user.username,
        "event_submitted",
        actor_role=user.role,
        target_type="event",
        ip_address=client_ip(request),
        details={
            **ingestion,
            "auto_process": payload.auto_process,
            "alerts_created": after_alerts - before_alerts,
            "incidents_created": new_incidents,
        },
    )
    return {
        "event_uids": [event.event_uid for event in events],
        "ingestion": ingestion,
        "auto_process": payload.auto_process,
        "detection": detection_result,
        "correlation": correlation_result,
        "alerts_created": after_alerts - before_alerts,
        "incidents_created": new_incidents,
    }


@router.get("/events/search")
def search_events(
    q: str = "",
    host: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
) -> dict:
    """SIEM-style search with field filters, a simple query syntax and facets."""
    limit, offset = max(1, min(500, limit)), max(0, offset)
    parsed = parse_query(q)
    if not parsed.valid:
        raise HTTPException(status_code=400, detail="; ".join(parsed.errors))

    query = select(SecurityEvent)
    for term in parsed.terms:
        value, field_name = term.value, term.field
        if field_name == "host":
            condition = SecurityEvent.host.contains(value, autoescape=True)
        elif field_name == "source_ip":
            condition = SecurityEvent.source_ip.contains(value, autoescape=True)
        elif field_name == "username":
            condition = SecurityEvent.username.contains(value, autoescape=True)
        elif field_name == "severity":
            condition = SecurityEvent.normalized["severity"].as_string().contains(value, autoescape=True)
        elif field_name == "event_type":
            condition = SecurityEvent.normalized["event_type"].as_string().contains(value, autoescape=True)
        elif field_name == "source":
            condition = SecurityEvent.source_type.contains(value, autoescape=True)
        elif field_name == "event_code":
            condition = SecurityEvent.event_code.contains(value, autoescape=True)
        elif field_name == "action":
            condition = SecurityEvent.action.contains(value, autoescape=True)
        elif field_name == "agent_id":
            condition = SecurityEvent.normalized["agent_id"].as_string().contains(value, autoescape=True)
        elif field_name == "event_id":
            condition = or_(
                SecurityEvent.normalized["client_event_id"].as_string().contains(value, autoescape=True),
                SecurityEvent.event_uid.contains(value, autoescape=True),
            )
        else:
            condition = or_(
                SecurityEvent.message.contains(value, autoescape=True),
                SecurityEvent.raw_event.contains(value, autoescape=True),
                SecurityEvent.event_code.contains(value, autoescape=True),
                SecurityEvent.host.contains(value, autoescape=True),
                SecurityEvent.username.contains(value, autoescape=True),
                SecurityEvent.source_ip.contains(value, autoescape=True),
                cast(SecurityEvent.normalized, String).contains(value, autoescape=True),
            )
        query = query.where(~condition if term.negated else condition)

    for column, value in (
        (SecurityEvent.host, host),
        (SecurityEvent.source_ip, source_ip),
        (SecurityEvent.username, username),
    ):
        if value:
            query = query.where(column.contains(value, autoescape=True))
    if severity:
        query = query.where(SecurityEvent.normalized["severity"].as_string().ilike(severity))
    if event_type:
        query = query.where(SecurityEvent.normalized["event_type"].as_string().ilike(event_type))
    start_dt, end_dt = _parse_dt(start, "start"), _parse_dt(end, "end")
    if start_dt:
        query = query.where(SecurityEvent.timestamp >= start_dt)
    if end_dt:
        query = query.where(SecurityEvent.timestamp <= end_dt)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(db.scalars(query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit)).all())
    facets = {"severity": {}, "source_type": {}}
    for row in rows:
        sev = str((row.normalized or {}).get("severity", "info"))
        facets["severity"][sev] = facets["severity"].get(sev, 0) + 1
        facets["source_type"][row.source_type] = facets["source_type"].get(row.source_type, 0) + 1
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "query": q,
        "parsed_terms": [term.__dict__ for term in parsed.terms],
        "items": [_event_out(event) for event in rows],
        "facets": facets,
    }


@router.get("/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_out(event)


@router.get("/collect/samples")
def list_samples(_user=Depends(require_analyst)) -> dict:
    return {"samples": available_samples()}


def _ingest_parsed(events, db, user, request, source: str) -> dict:
    result = ingest_events(db, events)
    log_action(db, user.username, "logs_collected", actor_role=user.role,
               target_type="collection", target_id=source, ip_address=client_ip(request), details=result)
    return {"source": source, **result}


@router.post("/collect/windows/text")
def collect_windows_text(
    payload: TextCollectionRequest, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    events = parse_windows(payload.text, payload.source_name, payload.host)
    return _ingest_parsed(events, db, user, request, "windows-text")


@router.post("/collect/linux/text")
def collect_linux_text(
    payload: TextCollectionRequest, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    events = parse_linux_auth(payload.text, payload.source_name, payload.host)
    return _ingest_parsed(events, db, user, request, "linux-text")


@router.post("/collect/wazuh/text")
def collect_wazuh_text(
    payload: TextCollectionRequest, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    try:
        events = parse_wazuh_alerts(payload.text, payload.source_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ingest_parsed(events, db, user, request, "wazuh-text")


@router.post("/collect/sample")
def collect_sample(
    payload: dict, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    name = str(payload.get("name", ""))
    platform = str(payload.get("platform", "windows")).lower()
    try:
        text = read_sample(name)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if platform == "linux":
        events = parse_linux_auth(text, name)
    elif platform == "wazuh":
        events = parse_wazuh_alerts(text, name)
    else:
        events = parse_windows(text, name)
    return _ingest_parsed(events, db, user, request, f"sample:{name}")


@router.post("/collect/wazuh/fetch")
def collect_wazuh_fetch(
    request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    client = WazuhClient()
    if not client.configured:
        raise HTTPException(status_code=503, detail="Wazuh integration is not configured")
    events = client.fetch_alerts()
    return _ingest_parsed(events, db, user, request, "wazuh-api")
