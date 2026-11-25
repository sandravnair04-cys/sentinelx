"""Pydantic request/response schemas used by the REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserOut(ORMModel):
    id: int
    email: EmailStr
    username: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    full_name: str = ""
    password: str = Field(min_length=10, max_length=256)
    role: str = Field(default="analyst", pattern="^(viewer|analyst|admin)$")


class RoleUpdate(BaseModel):
    role: str = Field(pattern="^(viewer|analyst|admin)$")
    is_active: bool | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    username: str


class EventIn(BaseModel):
    source_type: str = "manual"
    source_name: str = "manual-entry"
    event_code: str = ""
    action: str = "unknown"
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    host: str | None = None
    timestamp: datetime | None = None
    message: str = ""
    raw_event: str = ""
    confidence: float = 0.8


class EventsBatch(BaseModel):
    events: list[EventIn]


class EventOut(ORMModel):
    id: int
    event_uid: str
    source_type: str
    source_name: str
    event_code: str
    action: str
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    host: str | None
    timestamp: datetime
    message: str
    normalized: dict
    confidence: float
    processed: bool


class TextCollectionRequest(BaseModel):
    text: str = Field(max_length=2_000_000)
    source_name: str = "uploaded-log"
    host: str | None = None


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: str | None = None
    thresholds: dict[str, Any] | None = None


class AlertOut(ORMModel):
    id: int
    alert_uid: str
    rule_name: str
    category: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence: dict
    event_ids: list
    mitre: list
    source_ip: str | None
    username: str | None
    host: str | None
    status: str
    correlated: bool
    created_at: datetime


class IncidentOut(ORMModel):
    id: int
    incident_id: str
    title: str
    category: str
    severity: str
    risk_score: float
    status: str
    source_ip: str | None
    username: str | None
    host: str | None
    detection_time: datetime
    resolved_at: datetime | None
    finding_summary: str
    timeline: list
    mitre: list
    simulation: bool
    updated_at: datetime


class IncidentUpdate(BaseModel):
    status: str | None = None
    title: str | None = None
    severity: str | None = None
    resolution_notes: str | None = None
    finding_summary: str | None = None
    assigned_to: str | None = None


class InvestigationStart(BaseModel):
    incident_id: str
    started_by: str = "analyst"


class InvestigationOut(ORMModel):
    id: int
    session_uid: str
    incident_id: str
    status: str
    llm_mode: str
    current_step: str
    state: dict
    error: str
    started_by: str
    started_at: datetime
    finished_at: datetime | None


class ApprovalDecision(BaseModel):
    decision: str = Field(default="approved", pattern="^(approved|rejected)$")
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = ""
    role: str = Field(default="analyst", pattern="^(analyst|admin)$")


class IntelLookup(BaseModel):
    indicator: str = Field(min_length=2, max_length=255)
    indicator_type: str | None = None


class SimulationRequest(BaseModel):
    scenario: str
    count: int = Field(default=10, ge=1, le=500)
    source_ip: str = "203.0.113.77"
    username: str = "administrator"
    host: str = "WIN-SRV-01"


class SettingUpdate(BaseModel):
    value: dict[str, Any]


# ---------------------------------------------------------------------------
# SXUF ingestion & endpoint registry schemas (Phase 3/4)
# ---------------------------------------------------------------------------


class ForwardedEvent(BaseModel):
    """One normalised event as sent by a SXUF forwarder.

    Treat every value as untrusted data. Lengths are bounded to prevent memory
    exhaustion, and unknown fields are rejected to keep the contract explicit.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    hostname: str = Field(min_length=1, max_length=255)
    source: str = Field(default="unknown", max_length=60)
    event_type: str = Field(default="unknown", max_length=60)
    source_ip: str | None = Field(default=None, max_length=64)
    username: str | None = Field(default=None, max_length=255)
    severity: str = Field(default="info", max_length=20)
    raw_event: str = Field(default="", max_length=200_000)
    normalized_event: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = Field(default=None, max_length=100)


class IngestBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_id: str = Field(default="", max_length=64)
    events: list[ForwardedEvent] = Field(default_factory=list, max_length=1000)


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    version: str = Field(default="unknown", max_length=40)
    os_type: str = Field(default="unknown", max_length=20)
    os_version: str = Field(default="", max_length=120)
    ip_address: str = Field(default="", max_length=64)
    status: str = Field(default="online", max_length=20)
    buffer_depth: int = Field(default=0, ge=0, le=10_000_000)
    events_sent: int = Field(default=0, ge=0)
    errors: int = Field(default=0, ge=0)
    sources: list[str] = Field(default_factory=list, max_length=200)
    config_fingerprint: str = Field(default="", max_length=64)
    health: dict[str, Any] = Field(default_factory=dict)


class AgentRegistration(BaseModel):
    agent_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    hostname: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=lambda: ["ingest", "heartbeat"])
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    query_text: str = Field(default="", max_length=4000)
    filters: dict[str, Any] = Field(default_factory=dict)
    is_shared: bool = False


class EventSubmission(BaseModel):
    """Human-facing event submission with optional automatic processing."""

    mode: str = Field(default="raw", pattern="^(raw|structured)$")
    format: str = Field(default="windows", pattern="^(windows|linux|wazuh)$")
    text: str = Field(default="", max_length=200_000)
    source_name: str = Field(default="manual-submission", max_length=255)
    host: str | None = Field(default=None, max_length=255)
    event: EventIn | None = None
    auto_process: bool = True
