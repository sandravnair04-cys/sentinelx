"""SQLAlchemy ORM models for SENTINELX.

Types are chosen to be portable between SQLite (development) and PostgreSQL
(production). JSON columns use the generic ``JSON`` type which maps to JSONB on
PostgreSQL. All primary keys are integers for portability; human-facing unique
identifiers (INC-2026-0001, EVT-<hash>, etc.) are stored separately.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.utcnow()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(150), default="")
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="analyst")  # analyst | admin
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_ip_time", "source_ip", "timestamp"),
        Index("ix_events_user_time", "username", "timestamp"),
        Index("ix_events_host_time", "host", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(30), default="unknown")
    # windows | linux | wazuh | simulation | manual
    source_name: Mapped[str] = mapped_column(String(255), default="")
    event_code: Mapped[str] = mapped_column(String(64), default="")
    # Windows event ID (4624...) or Linux/submission subtype
    action: Mapped[str] = mapped_column(String(40), default="unknown")
    # success | failure | privilege | process | network | unknown
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    raw_event: Mapped[str] = mapped_column(Text, default="")
    normalized: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    processed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(60), default="general")
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    thresholds: Mapped[dict] = mapped_column(JSON, default=dict)
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(20), default="builtin")  # builtin | sigma
    definition: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_time", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("detection_rules.id"), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(150), default="")
    category: Mapped[str] = mapped_column(String(60), default="")
    severity: Mapped[str] = mapped_column(String(20), default="LOW")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="new")
    correlated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(60), default="")
    severity: Mapped[str] = mapped_column(String(20), default="LOW")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(30), default="New", index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detection_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolution_notes: Mapped[str] = mapped_column(Text, default="")
    finding_summary: Mapped[str] = mapped_column(Text, default="")
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    simulation: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    recommendations: Mapped[list["ResponseRecommendation"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["InvestigationSession"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    reports: Mapped[list["ReportRecord"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_fk: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40), default="event")
    description: Mapped[str] = mapped_column(Text, default="")
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    hash_sha256: Mapped[str] = mapped_column(String(64), default="")
    event_uid: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="evidence")


class InvestigationSession(Base):
    __tablename__ = "investigation_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    incident_fk: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="running")
    llm_mode: Mapped[str] = mapped_column(String(20), default="fallback")
    current_step: Mapped[str] = mapped_column(String(60), default="")
    state: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    started_by: Mapped[str] = mapped_column(String(100), default="system")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    incident: Mapped[Incident] = relationship(back_populates="sessions")


class AgentExecution(Base):
    __tablename__ = "agent_executions"
    __table_args__ = (Index("ix_agent_exec_time", "started_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_uid: Mapped[str] = mapped_column(String(64), index=True, default="")
    agent_key: Mapped[str] = mapped_column(String(60), index=True)
    agent_name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(Boolean, default=False)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_fk: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="LOW")
    factors: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    model_version: Mapped[str] = mapped_column(String(30), default="deterministic-v1")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="assessments")


class ResponseRecommendation(Base):
    __tablename__ = "response_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_fk: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    session_uid: Mapped[str] = mapped_column(String(64), index=True, default="")
    action_type: Mapped[str] = mapped_column(String(60))
    target: Mapped[str] = mapped_column(String(255), default="")
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    purpose: Mapped[str] = mapped_column(Text, default="")
    risk_if_ignored: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="pending")
    suggested_by: Mapped[str] = mapped_column(String(60), default="incident-response-agent")
    analyst: Mapped[str] = mapped_column(String(100), default="")
    analyst_role: Mapped[str] = mapped_column(String(20), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decision_reason: Mapped[str] = mapped_column(Text, default="")
    execution_mode: Mapped[str] = mapped_column(String(20), default="simulated")
    execution_result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="recommendations")
    approvals: Mapped[list["ApprovalRecord"]] = relationship(
        back_populates="recommendation", cascade="all, delete-orphan"
    )


class ApprovalRecord(Base):
    __tablename__ = "approval_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    recommendation_id: Mapped[int] = mapped_column(
        ForeignKey("response_recommendations.id"), index=True
    )
    action: Mapped[str] = mapped_column(String(20))  # approved | rejected
    analyst: Mapped[str] = mapped_column(String(100))
    analyst_role: Mapped[str] = mapped_column(String(20), default="analyst")
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    recommendation: Mapped[ResponseRecommendation] = relationship(back_populates="approvals")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(100), default="system")
    actor_role: Mapped[str] = mapped_column(String(20), default="system")
    action: Mapped[str] = mapped_column(String(120), index=True)
    target_type: Mapped[str] = mapped_column(String(60), default="")
    target_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class ThreatIntelResult(Base):
    __tablename__ = "threat_intel_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    indicator_type: Mapped[str] = mapped_column(String(20), default="ip")
    provider: Mapped[str] = mapped_column(String(60), default="local")
    verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    cached_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ReportRecord(Base):
    __tablename__ = "report_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_fk: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    generated_by: Mapped[str] = mapped_column(String(100), default="system")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="reports")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


# ---------------------------------------------------------------------------
# SXUF forwarder / endpoint registry (Phase 3)
# ---------------------------------------------------------------------------


class Endpoint(Base):
    """A monitored endpoint. Created automatically on first registered ingest."""

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    os_type: Mapped[str] = mapped_column(String(20), default="unknown")  # windows | linux | unknown
    os_version: Mapped[str] = mapped_column(String(120), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    agent_id: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="unknown")  # online | offline | unknown
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    events_received: Mapped[int] = mapped_column(Integer, default=0)
    health: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Forwarder(Base):
    """SXUF instance metadata and health. Secrets are never stored here."""

    __tablename__ = "forwarders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="", index=True)
    version: Mapped[str] = mapped_column(String(40), default="unknown")
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    config_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    sources: Mapped[list] = mapped_column(JSON, default=list)
    events_sent: Mapped[int] = mapped_column(Integer, default=0)
    buffer_depth: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class AgentCredential(Base):
    """Hashed API credential for a forwarder. The plaintext key is shown once."""

    __tablename__ = "agent_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(64))  # sha256 of the random token
    key_prefix: Mapped[str] = mapped_column(String(16), default="")  # display only
    scopes: Mapped[list] = mapped_column(JSON, default=list)  # ingest | heartbeat
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | revoked
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IngestReceipt(Base):
    """Per-agent client event id ledger; guarantees exactly-once acknowledgement."""

    __tablename__ = "ingest_receipts"
    __table_args__ = (
        UniqueConstraint("agent_id", "client_event_id", name="uq_agent_client_event"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    client_event_id: Mapped[str] = mapped_column(String(128), index=True)
    event_uid: Mapped[str] = mapped_column(String(64), default="")
    batch_id: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(20), default="accepted")  # accepted | duplicate
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class SavedSearch(Base):
    """A named, reusable Log Explorer query owned by a human analyst."""

    __tablename__ = "saved_searches"
    __table_args__ = (UniqueConstraint("owner", "name", name="uq_saved_search_owner_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    owner: Mapped[str] = mapped_column(String(100), index=True)
    query_text: Mapped[str] = mapped_column(Text, default="")
    filters: Mapped[dict] = mapped_column(JSON, default=dict)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
