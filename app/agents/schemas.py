"""Structured output schemas used to validate every agent response."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class AgentOutput(BaseModel):
    """Base class: agents must always report their reasoning basis."""

    summary: str = Field(default="", max_length=3000)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_basis: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)

    @field_validator("summary", mode="before")
    @classmethod
    def _coerce_summary(cls, value: Any) -> str:
        if isinstance(value, (dict, list)):
            return str(value)[:3000]
        return "" if value is None else str(value)[:3000]


class LogAnalysisOutput(AgentOutput):
    key_fields: dict[str, Any] = Field(default_factory=dict)
    patterns: list[str] = Field(default_factory=list)
    event_count: int = Field(default=0, ge=0)


class ThreatDetectionOutput(AgentOutput):
    attack_categories: list[str] = Field(default_factory=list)
    preliminary_severity: str = Field(default="LOW")
    rule_matches: list[str] = Field(default_factory=list)
    explanation: str = Field(default="")

    @field_validator("preliminary_severity")
    @classmethod
    def _severity(cls, value: str) -> str:
        value = str(value).upper()
        return value if value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "LOW"


class InvestigationOutput(AgentOutput):
    affected_users: list[str] = Field(default_factory=list)
    affected_systems: list[str] = Field(default_factory=list)
    correlation_explanation: str = Field(default="")
    timeline_summary: str = Field(default="")
    mitre_techniques: list[str] = Field(default_factory=list)


class RiskOutput(AgentOutput):
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    severity: str = Field(default="LOW")
    factors: list[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    action_type: str = Field(
        default="collect_evidence",
        pattern="^(block_ip|disable_account|isolate_endpoint|collect_evidence|investigate_process)$",
    )
    target: str = ""
    title: str = ""
    description: str = ""
    purpose: str = ""
    risk_if_ignored: str = ""
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


class ResponseOutput(AgentOutput):
    actions: list[ResponseAction] = Field(default_factory=list)
    approval_required: bool = True


class ReportOutput(AgentOutput):
    executive_summary: str = Field(default="")
    remediation: list[str] = Field(default_factory=list)
    report_title: str = Field(default="SENTINELX Incident Report")


OUTPUT_SCHEMAS = {
    "log_analysis": LogAnalysisOutput,
    "threat_detection": ThreatDetectionOutput,
    "investigation": InvestigationOutput,
    "risk_assessment": RiskOutput,
    "incident_response": ResponseOutput,
    "report_generation": ReportOutput,
}
