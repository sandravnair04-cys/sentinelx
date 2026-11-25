"""Intelligent event correlation and incident construction."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, Evidence, Incident, RiskAssessment, SecurityEvent
from ..risk.scoring import score_risk
from ..utils.helpers import canonical_hash, severity_rank
from ..utils.timeutil import iso
from .mitre import techniques_for_signals

DEFAULT_WINDOW = 3600  # seconds
PRIVILEGED = {"administrator", "admin", "root", "svc_admin", "systems manager"}


def _relevant(event: SecurityEvent) -> bool:
    return event.action != "unknown" or event.event_code in {"4672", "USER_CREATED", "GROUP_ADD"}


def build_correlations(
    events: list[SecurityEvent], alerts: list[Alert], window_seconds: int = DEFAULT_WINDOW
) -> list[dict[str, Any]]:
    """Group related events into candidate incidents with visible evidence."""
    candidates: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if not _relevant(event):
            continue
        key = event.source_ip or (event.username and f"user:{event.username}") or (event.host and f"host:{event.host}")
        candidates[str(key)].append(event)

    results: list[dict[str, Any]] = []
    for key, group in candidates.items():
        group = sorted(group, key=lambda e: e.timestamp)
        # Keep only the most recent time-bounded cluster per key.
        last = group[-1].timestamp
        group = [e for e in group if 0 <= (last - e.timestamp).total_seconds() <= window_seconds]

        group_uids = {e.event_uid for e in group}
        group_users = {e.username for e in group if e.username}
        related_alerts = [
            a for a in alerts
            if any(uid in (a.event_ids or []) for uid in group_uids)
            or (
                a.source_ip == group[0].source_ip
                and a.username in group_users
            )
        ]
        if len(group) < 2 and not related_alerts:
            continue

        failed = [e for e in group if e.action == "failure"]
        successes = [e for e in group if e.action == "success"]
        privileged = [
            e for e in group
            if e.action == "privilege" or (e.username or "").lower() in PRIVILEGED
        ]
        network = [e for e in group if e.action == "network"]
        processes = [e for e in group if e.action == "process"]
        success_after_failures = any(
            s.username == f.username and s.source_ip == f.source_ip and s.timestamp > f.timestamp
            for s in successes for f in failed
        )
        accounts = {e.username for e in group if e.username}
        signals = {
            "failed_logins": len(failed) >= 3,
            "password_spraying": len(accounts) >= 3 and len(failed) >= 3,
            "success_after_failures": success_after_failures,
            "privileged_activity": bool(privileged),
            "account_manipulation": any(e.event_code in {"USER_CREATED", "GROUP_ADD", "4732"} for e in group),
            "suspicious_process": bool(processes),
            "network_anomaly": bool(network),
        }
        if not any(signals.values()):
            continue

        if success_after_failures or len(failed) >= 3:
            category = "Credential Access / Brute Force"
        elif signals["account_manipulation"] or signals["privileged_activity"]:
            category = "Privilege Escalation"
        elif processes:
            category = "Suspicious Process Execution"
        elif network:
            category = "Network Anomaly"
        else:
            category = "Suspicious Activity"

        techniques = techniques_for_signals(signals)
        severity = "LOW"
        for alert in related_alerts:
            if severity_rank(alert.severity) > severity_rank(severity):
                severity = alert.severity
        if severity == "LOW" and any(signals.values()):
            severity = "MEDIUM"

        timeline = [
            {
                "timestamp": iso(e.timestamp),
                "event_uid": e.event_uid,
                "action": e.action,
                "code": e.event_code,
                "source": e.source_type,
                "username": e.username,
                "source_ip": e.source_ip,
                "host": e.host,
                "description": e.message[:200],
            }
            for e in group
        ]
        evidence = []
        for e in group[:30]:
            evidence.append(
                {
                    "type": "event",
                    "description": f"{e.event_code} ({e.action}) from {e.source_ip or 'unknown'}",
                    "event_uid": e.event_uid,
                    "hash": canonical_hash(e.raw_event or e.normalized),
                    "timestamp": iso(e.timestamp),
                }
            )
        for alert in related_alerts[:10]:
            evidence.append(
                {
                    "type": "alert",
                    "description": alert.title,
                    "event_uid": alert.alert_uid,
                    "hash": canonical_hash(alert.evidence),
                    "timestamp": iso(alert.created_at),
                }
            )

        confidence = min(0.95, 0.45 + sum(1 for v in signals.values() if v) * 0.08)
        results.append(
            {
                "key": key,
                "category": category,
                "severity": severity,
                "confidence": round(confidence, 2),
                "source_ip": group[0].source_ip,
                "username": next((u for u in accounts if u and u.lower() in PRIVILEGED), next(iter(accounts), None)),
                "host": group[0].host,
                "signals": signals,
                "techniques": techniques,
                "events": group,
                "alerts": related_alerts,
                "timeline": timeline,
                "evidence": evidence,
                "first_seen": iso(group[0].timestamp),
                "last_seen": iso(group[-1].timestamp),
                "fingerprint": canonical_hash(
                    {
                        "ip": group[0].source_ip,
                        "user": sorted(accounts),
                        "category": category,
                        "day": group[0].timestamp.strftime("%Y%m%d"),
                    }
                ),
            }
        )
    return results


def create_incidents(
    db: Session, correlations: list[dict[str, Any]], simulation: bool = False
) -> list[Incident]:
    """Persist correlations as incidents with evidence and risk assessments."""
    created: list[Incident] = []
    existing_fingerprints = {
        row.finding_summary
        for row in db.scalars(select(Incident))
        if row.finding_summary.startswith("correlation:")
    }
    year = datetime.utcnow().year
    counter = db.scalar(select(Incident.id).order_by(Incident.id.desc()).limit(1)) or 0

    for correlation in correlations:
        fingerprint = f"correlation:{correlation['fingerprint']}"
        if fingerprint in existing_fingerprints:
            continue
        counter += 1
        assessment = score_risk(
            alerts=[_alert_dict(a) for a in correlation["alerts"]],
            events=[_event_dict(e) for e in correlation["events"]],
            context={
                "username": correlation["username"],
                "success_after_failures": correlation["signals"]["success_after_failures"],
            },
        )
        incident = Incident(
            incident_id=f"INC-{year}-{counter:04d}",
            title=f"{correlation['category']} — {correlation['source_ip'] or correlation['username'] or correlation['host']}",
            category=correlation["category"],
            severity=assessment["severity"],
            risk_score=assessment["score"],
            status="New",
            source_ip=correlation["source_ip"],
            username=correlation["username"],
            host=correlation["host"],
            detection_time=datetime.utcnow(),
            finding_summary=fingerprint,
            timeline=correlation["timeline"],
            mitre=correlation["techniques"],
            alert_ids=[a.alert_uid for a in correlation["alerts"]],
            event_ids=[e.event_uid for e in correlation["events"]],
            simulation=simulation or all(e.source_type == "simulation" for e in correlation["events"]),
        )
        db.add(incident)
        db.flush()
        for item in correlation["evidence"][:30]:
            db.add(
                Evidence(
                    incident_fk=incident.id,
                    kind=item["type"],
                    description=item["description"],
                    value=item,
                    hash_sha256=item["hash"],
                    event_uid=item["event_uid"],
                )
            )
        db.add(
            RiskAssessment(
                incident_fk=incident.id,
                score=assessment["score"],
                severity=assessment["severity"],
                factors=assessment["factors"],
                evidence=assessment["evidence"],
                recommendations=assessment["recommendations"],
            )
        )
        for alert in correlation["alerts"]:
            alert.correlated = True
        created.append(incident)
        existing_fingerprints.add(fingerprint)
    db.commit()
    return created


def correlate_and_create(db: Session, window_seconds: int = DEFAULT_WINDOW) -> dict[str, int]:
    events = list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.asc())).all())
    alerts = list(db.scalars(select(Alert)).all())
    correlations = build_correlations(events, alerts, window_seconds)
    incidents = create_incidents(db, correlations)
    return {"events": len(events), "correlations": len(correlations), "incidents_created": len(incidents)}


def _alert_dict(alert: Alert) -> dict[str, Any]:
    return {
        "title": alert.title,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "mitre": alert.mitre,
        "category": alert.category,
    }


def _event_dict(event: SecurityEvent) -> dict[str, Any]:
    return {
        "username": event.username,
        "host": event.host,
        "source_ip": event.source_ip,
        "action": event.action,
    }
