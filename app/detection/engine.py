"""Deterministic, evidence-driven detection engine.

Every alert references concrete event IDs and includes the evidence used to
create it. Rules are configurable; an event is never labelled a confirmed
attack solely because a rule matched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, DetectionRule, SecurityEvent, ThreatIntelResult
from ..utils.helpers import canonical_hash, is_private_ip, severity_rank, sha256_text
from .rules import BUILTIN_BY_KEY, BUILTIN_RULES, BuiltinRule
from .sigma import evaluate_sigma_rule, parse_sigma_rule
from .types import DetectionEvent

PRIVILEGED_USERS = {
    "administrator", "admin", "root", "svc_admin", "domain admin", "systems manager"
}


@dataclass
class Candidate:
    rule_key: str
    rule_name: str
    category: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    events: list[DetectionEvent] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    source_ip: str | None = None
    username: str | None = None
    host: str | None = None


def _ordered(db: Session, since_minutes: int | None) -> list[DetectionEvent]:
    query = select(SecurityEvent).order_by(SecurityEvent.timestamp.asc())
    if since_minutes:
        cutoff = datetime.utcnow() - timedelta(minutes=since_minutes)
        query = query.where(SecurityEvent.timestamp >= cutoff)
    return [DetectionEvent.from_model(e) for e in db.scalars(query).all()]


def _window(events: list[DetectionEvent], seconds: int) -> list[dict[str, list[DetectionEvent]]]:
    """Return sliding windows grouped by source IP."""
    buckets: dict[str, list[DetectionEvent]] = {}
    for event in events:
        key = event.source_ip or "unknown"
        bucket = [e for e in buckets.get(key, []) if (event.timestamp - e.timestamp).total_seconds() <= seconds]
        bucket.append(event)
        buckets[key] = bucket
    return buckets


def _failure_candidates(events: list[DetectionEvent], rules: dict[str, DetectionRule]) -> list[Candidate]:
    result: list[Candidate] = []
    failures = [e for e in events if e.action == "failure"]
    if not failures:
        return result

    source_rule = rules.get("brute_force_source")
    account_rule = rules.get("brute_force_account")
    spray_rule = rules.get("password_spraying")

    def threshold(key: str, field_name: str, default: int) -> int:
        rule = rules.get(key)
        if rule and isinstance(rule.thresholds, dict) and field_name in rule.thresholds:
            return int(rule.thresholds[field_name])
        return default

    window = threshold("brute_force_source", "window_seconds", BUILTIN_BY_KEY["brute_force_source"].thresholds["window_seconds"])
    limit = threshold("brute_force_source", "threshold", BUILTIN_BY_KEY["brute_force_source"].thresholds["threshold"])

    if source_rule and source_rule.enabled:
        for ip, group in _window(failures, window).items():
            if len(group) >= limit:
                accounts = sorted({e.username or "unknown" for e in group})
                result.append(
                    Candidate(
                        rule_key="brute_force_source",
                        rule_name=source_rule.name,
                        category="Brute Force",
                        severity=source_rule.severity,
                        confidence=min(0.95, 0.6 + len(group) / 100),
                        title=f"Brute-force attempts from {ip}",
                        description=(
                            f"{len(group)} failed logins were observed from {ip} within "
                            f"{window}s against {len(accounts)} account(s)."
                        ),
                        evidence={
                            "source_ip": ip,
                            "failed_attempts": len(group),
                            "window_seconds": window,
                            "threshold": limit,
                            "targeted_accounts": accounts,
                        },
                        events=group,
                        mitre=BUILTIN_BY_KEY["brute_force_source"].mitre,
                        source_ip=ip,
                    )
                )

    if account_rule and account_rule.enabled:
        by_account: dict[str, list[DetectionEvent]] = {}
        for event in failures:
            by_account.setdefault(event.username or "unknown", []).append(event)
        acct_limit = threshold("brute_force_account", "threshold", 8)
        for user, group in by_account.items():
            recent: list[DetectionEvent] = []
            for event in group:
                recent = [e for e in recent if (event.timestamp - e.timestamp).total_seconds() <= window]
                recent.append(event)
                if len(recent) == acct_limit:
                    result.append(
                        Candidate(
                            rule_key="brute_force_account",
                            rule_name=account_rule.name,
                            category="Brute Force",
                            severity=account_rule.severity,
                            confidence=0.8,
                            title=f"Repeated failed logins against {user}",
                            description=f"{acct_limit} failed logins targeted account '{user}' within {window}s.",
                            evidence={"username": user, "count": len(recent), "window_seconds": window},
                            events=recent,
                            mitre=BUILTIN_BY_KEY["brute_force_account"].mitre,
                            username=user,
                        )
                    )
                    break

    if spray_rule and spray_rule.enabled:
        min_accounts = threshold("password_spraying", "min_accounts", 3)
        for ip, group in _window(failures, window).items():
            accounts = {e.username for e in group if e.username}
            if len(accounts) >= min_accounts:
                result.append(
                    Candidate(
                        rule_key="password_spraying",
                        rule_name=spray_rule.name,
                        category="Brute Force",
                        severity=spray_rule.severity,
                        confidence=0.85,
                        title=f"Password spraying from {ip}",
                        description=f"{len(accounts)} distinct accounts were targeted from {ip} in {window}s.",
                        evidence={"source_ip": ip, "accounts": sorted(accounts), "window_seconds": window},
                        events=group,
                        mitre=BUILTIN_BY_KEY["password_spraying"].mitre,
                        source_ip=ip,
                    )
                )
    return result


def _login_candidates(events: list[DetectionEvent], rules: dict[str, DetectionRule]) -> list[Candidate]:
    result: list[Candidate] = []
    failures = [e for e in events if e.action == "failure"]
    successes = [e for e in events if e.action == "success"]
    rule = rules.get("login_after_failures")
    if rule and rule.enabled:
        min_failures = int((rule.thresholds or {}).get("min_failures", 3))
        window = int((rule.thresholds or {}).get("window_seconds", 600))
        for success in successes:
            prior = [
                e for e in failures
                if e.source_ip == success.source_ip
                and e.username == success.username
                and 0 <= (success.timestamp - e.timestamp).total_seconds() <= window
            ]
            if len(prior) >= min_failures:
                result.append(
                    Candidate(
                        rule_key="login_after_failures",
                        rule_name=rule.name,
                        category="Suspicious Login",
                        severity=rule.severity,
                        confidence=0.9,
                        title=f"Successful login after {len(prior)} failures ({success.username})",
                        description=(
                            f"Account '{success.username}' authenticated successfully from "
                            f"{success.source_ip} after {len(prior)} failed attempts. This may "
                            "indicate a successful password guess; verify with the account owner."
                        ),
                        evidence={
                            "username": success.username,
                            "source_ip": success.source_ip,
                            "failed_before_success": len(prior),
                            "window_seconds": window,
                        },
                        events=prior + [success],
                        mitre=BUILTIN_BY_KEY["login_after_failures"].mitre,
                        source_ip=success.source_ip,
                        username=success.username,
                        host=success.host,
                    )
                )

    rule = rules.get("privileged_unusual_source")
    if rule and rule.enabled:
        lookback = int((rule.thresholds or {}).get("lookback_days", 7))
        for success in successes:
            user = (success.username or "").lower()
            if user not in PRIVILEGED_USERS or not success.source_ip or is_private_ip(success.source_ip):
                continue
            prior_success = any(
                e.username == success.username
                and e.source_ip == success.source_ip
                and e.id != success.id
                and 0 <= (success.timestamp - e.timestamp).total_seconds() <= lookback * 86400
                for e in successes
            )
            if not prior_success:
                result.append(
                    Candidate(
                        rule_key="privileged_unusual_source",
                        rule_name=rule.name,
                        category="Suspicious Login",
                        severity=rule.severity,
                        confidence=0.65,
                        title=f"Privileged login from new external source ({success.username})",
                        description=(
                            f"Privileged account '{success.username}' authenticated from external "
                            f"IP {success.source_ip} with no prior successful login in {lookback} days. "
                            "Treat as a lead, not a confirmed compromise."
                        ),
                        evidence={
                            "username": success.username,
                            "source_ip": success.source_ip,
                            "first_seen": True,
                            "lookback_days": lookback,
                        },
                        events=[success],
                        mitre=BUILTIN_BY_KEY["privileged_unusual_source"].mitre,
                        source_ip=success.source_ip,
                        username=success.username,
                        host=success.host,
                    )
                )
    return result


def _network_candidates(
    events: list[DetectionEvent], rules: dict[str, DetectionRule], db: Session
) -> list[Candidate]:
    result: list[Candidate] = []
    network = [
        e for e in events
        if e.action == "network" or e.event_code in {"NET_OUTBOUND", "CONNECTION"}
        or "connection" in e.message.lower() or "outbound" in e.message.lower()
    ]
    if not network:
        return result

    malicious = set()
    for row in db.scalars(select(ThreatIntelResult).where(ThreatIntelResult.verdict == "malicious")):
        malicious.add(row.indicator)

    rule = rules.get("network_malicious_destination")
    if rule and rule.enabled:
        for event in network:
            indicator = event.destination_ip or event.source_ip
            if indicator and indicator in malicious:
                result.append(
                    Candidate(
                        rule_key="network_malicious_destination",
                        rule_name=rule.name,
                        category="Network Anomaly",
                        severity=rule.severity,
                        confidence=0.95,
                        title=f"Connection to malicious destination {indicator}",
                        description=f"An outbound connection to verified malicious indicator {indicator} was observed.",
                        evidence={"indicator": indicator, "intel_verdict": "malicious"},
                        events=[event],
                        mitre=BUILTIN_BY_KEY["network_malicious_destination"].mitre,
                        source_ip=event.source_ip,
                        host=event.host,
                    )
                )

    rule = rules.get("network_outbound_volume")
    if rule and rule.enabled:
        window = int((rule.thresholds or {}).get("window_seconds", 600))
        limit = int((rule.thresholds or {}).get("threshold", 20))
        for host, group in _network_by_host(network, window).items():
            if len(group) >= limit:
                result.append(
                    Candidate(
                        rule_key="network_outbound_volume",
                        rule_name=rule.name,
                        category="Network Anomaly",
                        severity=rule.severity,
                        confidence=0.7,
                        title=f"Unusual outbound connection volume from {host}",
                        description=f"{len(group)} outbound connections from {host} in {window}s.",
                        evidence={"host": host, "count": len(group), "window_seconds": window},
                        events=group,
                        mitre=BUILTIN_BY_KEY["network_outbound_volume"].mitre,
                        host=host,
                    )
                )

    rule = rules.get("network_suspicious_port")
    if rule and rule.enabled:
        ports = set((rule.thresholds or {}).get("ports", []))
        for event in network:
            text = f"{event.message} {event.payload.get('command', '')}".lower()
            hit = next((p for p in ports if re_word(str(p), text)), None)
            if hit:
                result.append(
                    Candidate(
                        rule_key="network_suspicious_port",
                        rule_name=rule.name,
                        category="Network Anomaly",
                        severity=rule.severity,
                        confidence=0.8,
                        title=f"Connection to suspicious port {hit}",
                        description=f"An outbound connection to port {hit} was observed from {event.host}.",
                        evidence={"port": hit, "host": event.host, "destination_ip": event.destination_ip},
                        events=[event],
                        mitre=BUILTIN_BY_KEY["network_suspicious_port"].mitre,
                        source_ip=event.source_ip,
                        host=event.host,
                    )
                )
    return result


def re_word(port: str, text: str) -> bool:
    import re
    return bool(re.search(rf"\b{re.escape(port)}\b", text))


def _network_by_host(events: list[DetectionEvent], window: int) -> dict[str, list[DetectionEvent]]:
    buckets: dict[str, list[DetectionEvent]] = {}
    for event in events:
        host = event.host or "unknown"
        bucket = [e for e in buckets.get(host, []) if (event.timestamp - e.timestamp).total_seconds() <= window]
        bucket.append(event)
        buckets[host] = bucket
    return buckets


def _process_and_privilege_candidates(events: list[DetectionEvent], rules: dict[str, DetectionRule]) -> list[Candidate]:
    result: list[Candidate] = []
    rule = rules.get("suspicious_process")
    if rule and rule.enabled:
        patterns = [str(p).lower() for p in (rule.thresholds or {}).get("patterns", [])]
        for event in events:
            if event.action not in {"process", "unknown"}:
                continue
            text = f"{event.message} {event.payload.get('command', '')}".lower()
            hits = [p for p in patterns if p in text]
            if hits and (event.action == "process" or len(hits) >= 2):
                result.append(
                    Candidate(
                        rule_key="suspicious_process",
                        rule_name=rule.name,
                        category="Suspicious Process",
                        severity=rule.severity,
                        confidence=0.8,
                        title=f"Suspicious command execution on {event.host}",
                        description=(
                            f"Command execution matched suspicious pattern(s): {', '.join(hits)}. "
                            "Verify the process owner and business justification."
                        ),
                        evidence={"matched_patterns": hits, "command": event.message[:300]},
                        events=[event],
                        mitre=BUILTIN_BY_KEY["suspicious_process"].mitre,
                        username=event.username,
                        host=event.host,
                        source_ip=event.source_ip,
                    )
                )

    rule = rules.get("privilege_assignment")
    if rule and rule.enabled:
        for event in events:
            if event.event_code == "4672" and (event.username or "").lower() not in {"system", "local system"}:
                external = event.source_ip and not is_private_ip(event.source_ip)
                if external:
                    result.append(
                        Candidate(
                            rule_key="privilege_assignment",
                            rule_name=rule.name,
                            category="Privilege Escalation",
                            severity=rule.severity,
                            confidence=0.7,
                            title=f"Administrative privileges assigned to {event.username}",
                            description="Special privileges were assigned following an external logon.",
                            evidence={"username": event.username, "source_ip": event.source_ip},
                            events=[event],
                            mitre=BUILTIN_BY_KEY["privilege_assignment"].mitre,
                            username=event.username,
                            source_ip=event.source_ip,
                            host=event.host,
                        )
                    )

    rule = rules.get("account_manipulation")
    if rule and rule.enabled:
        groups = {str(g).lower() for g in (rule.thresholds or {}).get("privileged_groups", [])}
        for event in events:
            payload_group = str(event.payload.get("group", "")).lower()
            if event.event_code in {"USER_CREATED", "GROUP_ADD", "4732"} or (
                event.action == "privilege" and payload_group in groups
            ):
                privileged = event.event_code in {"USER_CREATED", "4732"} or payload_group in groups
                if privileged:
                    result.append(
                        Candidate(
                            rule_key="account_manipulation",
                            rule_name=rule.name,
                            category="Privilege Escalation",
                            severity=rule.severity,
                            confidence=0.85,
                            title=f"Privileged account manipulation by {event.username}",
                            description="A privileged account or group membership change was observed.",
                            evidence={"username": event.username, "group": payload_group or None},
                            events=[event],
                            mitre=BUILTIN_BY_KEY["account_manipulation"].mitre,
                            username=event.username,
                            host=event.host,
                        )
                    )
    return result


def ensure_builtin_rules(db: Session) -> None:
    """Create/update built-in rules without overwriting operator changes."""
    existing = {r.name: r for r in db.scalars(select(DetectionRule)).all()}
    for builtin in BUILTIN_RULES:
        rule = existing.get(builtin.name)
        if rule is None:
            db.add(
                DetectionRule(
                    name=builtin.name,
                    category=builtin.category,
                    description=builtin.description,
                    severity=builtin.severity,
                    enabled=True,
                    thresholds=builtin.thresholds,
                    mitre=builtin.mitre,
                    source="builtin",
                )
            )
        else:
            # Keep enabled/severity/thresholds as configured by the operator;
            # refresh documentation and MITRE mapping only.
            rule.description = builtin.description
            rule.mitre = builtin.mitre
    db.commit()


def _persist(db: Session, candidates: list[Candidate]) -> dict[str, int]:
    created = 0
    for candidate in candidates:
        if not candidate.events:
            continue
        event_uids = sorted({e.event_uid for e in candidate.events})
        bucket = candidate.events[0].timestamp.strftime("%Y%m%d%H")
        fingerprint = canonical_hash(
            {
                "rule": candidate.rule_key,
                "ip": candidate.source_ip,
                "user": candidate.username,
                "host": candidate.host,
                "events": event_uids,
            }
        )
        alert_uid = sha256_text(f"{candidate.rule_key}|{fingerprint}|{bucket}")[:40]
        if db.scalar(select(Alert.id).where(Alert.alert_uid == alert_uid)):
            continue
        evidence = dict(candidate.evidence)
        evidence["fingerprint"] = fingerprint
        evidence["event_uids"] = event_uids
        db.add(
            Alert(
                alert_uid=alert_uid,
                rule_name=candidate.rule_name,
                category=candidate.category,
                severity=candidate.severity,
                confidence=round(candidate.confidence, 2),
                title=candidate.title[:255],
                description=candidate.description,
                evidence=evidence,
                event_ids=event_uids,
                mitre=candidate.mitre,
                source_ip=candidate.source_ip,
                username=candidate.username,
                host=candidate.host,
            )
        )
        created += 1
    if created:
        db.commit()
    return {"created": created, "evaluated": len(candidates)}


def run_detection(db: Session, since_minutes: int | None = None) -> dict[str, Any]:
    """Run all enabled built-in and Sigma rules, returning a summary."""
    ensure_builtin_rules(db)
    events = _ordered(db, since_minutes)
    name_to_key = {builtin.name: builtin.key for builtin in BUILTIN_RULES}
    rules: dict[str, DetectionRule] = {}
    for row in db.scalars(select(DetectionRule)).all():
        rules[name_to_key.get(row.name, row.name)] = row
    candidates: list[Candidate] = []

    candidates += _failure_candidates(events, rules)
    candidates += _login_candidates(events, rules)
    candidates += _network_candidates(events, rules, db)
    candidates += _process_and_privilege_candidates(events, rules)

    for rule_row in db.scalars(
        select(DetectionRule).where(DetectionRule.source == "sigma", DetectionRule.enabled.is_(True))
    ):
        try:
            sigma = parse_sigma_rule(rule_row.definition)
        except ValueError:
            continue
        for match in evaluate_sigma_rule(sigma, events):
            matched: list[DetectionEvent] = match["events"]
            candidates.append(
                Candidate(
                    rule_key="sigma:" + sigma.rule_id,
                    rule_name=rule_row.name,
                    category="Sigma",
                    severity=rule_row.severity,
                    confidence=0.75,
                    title=f"Sigma match: {sigma.title}",
                    description=sigma.description or f"Sigma rule {sigma.title} matched collected events.",
                    evidence=match["evidence"],
                    events=matched,
                    mitre=sigma.tags,
                    source_ip=matched[-1].source_ip if matched else None,
                    username=matched[-1].username if matched else None,
                    host=matched[-1].host if matched else None,
                )
            )

    summary = _persist(db, candidates)
    summary["events_evaluated"] = len(events)
    summary["alerts_total"] = db.scalar(select(func.count()).select_from(Alert)) or 0
    return summary
