"""Detection rule and alert endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...database import get_db
from ...detection import ensure_builtin_rules, load_bundled_sigma, run_detection
from ...models import Alert, DetectionRule
from ...schemas import RuleUpdate
from ...security import require_admin, require_analyst

router = APIRouter(tags=["Detection"])


def _rule_out(rule: DetectionRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "category": rule.category,
        "description": rule.description,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "thresholds": rule.thresholds,
        "mitre": rule.mitre,
        "source": rule.source,
        "updated_at": rule.updated_at.isoformat() + "Z" if rule.updated_at else None,
    }


def _alert_out(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "alert_uid": alert.alert_uid,
        "rule_name": alert.rule_name,
        "category": alert.category,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "title": alert.title,
        "description": alert.description,
        "evidence": alert.evidence,
        "event_ids": alert.event_ids,
        "mitre": alert.mitre,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "host": alert.host,
        "status": alert.status,
        "correlated": alert.correlated,
        "created_at": alert.created_at.isoformat() + "Z",
    }


@router.get("/detection/rules")
def list_rules(db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    ensure_builtin_rules(db)
    rules = list(db.scalars(select(DetectionRule).order_by(DetectionRule.name)).all())
    return {"items": [_rule_out(r) for r in rules]}


@router.patch("/detection/rules/{rule_id}")
def update_rule(
    rule_id: int, payload: RuleUpdate, db: Session = Depends(get_db), _admin=Depends(require_admin)
) -> dict:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.severity is not None:
        if payload.severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=400, detail="Invalid severity")
        rule.severity = payload.severity
    if payload.thresholds is not None:
        rule.thresholds = {**(rule.thresholds or {}), **payload.thresholds}
    db.commit()
    db.refresh(rule)
    return _rule_out(rule)


@router.post("/detection/sigma/reload")
def reload_sigma(db: Session = Depends(get_db), _admin=Depends(require_admin)) -> dict:
    return {"loaded": load_bundled_sigma(db)}


@router.post("/detection/run")
def run(db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    return run_detection(db)


@router.get("/alerts")
def list_alerts(
    limit: int = 100,
    offset: int = 0,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
) -> dict:
    limit, offset = max(1, min(500, limit)), max(0, offset)
    query = select(Alert)
    if severity:
        query = query.where(Alert.severity == severity.upper())
    if category:
        query = query.where(Alert.category == category)
    if status:
        query = query.where(Alert.status == status)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(db.scalars(query.order_by(Alert.created_at.desc()).offset(offset).limit(limit)).all())
    return {"total": total, "items": [_alert_out(a) for a in rows]}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_out(alert)


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: int, payload: dict, db: Session = Depends(get_db), _user=Depends(require_analyst)
) -> dict:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    status_value = str(payload.get("status", ""))
    if status_value not in {"new", "acknowledged", "closed"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    alert.status = status_value
    db.commit()
    return _alert_out(alert)
