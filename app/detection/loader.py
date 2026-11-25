"""Load bundled Sigma rules into the database."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import BASE_DIR
from ..models import DetectionRule
from .sigma import parse_sigma_rule

SIGMA_DIR = BASE_DIR / "data" / "sigma"


def load_bundled_sigma(db: Session) -> int:
    loaded = 0
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        definition = path.read_text(encoding="utf-8")
        rule = parse_sigma_rule(definition)
        existing = db.scalar(select(DetectionRule).where(DetectionRule.name == rule.title))
        if existing:
            existing.definition = definition
            existing.source = "sigma"
            existing.mitre = rule.tags
            existing.severity = rule.level
            continue
        db.add(
            DetectionRule(
                name=rule.title,
                category="Sigma",
                description=rule.description,
                severity=rule.level,
                enabled=True,
                thresholds={},
                mitre=rule.tags,
                source="sigma",
                definition=definition,
            )
        )
        loaded += 1
    db.commit()
    return loaded
