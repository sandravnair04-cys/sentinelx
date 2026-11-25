"""MITRE ATT&CK explorer built on the bundled curated technique subset."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import Alert, Incident
from ...security import require_viewer

router = APIRouter(tags=["MITRE ATT&CK"])

_DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "mitre_attack.json"


def _load() -> dict:
    with _DATA_FILE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


_TECHNIQUE_RE = re.compile(r"^\s*(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _normalise_id(value: str) -> str | None:
    """Extract a bare technique ID from labels like 'T1110.003 - Password Spraying'."""
    match = _TECHNIQUE_RE.match(value)
    return match.group(1).upper() if match else None


def _flatten_ids(value) -> list[str]:
    """MITRE mappings are stored as strings or dicts in alerts/incidents."""
    ids: list[str] = []
    if isinstance(value, str):
        normalised = _normalise_id(value)
        return [normalised] if normalised else []
    if isinstance(value, dict):
        candidates = [value.get("id"), value.get("technique"), value.get("tactic"), value.get("value")]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate:
                normalised = _normalise_id(candidate)
                if normalised:
                    ids.append(normalised)
        return ids
    if isinstance(value, (list, tuple)):
        for item in value:
            ids.extend(_flatten_ids(item))
    return ids


@router.get("/mitre/tactics")
def tactics(_user=Depends(require_viewer)) -> dict:
    data = _load()
    return {"version": data["version"], "note": data["note"], "items": data["tactics"]}


@router.get("/mitre/techniques")
def techniques(
    tactic: str | None = None,
    search: str | None = None,
    _user=Depends(require_viewer),
) -> dict:
    data = _load()
    items = data["techniques"]
    if tactic:
        items = [item for item in items if tactic in item.get("tactics", [])]
    if search:
        needle = search.lower()
        items = [
            item
            for item in items
            if needle in item["id"].lower()
            or needle in item["name"].lower()
            or needle in item.get("description", "").lower()
        ]
    return {"total": len(items), "items": items}


@router.get("/mitre/techniques/{technique_id}")
def technique(technique_id: str, _user=Depends(require_viewer)) -> dict:
    for item in _load()["techniques"]:
        if item["id"].upper() == technique_id.upper():
            return item
    raise HTTPException(status_code=404, detail="Technique not found in bundled subset")


@router.get("/mitre/coverage")
def coverage(db: Session = Depends(get_db), _user=Depends(require_viewer)) -> dict:
    """Which catalogue techniques have actually appeared in local alerts/incidents."""
    data = _load()
    catalogue = {item["id"].upper(): item for item in data["techniques"]}
    observed: Counter[str] = Counter()
    for (mapping,) in db.execute(select(Alert.mitre)).all():
        observed.update(_flatten_ids(mapping))
    for (mapping,) in db.execute(select(Incident.mitre)).all():
        observed.update(_flatten_ids(mapping))

    covered = []
    for technique_id, count in observed.items():
        item = catalogue.get(technique_id.upper())
        if item:
            covered.append({**item, "observations": count})
        else:
            covered.append(
                {"id": technique_id, "name": "External / custom technique", "tactics": [],
                 "description": "Observed locally but not part of the bundled curated subset.",
                 "observations": count}
            )
    covered.sort(key=lambda item: (-item["observations"], item["id"]))
    return {
        "catalogue_size": len(catalogue),
        "covered_count": len(covered),
        "coverage_percent": round(100 * len(covered) / max(1, len(catalogue)), 1),
        "items": covered,
        "note": "Coverage reflects local alert/incident mappings only; absence does not prove absence of adversary activity.",
    }
