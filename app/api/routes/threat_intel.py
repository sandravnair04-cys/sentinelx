"""Threat intelligence lookup endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...schemas import IntelLookup
from ...security import require_analyst
from ...threat_intel.service import list_results, lookup

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.post("/lookup")
def lookup_indicator(
    payload: IntelLookup, db: Session = Depends(get_db), _user=Depends(require_analyst)
) -> dict:
    return lookup(db, payload.indicator, payload.indicator_type)


@router.get("/results")
def results(limit: int = 50, db: Session = Depends(get_db), _user=Depends(require_analyst)) -> dict:
    return {"items": list_results(db, min(200, limit))}


@router.get("/status")
def status(_user=Depends(require_analyst)) -> dict:
    return {
        "virustotal_configured": bool(settings.virustotal_api_key),
        "abuseipdb_configured": bool(settings.abuseipdb_api_key),
        "enabled": settings.threat_intel_enabled,
        "cache_ttl_seconds": settings.threat_intel_cache_ttl_seconds,
        "supported_types": ["ip", "domain", "md5", "sha1", "sha256"],
        "note": "Unknown results do not mean clean. No files are uploaded to third parties.",
    }
