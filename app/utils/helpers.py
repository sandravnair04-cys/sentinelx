"""Hashing, indicator classification and safe serialisation helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from typing import Any

from .timeutil import iso


def sha256_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def canonical_hash(payload: Any) -> str:
    """Stable hash of any JSON-serialisable object (for evidence / dedupe)."""
    raw = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256_text(raw)




def classify_indicator(value: str) -> str | None:
    """Return ip / domain / md5 / sha1 / sha256 / unknown for a lookup value."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return "md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "sha256"
    if re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", value):
        return "domain"
    return None


def is_private_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def json_safe(value: Any) -> Any:
    """Convert ORM/date/pydantic objects into JSON-serialisable structures."""
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    if isinstance(value, datetime):
        return iso(value)
    if hasattr(value, "model_dump"):
        return json_safe(value.model_dump())
    if hasattr(value, "__dict__") and not isinstance(value, (str, int, float, bool)):
        return {
            k: json_safe(v)
            for k, v in vars(value).items()
            if not k.startswith("_")
        }
    return value


def severity_rank(severity: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(
        str(severity).upper(), 0
    )


def severity_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, round(float(value), 2)))
