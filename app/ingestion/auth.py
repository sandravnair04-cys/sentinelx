"""Scoped authentication for SXUF forwarders.

The forwarder presents ``X-Agent-ID`` and ``X-Agent-Key`` on every request.
Only a SHA-256 hash of the key is stored server-side, so a database leak does
not reveal usable credentials. Comparisons use ``hmac.compare_digest`` and
failed attempts are rate-limited per source IP + agent id.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AgentCredential
from ..security import check_rate_limit, client_ip, reset_rate_limit

_UNAUTHORIZED = "Invalid agent credentials"


def generate_agent_key() -> str:
    """Return a high-entropy one-time credential (displayed to the admin once)."""
    return "sxuf_" + secrets.token_urlsafe(32)


def hash_agent_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _presented_key(request: Request) -> str:
    key = request.headers.get("x-agent-key", "")
    if key:
        return key
    header = request.headers.get("authorization", "")
    if header.lower().startswith("agent "):
        return header.split(" ", 1)[1].strip()
    return ""


def require_agent(scope: str) -> Callable:
    """Build a FastAPI dependency requiring the given agent scope."""

    def dependency(
        request: Request, db: Session = Depends(get_db)
    ) -> AgentCredential:
        agent_id = (request.headers.get("x-agent-id") or "").strip()
        key = _presented_key(request)
        ip = client_ip(request)
        rate_key = f"agent-auth:{ip}:{agent_id or 'missing'}"

        if not agent_id or not key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_UNAUTHORIZED)
        if not check_rate_limit(rate_key, limit=10, window=60):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed agent authentications")

        credential = db.scalar(select(AgentCredential).where(AgentCredential.agent_id == agent_id))
        valid = credential is not None
        if valid and credential.status != "active":
            valid = False
        if valid and credential.expires_at and credential.expires_at <= datetime.utcnow():
            valid = False
        if valid and scope not in (credential.scopes or []):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Agent scope '{scope}' required")
        if valid and not hmac.compare_digest(hash_agent_key(key), credential.key_hash):
            valid = False

        if not valid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_UNAUTHORIZED)

        credential.last_used_at = datetime.utcnow()
        db.commit()
        reset_rate_limit(rate_key)
        return credential

    return dependency
