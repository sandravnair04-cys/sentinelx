"""Optional Wazuh integration.

Two capabilities:
  1. ``parse_wazuh_alert`` converts a Wazuh JSON alert (filebeat/alert format)
     into a normalised SENTINELX event. Works offline with sample files.
  2. ``WazuhClient`` can fetch alerts from a Wazuh API when URL/credentials are
     configured. It is disabled by default and never runs automatically.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import settings
from ..utils.timeutil import to_utc_naive
from .normalizer import NormalizedEvent


def parse_wazuh_alert(payload: dict[str, Any], source_name: str = "wazuh") -> NormalizedEvent | None:
    data = payload.get("data", payload)
    rule = payload.get("rule", data.get("rule", {}))
    agent = payload.get("agent", data.get("agent", {}))
    timestamp = payload.get("@timestamp") or payload.get("timestamp")
    if not timestamp:
        return None
    rule_id = str(rule.get("id", data.get("event_id", "WAZUH")))
    level = int(rule.get("level", 0) or 0)
    description = str(rule.get("description", "Wazuh alert"))
    src_ip = data.get("srcip") or data.get("source_ip")
    user = data.get("dstuser") or data.get("user")
    host = agent.get("name") or data.get("hostname")
    if level >= 10 or "privilege" in description.lower():
        action = "privilege"
    elif "failed" in description.lower() or level >= 5:
        action = "failure"
    elif "success" in description.lower() or "accepted" in description.lower():
        action = "success"
    else:
        action = "unknown"
    return NormalizedEvent(
        source_type="wazuh",
        source_name=source_name,
        event_code=f"WAZUH-{rule_id}",
        timestamp=to_utc_naive(timestamp),
        action=action,
        username=user,
        source_ip=src_ip,
        host=host,
        message=description[:500],
        raw_event=json.dumps(payload)[:4000],
        confidence=0.8,
        extra={"wazuh_level": level, "rule_groups": rule.get("groups", [])},
    )


def parse_wazuh_alerts(text: str, source_name: str = "wazuh") -> list[NormalizedEvent]:
    payload: Any = json.loads(text)
    rows = payload if isinstance(payload, list) else payload.get("alerts", [payload])
    events: list[NormalizedEvent] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        # Filebeat wraps alerts in {"message": "{...}"}
        if isinstance(row.get("message"), str) and row["message"].strip().startswith("{"):
            try:
                row = json.loads(row["message"])
            except json.JSONDecodeError:
                pass
        event = parse_wazuh_alert(row, source_name)
        if event:
            events.append(event)
    return events


class WazuhClient:
    """Thin, optional Wazuh API client. Never used unless explicitly called."""

    def __init__(self, base_url: str | None = None, user: str | None = None, password: str | None = None):
        self.base_url = (base_url or settings.wazuh_url).rstrip("/")
        self.user = user or settings.wazuh_user
        self.password = password or settings.wazuh_password
        self._token: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.user and self.password)

    def authenticate(self) -> bool:
        if not self.configured:
            return False
        try:
            response = httpx.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.user, self.password),
                timeout=10,
                verify=settings.wazuh_verify_tls,
            )
            response.raise_for_status()
            self._token = response.json().get("data", {}).get("token")
            return bool(self._token)
        except (httpx.HTTPError, ValueError):
            return False

    def fetch_alerts(self, limit: int = 100) -> list[NormalizedEvent]:
        if not self.configured:
            return []
        if not self._token and not self.authenticate():
            return []
        try:
            response = httpx.get(
                f"{self.base_url}/alerts",
                headers={"Authorization": f"Bearer {self._token}"},
                params={"limit": limit, "sort": "-timestamp"},
                timeout=15,
                verify=settings.wazuh_verify_tls,
            )
            response.raise_for_status()
            payload = response.json().get("data", {}).get("alerts", [])
            result = []
            for row in payload:
                event = parse_wazuh_alert(row)
                if event:
                    result.append(event)
            return result
        except (httpx.HTTPError, ValueError):
            return []
