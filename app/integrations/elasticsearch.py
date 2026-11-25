"""Optional Elasticsearch integration for advanced log management.

Disabled unless ELASTICSEARCH_URL is configured. Failures are logged and never
block the local SQLite workflow.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import settings
from ..models import SecurityEvent


class ElasticClient:
    def __init__(self):
        self.url = settings.elasticsearch_url.rstrip("/")
        self.index = settings.elasticsearch_index
        self.enabled = bool(self.url)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if settings.elasticsearch_api_key:
            headers["Authorization"] = f"ApiKey {settings.elasticsearch_api_key}"
        return headers

    def index_events(self, events: list[SecurityEvent]) -> bool:
        if not self.enabled or not events:
            return False
        lines: list[str] = []
        for event in events:
            lines.append(json.dumps({"index": {"_index": self.index, "_id": event.event_uid}}))
            lines.append(
                json.dumps(
                    {
                        "event_uid": event.event_uid,
                        "source_type": event.source_type,
                        "event_code": event.event_code,
                        "action": event.action,
                        "username": event.username,
                        "source_ip": event.source_ip,
                        "host": event.host,
                        "timestamp": event.timestamp.isoformat() + "Z",
                        "message": event.message,
                    },
                    default=str,
                )
            )
        try:
            response = httpx.post(
                f"{self.url}/_bulk",
                headers=self._headers(),
                content=("\n".join(lines) + "\n").encode("utf-8"),
                timeout=10,
            )
            response.raise_for_status()
            return not response.json().get("errors", False)
        except (httpx.HTTPError, ValueError):
            return False

    def search(self, query: str, size: int = 20) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        try:
            response = httpx.get(
                f"{self.url}/{self.index}/_search",
                headers=self._headers(),
                params={"q": query, "size": size},
                timeout=10,
            )
            response.raise_for_status()
            return [hit["_source"] for hit in response.json().get("hits", {}).get("hits", [])]
        except (httpx.HTTPError, ValueError, KeyError):
            return []
