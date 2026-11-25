"""HTTPS transport with bounded retries and agent authentication."""

from __future__ import annotations

import random
import time
import uuid
from typing import Any

import httpx

from .config import Config


class TransportError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, fatal: bool = False):
        super().__init__(message)
        self.status = status
        self.fatal = fatal


class Transport:
    def __init__(self, config: Config, health: Any | None = None):
        self.config = config
        self.health = health
        verify: bool | str = config.ca_bundle or config.tls_verify
        self._client = httpx.Client(
            timeout=config.timeout_seconds,
            verify=verify,
            headers=config.headers,
            follow_redirects=False,
        )
        self._base = config.server_url.rstrip("/")

    def close(self) -> None:
        self._client.close()

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self._base}{path}"
        for attempt in range(self.config.max_retries + 1):
            try:
                response = self._client.post(url, json=payload)
            except httpx.HTTPError as exc:
                if attempt >= self.config.max_retries:
                    raise TransportError(f"Network error: {exc}") from exc
                delay = min(30.0, 2**attempt) + random.uniform(0, 0.5)
                time.sleep(delay)
                continue

            if response.status_code in (200, 201, 202):
                try:
                    return response.json()
                except ValueError:
                    return {"status": "ok"}

            if response.status_code in (400, 401, 403, 404, 422):
                raise TransportError(
                    f"Server rejected request ({response.status_code}): {response.text[:300]}",
                    status=response.status_code,
                    fatal=response.status_code in (401, 403),
                )
            if attempt >= self.config.max_retries:
                raise TransportError(
                    f"Server error ({response.status_code}): {response.text[:300]}",
                    status=response.status_code,
                )
            retry_after = response.headers.get("retry-after", "")
            try:
                delay = min(60.0, float(retry_after)) if retry_after else min(30.0, 2**attempt)
            except ValueError:
                delay = min(30.0, 2**attempt)
            time.sleep(delay + random.uniform(0, 0.5))
        raise TransportError("Retry budget exhausted")

    def send_batch(self, events: list[dict[str, Any]]) -> dict:
        return self._post(
            "/api/ingest/batch",
            {"batch_id": str(uuid.uuid4()), "events": events},
        )

    def send_heartbeat(self, payload: dict[str, Any]) -> dict:
        return self._post("/api/ingest/heartbeat", payload)
