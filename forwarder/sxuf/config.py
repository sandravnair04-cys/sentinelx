"""Forwarder configuration loading and validation.

Only explicitly configured log sources are collected. A deny-list prevents
accidental collection of credential material even if someone adds a path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DENIED_PATH_FRAGMENTS = (
    "/etc/shadow",
    "/etc/gshadow",
    ".ssh/",
    ".aws/",
    ".kube/",
    "id_rsa",
    ".npmrc",
    ".pypirc",
    "credentials",
    "cookie",
    "browser",
    "keychain",
)
SUPPORTED_KINDS = {"file", "journal", "windows_event"}


class ConfigError(ValueError):
    """Raised when the forwarder configuration is invalid or unsafe."""


@dataclass
class SourceConfig:
    kind: str
    name: str
    path: str = ""
    channel: str = "Security"
    event_ids: list[int] = field(default_factory=list)
    poll_seconds: float = 2.0
    batch_size: int = 64

    def __post_init__(self) -> None:
        self.kind = self.kind.lower()
        if self.kind not in SUPPORTED_KINDS:
            raise ConfigError(f"Unsupported source kind: {self.kind}")
        if not self.name:
            raise ConfigError("Every source needs a name")
        if self.kind == "file":
            if not self.path:
                raise ConfigError(f"File source '{self.name}' needs a path")
            lowered = self.path.replace("\\", "/").lower()
            if any(fragment in lowered for fragment in DENIED_PATH_FRAGMENTS):
                raise ConfigError(f"Refusing to collect sensitive path: {self.path}")
        self.poll_seconds = max(0.2, min(3600.0, float(self.poll_seconds)))
        self.batch_size = max(1, min(1000, int(self.batch_size)))


@dataclass
class Config:
    agent_id: str
    agent_key: str
    server_url: str
    key_file: str = ""
    hostname: str = ""
    os_type: str = ""
    tls_verify: bool = True
    ca_bundle: str = ""
    timeout_seconds: float = 15.0
    batch_size: int = 100
    heartbeat_seconds: int = 60
    flush_seconds: float = 5.0
    max_buffer_events: int = 50_000
    max_retries: int = 5
    state_dir: str = "state"
    sources: list[SourceConfig] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.agent_id = str(self.agent_id).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,100}", self.agent_id):
            raise ConfigError("agent_id must be 3-100 chars of A-Z a-z 0-9 . _ -")
        if not self.agent_key:
            raise ConfigError("agent_key is required (register the agent on the server first)")
        if not self.server_url.startswith(("https://", "http://")):
            raise ConfigError("server_url must start with https:// or http://")
        if self.server_url.startswith("http://") and "localhost" not in self.server_url and "127.0.0.1" not in self.server_url:
            raise ConfigError("Refusing plaintext HTTP except for localhost lab use")
        if not self.tls_verify:
            # Explicit opt-in only, and never silently accepted.
            if os.environ.get("SXUF_ALLOW_INSECURE_TLS") != "1":
                raise ConfigError("tls_verify=false requires SXUF_ALLOW_INSECURE_TLS=1")
        if not self.hostname:
            if hasattr(os, "uname"):
                self.hostname = os.uname().nodename
            else:
                self.hostname = os.environ.get("COMPUTERNAME", "unknown-host")
        self.timeout_seconds = max(1.0, min(120.0, float(self.timeout_seconds)))
        self.batch_size = max(1, min(1000, int(self.batch_size)))
        self.heartbeat_seconds = max(5, min(3600, int(self.heartbeat_seconds)))
        self.max_retries = max(0, min(20, int(self.max_retries)))

    @property
    def headers(self) -> dict[str, str]:
        return {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Key": self.agent_key,
            "Content-Type": "application/json",
            "User-Agent": f"SXUF/{__import__('sxuf').__version__}",
        }

    @property
    def state_path(self) -> Path:
        return Path(self.state_dir).expanduser().resolve()

    def fingerprint(self) -> str:
        """Stable hash of non-secret settings for server-side config tracking."""
        material = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "server": self.server_url.rstrip("/"),
            "sources": [
                {"kind": s.kind, "name": s.name, "path": s.path, "channel": s.channel,
                 "event_ids": s.event_ids}
                for s in self.sources
            ],
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def load_config(path: str | Path) -> Config:
    config_path = Path(path).expanduser().resolve()
    if not config_path.is_file():
        raise ConfigError(f"Configuration file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        raw: dict[str, Any] = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise ConfigError("Configuration root must be a mapping")

    agent = raw.get("agent", {}) or {}
    server = raw.get("server", {}) or {}
    endpoint = raw.get("endpoint", {}) or {}
    runtime = raw.get("runtime", {}) or {}
    raw_sources = raw.get("sources", []) or []
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ConfigError("At least one explicitly configured source is required")

    key_file = str(agent.get("key_file", "") or "")
    agent_key = os.environ.get("SXUF_AGENT_KEY", "") or str(agent.get("key", ""))
    if not agent_key and key_file:
        secret_path = Path(key_file).expanduser()
        if not secret_path.is_absolute():
            secret_path = config_path.parent / secret_path
        if not secret_path.is_file():
            raise ConfigError(f"Agent key file not found: {secret_path}")
        agent_key = secret_path.read_text(encoding="utf-8").strip()
    try:
        sources = [SourceConfig(**dict(item)) for item in raw_sources]
    except TypeError as exc:
        raise ConfigError(f"Invalid source configuration: {exc}") from exc
    return Config(
        agent_id=str(agent.get("id", "")),
        agent_key=agent_key,
        key_file=key_file,
        server_url=str(server.get("url", "")),
        hostname=str(endpoint.get("hostname", "")),
        os_type=str(endpoint.get("os_type", "")),
        tls_verify=bool(server.get("tls_verify", True)),
        ca_bundle=str(server.get("ca_bundle", "")),
        timeout_seconds=float(server.get("timeout_seconds", 15)),
        batch_size=int(runtime.get("batch_size", 100)),
        heartbeat_seconds=int(runtime.get("heartbeat_seconds", 60)),
        flush_seconds=float(runtime.get("flush_seconds", 5)),
        max_buffer_events=int(runtime.get("max_buffer_events", 50_000)),
        max_retries=int(runtime.get("max_retries", 5)),
        state_dir=str(runtime.get("state_dir", "state")),
        sources=sources,
    )
