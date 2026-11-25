"""Central configuration for SENTINELX.

All secrets are read from environment variables (optionally a local .env file).
Nothing sensitive is hardcoded. See .env.example for the full list.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = Path(__file__).resolve().parent / "static"
FRONTEND_DIST_DIR = BASE_DIR / "frontend" / "dist"


class Settings(BaseSettings):
    """Application settings loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "SENTINELX"
    app_env: str = "development"
    debug: bool = True
    secret_key: str = "dev-only-insecure-secret-change-me"
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    database_url: str = "sqlite:///./data/sentinelx.db"
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"

    login_rate_limit: int = 5
    login_rate_window_seconds: int = 60

    seed_demo_data: bool = True
    simulation_mode: bool = True

    brute_force_window_seconds: int = 300
    brute_force_threshold: int = 5
    failed_success_window_seconds: int = 600
    max_sigma_alerts_per_run: int = 500

    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: int = 20
    llm_temperature: float = 0.0

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    threat_intel_timeout_seconds: int = 10
    threat_intel_cache_ttl_seconds: int = 86400

    elasticsearch_url: str = ""
    elasticsearch_index: str = "sentinelx-events"
    elasticsearch_api_key: str = ""

    wazuh_url: str = ""
    wazuh_user: str = ""
    wazuh_password: str = ""
    wazuh_verify_tls: bool = True

    response_execution_enabled: bool = False

    # SXUF forwarder registry
    forwarder_offline_after_seconds: int = 300
    agent_key_default_ttl_days: int = 365
    log_retention_days: int = 90
    auto_process_forwarded: bool = True

    @field_validator("database_url")
    @classmethod
    def _normalise_db_url(cls, value: str) -> str:
        """Make relative SQLite paths absolute so cwd never matters."""
        if value.startswith("sqlite:///") and not value.startswith("sqlite:////"):
            relative = value[len("sqlite:///") :]
            if not os.path.isabs(relative):
                # Relative paths are resolved from the project root. The default
                # is ./data/sentinelx.db.
                return f"sqlite:///{BASE_DIR / relative.lstrip('./')}"
        return value

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key)

    @property
    def threat_intel_enabled(self) -> bool:
        return bool(self.virustotal_api_key or self.abuseipdb_api_key)

    @property
    def elasticsearch_enabled(self) -> bool:
        return bool(self.elasticsearch_url)

    @property
    def wazuh_enabled(self) -> bool:
        return bool(self.wazuh_url and self.wazuh_user and self.wazuh_password)

    def public_dict(self) -> dict:
        """Non-secret settings safe to return to the UI."""
        return {
            "app_name": self.app_name,
            "app_env": self.app_env,
            "database": self.database_url.split("://")[0],
            "llm_mode": "api" if self.llm_enabled else "fallback",
            "llm_model": self.llm_model if self.llm_enabled else None,
            "threat_intel_enabled": self.threat_intel_enabled,
            "elasticsearch_enabled": self.elasticsearch_enabled,
            "wazuh_enabled": self.wazuh_enabled,
            "response_execution_enabled": self.response_execution_enabled,
            "simulation_mode": self.simulation_mode,
            "brute_force_window_seconds": self.brute_force_window_seconds,
            "brute_force_threshold": self.brute_force_threshold,
            "failed_success_window_seconds": self.failed_success_window_seconds,
            "forwarder_offline_after_seconds": self.forwarder_offline_after_seconds,
            "log_retention_days": self.log_retention_days,
            "auto_process_forwarded": self.auto_process_forwarded,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
