"""Optional VirusTotal and AbuseIPDB providers.

API keys are read from environment variables only. No file or log content is
ever uploaded to a third party. Failed/rate-limited requests degrade to
'unknown' rather than producing a false 'clean' verdict.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..config import settings


class LookupError_(Exception):
    pass


class VirusTotalProvider:
    name = "virustotal"

    @property
    def enabled(self) -> bool:
        return bool(settings.virustotal_api_key)

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if not self.enabled:
            raise LookupError_("VirusTotal API key not configured")
        if indicator_type == "ip":
            path = f"ip_addresses/{indicator}"
        elif indicator_type == "domain":
            path = f"domains/{indicator}"
        elif indicator_type in {"md5", "sha1", "sha256"}:
            path = f"file/{indicator}"
        else:
            raise LookupError_(f"Unsupported indicator type: {indicator_type}")
        try:
            response = httpx.get(
                f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": settings.virustotal_api_key},
                timeout=settings.threat_intel_timeout_seconds,
            )
            if response.status_code == 429:
                raise LookupError_("VirusTotal rate limit reached; try again later")
            if response.status_code == 404:
                return _result("unknown", 0, {"reason": "Not found in VirusTotal"}, {})
            response.raise_for_status()
            stats = (
                response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = max(1, sum(int(v) for v in stats.values()))
            if malicious > 0:
                verdict, score = "malicious", min(100.0, malicious / total * 100)
            elif suspicious > 0:
                verdict, score = "unknown", min(100.0, suspicious / total * 100)
            else:
                verdict, score = "clean", 0.0
            return _result(verdict, score, stats, {"last_analysis_stats": stats})
        except httpx.HTTPError as exc:
            raise LookupError_(f"VirusTotal request failed: {type(exc).__name__}") from exc


class AbuseIPDBProvider:
    name = "abuseipdb"

    @property
    def enabled(self) -> bool:
        return bool(settings.abuseipdb_api_key)

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if not self.enabled:
            raise LookupError_("AbuseIPDB API key not configured")
        if indicator_type != "ip":
            raise LookupError_("AbuseIPDB supports IPv4/IPv6 addresses only")
        try:
            response = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                timeout=settings.threat_intel_timeout_seconds,
            )
            if response.status_code == 429:
                raise LookupError_("AbuseIPDB rate limit reached; try again later")
            response.raise_for_status()
            data = response.json().get("data", {})
            confidence = float(data.get("abuseConfidenceScore", 0) or 0)
            if confidence >= 75:
                verdict = "malicious"
            elif confidence >= 25:
                verdict = "unknown"
            else:
                verdict = "clean"
            details = {
                "abuse_confidence_score": confidence,
                "total_reports": data.get("totalReports"),
                "last_reported_at": data.get("lastReportedAt"),
            }
            return _result(verdict, confidence, details, data)
        except httpx.HTTPError as exc:
            raise LookupError_(f"AbuseIPDB request failed: {type(exc).__name__}") from exc


def _result(verdict: str, score: float, details: dict, raw: dict) -> dict[str, Any]:
    return {"verdict": verdict, "score": round(float(score), 2), "details": details, "raw": raw}
