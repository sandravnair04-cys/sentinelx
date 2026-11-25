"""SENTINELX REST API aggregation."""

from fastapi import APIRouter

from .routes import (
    admin,
    agents,
    auth,
    dashboard,
    detection,
    endpoints,
    events,
    incidents,
    ingest,
    mitre,
    investigations,
    reports,
    response,
    searches,
    simulation,
    threat_intel,
)

api_router = APIRouter(prefix="/api")
for module in (
    auth,
    dashboard,
    events,
    detection,
    ingest,
    endpoints,
    mitre,
    searches,
    incidents,
    investigations,
    response,
    agents,
    threat_intel,
    reports,
    simulation,
    admin,
):
    api_router.include_router(module.router)

__all__ = ["api_router"]
