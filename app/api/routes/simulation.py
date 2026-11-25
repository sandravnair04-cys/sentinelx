"""Safe lab simulation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ...config import settings
from ...correlation.engine import correlate_and_create
from ...database import get_db
from ...detection import run_detection
from ...schemas import SimulationRequest
from ...security import client_ip, require_analyst
from ...services.audit import log_action
from ...services.simulation import generate_scenario, scenario_descriptions
from ...collectors.base import ingest_events

router = APIRouter(prefix="/simulation", tags=["Simulation"])


@router.get("/scenarios")
def scenarios(_user=Depends(require_analyst)) -> dict:
    return {
        "enabled": settings.simulation_mode,
        "note": "All scenarios are synthetic, isolated lab events. No external systems are contacted.",
        "scenarios": scenario_descriptions(),
    }


@router.post("/run")
def run(
    payload: SimulationRequest, request: Request, db: Session = Depends(get_db), user=Depends(require_analyst)
) -> dict:
    if not settings.simulation_mode:
        raise HTTPException(status_code=403, detail="Simulation mode is disabled")
    try:
        events = generate_scenario(
            payload.scenario, payload.count, payload.source_ip, payload.username, payload.host
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    ingestion = ingest_events(db, events)
    detection = run_detection(db)
    correlation = correlate_and_create(db)
    log_action(
        db, user.username, "simulation_run", actor_role=user.role,
        target_type="simulation", target_id=payload.scenario,
        details={"count": payload.count, **ingestion}, ip_address=client_ip(request),
    )
    return {
        "scenario": payload.scenario,
        "events": ingestion,
        "detection": detection,
        "correlation": correlation,
        "simulated": True,
    }
