"""PII discovery endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.audit import log_event
from backend.discovery import run_discovery
from backend.security import Actor, get_current_actor

router = APIRouter(tags=["discovery"])


@router.post("/discover")
def discover(actor: Actor = Depends(get_current_actor)):
    report = run_discovery()
    log_event(
        action="DISCOVERY_RUN",
        status="SUCCESS",
        actor=actor.name,
        role=actor.role,
        reason=f"fields={report['total_fields']}, pii={report['pii_count']}",
    )
    return report
