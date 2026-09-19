"""Batch processing endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from backend.batch_service import create_batch, get_batch, list_batches, run_batch
from backend.database import to_json_safe
from backend.models import BatchRunRequest, BatchRunResponse
from backend.security import Actor, check_role, get_current_actor

router = APIRouter(tags=["batches"])


@router.post("/batch/run", response_model=BatchRunResponse)
def start_batch(payload: BatchRunRequest, actor: Actor = Depends(get_current_actor)):
    check_role(actor, "ADMIN", "DATA_OPERATOR")
    batch = create_batch(payload.source, payload.batch_size, payload.mode, actor.name, actor.role)
    # Run synchronously for demo responsiveness
    updated = run_batch(batch["batch_id"], actor.name, actor.role)
    doc = updated if updated and "batch_id" in updated else batch
    return {
        "batch_id": doc.get("batch_id", batch["batch_id"]),
        "source": doc.get("source", payload.source),
        "batch_size": doc.get("batch_size", payload.batch_size),
        "status": doc.get("status", "QUEUED"),
        "created_at": doc.get("started_at", ""),
        "records_processed": doc.get("records_processed", 0),
        "records_protected": doc.get("records_protected", 0),
        "errors": doc.get("errors_count", 0),
    }


@router.get("/batch")
def list_all_batches(actor: Actor = Depends(get_current_actor)):
    check_role(actor, "ADMIN", "DATA_OPERATOR", "PRIVACY_OFFICER")
    return {"batches": to_json_safe(list_batches(limit=100))}


@router.get("/batch/{batch_id}")
def get_batch_details(batch_id: str, actor: Actor = Depends(get_current_actor)):
    doc = get_batch(batch_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Batch not found")
    out = to_json_safe(doc)
    # Normalize keys expected by the frontend
    out.setdefault("protected", out.get("records_protected", 0))
    out.setdefault("failed", out.get("failed_records", 0))
    return out
