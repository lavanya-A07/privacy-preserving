"""Protection policy configuration and protection trigger."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from backend.audit import log_event
from backend.batch_service import get_active_policies
from backend.database import COLL_POLICIES, get_collection, to_json_safe
from backend.models import PolicyUpdate
from backend.security import Actor, get_current_actor, check_role

router = APIRouter(tags=["policies"])


@router.get("/policies")
def read_policies(actor: Actor = Depends(get_current_actor)):
    doc = get_collection(COLL_POLICIES).find_one({"active": True}, {"_id": 0})
    if doc and isinstance(doc.get("policies"), dict):
        return {"policies": doc["policies"]}
    return {"policies": get_active_policies()}


@router.post("/policies")
def write_policies(payload: PolicyUpdate, actor: Actor = Depends(get_current_actor)):
    check_role(actor, "ADMIN", "DATA_OPERATOR")
    coll = get_collection(COLL_POLICIES)
    now = datetime.now(timezone.utc).isoformat()
    coll.update_one(
        {"active": True},
        {
            "$set": {
                "active": True,
                "policies": payload.policies,
                "updated_at": now,
                "updated_by": actor.name,
            },
            "$setOnInsert": {"created_at": now},
        },
        upsert=True,
    )
    log_event(
        action="POLICY_UPDATED",
        status="SUCCESS",
        actor=actor.name,
        role=actor.role,
        reason="Policy updated",
    )
    doc = coll.find_one({"active": True}, {"_id": 0})
    return {"policies": doc.get("policies", {}) if doc else {}}


@router.post("/protect")
def trigger_protection(actor: Actor = Depends(get_current_actor)):
    """Trigger a full protection pass without creating a batch record.

    Kept for compatibility with the frontend `POST /protect` button.
    """
    check_role(actor, "ADMIN", "DATA_OPERATOR")
    from backend.batch_service import create_batch, run_batch

    batch = create_batch("mongo_source", 1000, "full", actor.name, actor.role)
    result = run_batch(batch["batch_id"], actor.name, actor.role)
    log_event(
        action="PROTECTION_COMPLETED",
        status="SUCCESS",
        actor=actor.name,
        role=actor.role,
        subject=batch["batch_id"],
        reason=f"protected={result.get('records_protected', 0)}",
    )
    return {
        "status": "COMPLETED",
        "batch_id": batch["batch_id"],
        "protected": result.get("records_protected", 0),
        "failed": result.get("failed_records", 0),
    }
