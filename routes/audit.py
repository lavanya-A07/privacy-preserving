"""Audit log retrieval endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.database import COLL_AUDIT, COLL_BATCHES, COLL_EMAIL, COLL_PROTECTED, COLL_SOURCE, get_collection, to_json_safe
from backend.security import Actor, get_current_actor

router = APIRouter(tags=["audit"])


@router.get("/audit")
def list_audit(
    event_type: str | None = Query(None, alias="event_type"),
    status: str | None = Query(None),
    actor: str | None = Query(None),
    purpose: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    _: Actor = Depends(get_current_actor),
):
    query: dict = {}
    if event_type:
        query["action"] = {"$regex": event_type, "$options": "i"}
    if status:
        query["status"] = status.upper()
    if actor:
        query["actor"] = {"$regex": actor, "$options": "i"}
    if purpose:
        query["purpose"] = {"$regex": purpose, "$options": "i"}

    cursor = (
        get_collection(COLL_AUDIT)
        .find(query, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    return {"events": to_json_safe(list(cursor))}


@router.get("/dashboard")
@router.get("/dashboard/stats")
def dashboard(_: Actor = Depends(get_current_actor)):
    """Return real, dynamic metrics from MongoDB."""
    source = get_collection(COLL_SOURCE)
    protected = get_collection(COLL_PROTECTED)
    batches = get_collection(COLL_BATCHES)
    emails = get_collection(COLL_EMAIL)
    audit = get_collection(COLL_AUDIT)

    total_source = source.count_documents({})
    total_protected = protected.count_documents({})

    # PII fields detected = distinct fields with PII category in latest discovery
    from backend.database import COLL_DISCOVERY
    latest_discovery = get_collection(COLL_DISCOVERY).find_one(
        {}, sort=[("timestamp", -1)]
    )
    pii_fields = 0
    if latest_discovery:
        pii_fields = latest_discovery.get("pii_count", 0)

    active_policies = 1 if get_collection("protection_policies").find_one({"active": True}) else 0

    successful_batches = batches.count_documents({"status": "COMPLETED"})
    failed_batches = batches.count_documents({"status": "FAILED"})

    email_actions = emails.count_documents({"event_type": "SENT"})
    bounce_events = emails.count_documents({"event_type": {"$in": ["BOUNCE", "COMPLAINT", "DEFERRED"]}})

    reveal_requests = audit.count_documents({"action": "REVEAL_AUTHORIZED"}) + audit.count_documents({"action": "REVEAL_DENIED"})
    denied_events = audit.count_documents({"action": "REVEAL_DENIED"})

    return {
        "total_source_customers": total_source,
        "protected_customers": total_protected,
        "pii_fields_detected": pii_fields,
        "active_policies": active_policies,
        "successful_batches": successful_batches,
        "failed_batches": failed_batches,
        "email_actions": email_actions,
        "bounce_events": bounce_events,
        "reveal_requests": reveal_requests,
        "denied_events": denied_events,
    }
