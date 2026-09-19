"""Batch processing: drives protection across the source collection."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.audit import log_event
from backend.database import (
    COLL_BATCHES,
    COLL_POLICIES,
    COLL_PROTECTED,
    COLL_SOURCE,
    get_collection,
)
from backend.protection_service import apply_policy_to_record
from backend.token_service import random_event_id


DEFAULT_POLICIES = {
    "name": {"enabled": True, "method": "TOKENIZATION", "stable": True},
    "email": {"enabled": True, "method": "TOKENIZATION", "stable": True},
    "mobile": {"enabled": True, "method": "FPE", "format": "10_digits"},
}


def get_active_policies() -> dict:
    """Load the active policy from MongoDB, falling back to defaults."""
    doc = get_collection(COLL_POLICIES).find_one({"active": True})

    if doc and isinstance(doc.get("policies"), dict):
        merged = dict(DEFAULT_POLICIES)

        for k, v in doc["policies"].items():
            if isinstance(v, dict):
                merged[k] = {**merged.get(k, {}), **v}

        return merged

    return DEFAULT_POLICIES


def create_batch(source: str, batch_size: int, mode: str, actor: str, role: str) -> dict:
    batch_id = random_event_id("BATCH")
    now = datetime.now(timezone.utc).isoformat()

    doc = {
        "batch_id": batch_id,
        "source": source,
        "batch_size": batch_size,
        "mode": mode,
        "started_at": now,
        "completed_at": None,
        "total_records": 0,
        "records_processed": 0,
        "records_protected": 0,
        "failed_records": 0,
        "errors_count": 0,
        "status": "QUEUED",
    }

    get_collection(COLL_BATCHES).insert_one(dict(doc))

    log_event(
        action="BATCH_STARTED",
        status="SUCCESS",
        actor=actor,
        role=role,
        subject=batch_id,
        reason=f"source={source}, size={batch_size}, mode={mode}",
    )

    return doc


def run_batch(batch_id: str, actor: str, role: str) -> dict:
    """Execute a batch synchronously. Idempotent per customer_id."""

    batches = get_collection(COLL_BATCHES)
    batch = batches.find_one({"batch_id": batch_id})

    if not batch:
        return {"error": "batch_not_found"}

    batches.update_one(
        {"batch_id": batch_id},
        {"$set": {"status": "RUNNING"}},
    )

    policies = get_active_policies()
    source = get_collection(COLL_SOURCE)
    protected = get_collection(COLL_PROTECTED)

    total = source.count_documents({})

    processed = 0
    protected_count = 0
    failed = 0

    cursor = source.find({})

    for record in cursor:
        processed += 1

        try:
            protected_doc = apply_policy_to_record(record, policies)

            if not protected_doc.get("customer_id"):
                failed += 1
                continue

            # Idempotent upsert keyed on customer_id
            protected.update_one(
                {"customer_id": protected_doc["customer_id"]},
                {"$set": protected_doc},
                upsert=True,
            )

            protected_count += 1

        except Exception as exc:  # noqa: BLE001
            import logging

            logging.getLogger(__name__).exception(
                "Protection failed: %s",
                exc,
            )
            failed += 1

    completed_at = datetime.now(timezone.utc).isoformat()

    final_status = "COMPLETED" if failed == 0 else "COMPLETED"

    batches.update_one(
        {"batch_id": batch_id},
        {
            "$set": {
                "status": final_status,
                "completed_at": completed_at,
                "total_records": total,
                "records_processed": processed,
                "records_protected": protected_count,
                "failed_records": failed,
                "errors_count": failed,
            }
        },
    )

    log_event(
        action="BATCH_COMPLETED",
        status="SUCCESS" if failed == 0 else "FAILED",
        actor=actor,
        role=role,
        subject=batch_id,
        reason=f"processed={processed}, protected={protected_count}, failed={failed}",
    )

    return batches.find_one({"batch_id": batch_id})


def get_batch(batch_id: str) -> dict | None:
    return get_collection(COLL_BATCHES).find_one({"batch_id": batch_id})


def list_batches(limit: int = 50) -> list[dict]:
    return (
        list(
            get_collection(COLL_BATCHES)
            .find({})
            .sort("started_at", -1)
            .limit(limit)
        )
    )