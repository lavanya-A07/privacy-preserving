"""Source and protected customer endpoints."""
from __future__ import annotations

import csv
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status

from backend.audit import log_event
from backend.config import get_settings
from backend.database import (
    COLL_PROTECTED,
    COLL_SOURCE,
    get_collection,
    to_json_safe,
)
from backend.models import SourceCustomerPage
from backend.security import Actor, get_current_actor

router = APIRouter(tags=["customers"])


@router.get("/customers/source", response_model=SourceCustomerPage)
def list_source_customers(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=500),
    actor: Actor = Depends(get_current_actor),
):
    coll = get_collection(COLL_SOURCE)
    total = coll.count_documents({})
    skip = (page - 1) * limit
    cursor = coll.find({}, {"_id": 0}).skip(skip).limit(limit)
    customers = [to_json_safe(doc) for doc in cursor]
    return {"page": page, "limit": limit, "total": total, "customers": customers}


@router.post("/customers/import")
async def import_customers(
    file: UploadFile | None = File(default=None),
    actor: Actor = Depends(get_current_actor),
):
    """Import customers from CSV. Uses data/customers.csv if no file uploaded."""
    settings = get_settings()
    if file is not None:
        content = await file.read()
        # Write to the canonical path for repeatability
        settings.customers_csv.parent.mkdir(parents=True, exist_ok=True)
        settings.customers_csv.write_bytes(content)

    csv_path = settings.customers_csv
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="customers.csv not found")

    required = {"customer_id", "name", "email", "mobile", "city", "segment"}
    inserted = 0
    updated = 0
    malformed = 0

    coll = get_collection(COLL_SOURCE)
    with csv_path.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if not required.issubset(set(reader.fieldnames or [])):
            raise HTTPException(status_code=400, detail="CSV missing required columns")
        for row in reader:
            if not row.get("customer_id"):
                malformed += 1
                continue
            result = coll.update_one(
                {"customer_id": row["customer_id"]},
                {"$set": row},
                upsert=True,
            )
            if result.upserted_id is not None:
                inserted += 1
            elif result.modified_count > 0:
                updated += 1

    log_event(
        action="CUSTOMER_IMPORT",
        status="SUCCESS",
        actor=actor.name,
        role=actor.role,
        reason=f"inserted={inserted}, updated={updated}, malformed={malformed}",
    )
    return {
        "status": "OK",
        "inserted": inserted,
        "updated": updated,
        "malformed": malformed,
        "total": coll.count_documents({}),
    }


@router.get("/customers/protected")
def list_protected_customers(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    actor: Actor = Depends(get_current_actor),
):
    coll = get_collection(COLL_PROTECTED)
    total = coll.count_documents({})
    cursor = coll.find({}, {"_id": 0}).skip((page - 1) * limit).limit(limit)
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "customers": [to_json_safe(doc) for doc in cursor],
    }



@router.get("/customers/protected/export")
def export_protected_customers(
    actor: Actor = Depends(get_current_actor),
):
    """Export all protected customer records as a CSV file."""
    from fastapi.responses import StreamingResponse
    import io

    coll = get_collection(COLL_PROTECTED)
    fields = [
        "customer_id",
        "city",
        "email_token",
        "mobile_protected",
        "name_token",
        "segment",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()

    cursor = coll.find({}, {"_id": 0})
    for doc in cursor:
        writer.writerow({field: doc.get(field, "") for field in fields})

    output.seek(0)

    log_event(
        action="PROTECTED_CSV_EXPORT",
        status="SUCCESS",
        actor=actor.name,
        role=actor.role,
        reason="Protected customer CSV exported",
    )

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=protected_customers.csv"
        },
    )
@router.get("/customers/{customer_id}")
def get_protected_customer(
    customer_id: str,
    actor: Actor = Depends(get_current_actor),
):
    """Return protected data only. Plaintext requires /reveal."""
    doc = get_collection(COLL_PROTECTED).find_one({"customer_id": customer_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Customer not found in protected store")
    return to_json_safe(doc)




