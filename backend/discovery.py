"""PII discovery — inspects the source collection schema and sample values."""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

from backend.database import COLL_DISCOVERY, COLL_SOURCE, get_collection
from backend.token_service import random_event_id

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MOBILE_RE = re.compile(r"^\+?\d{7,15}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{1,60}$")

# Field-name based hints (case-insensitive)
FIELD_HINTS = {
    "email": ("EMAIL", "EMAIL", 0.99, "TOKENIZATION"),
    "name": ("NAME", "NAME", 0.97, "TOKENIZATION"),
    "mobile": ("PHONE", "PHONE", 0.98, "FPE"),
    "phone": ("PHONE", "PHONE", 0.97, "FPE"),
    "city": ("LOCATION", "LOCATION", 0.85, "NONE"),
    "segment": ("NON-SENSITIVE", "NON-SENSITIVE", 0.92, "NONE"),
    "customer_id": ("IDENTIFIER", "IDENTIFIER", 0.95, "NONE"),
}


def _inspect_values(field: str, values: list[Any]) -> tuple[str, str, float, str]:
    """Return (detected_type, pii_category, confidence, recommendation)."""
    key = field.lower()
    if key in FIELD_HINTS:
        return FIELD_HINTS[key]

    # Value-pattern detection
    samples = [str(v) for v in values if v not in (None, "")]
    if not samples:
        return ("UNKNOWN", "NON-SENSITIVE", 0.30, "NONE")

    email_hits = sum(1 for s in samples if EMAIL_RE.match(s))
    mobile_hits = sum(1 for s in samples if MOBILE_RE.match(s) and not EMAIL_RE.match(s))
    name_hits = sum(1 for s in samples if NAME_RE.match(s))

    total = len(samples)
    if email_hits / total >= 0.6:
        return ("EMAIL", "EMAIL", round(email_hits / total, 2), "TOKENIZATION")
    if mobile_hits / total >= 0.6:
        return ("PHONE", "PHONE", round(mobile_hits / total, 2), "FPE")
    if name_hits / total >= 0.6:
        return ("NAME", "NAME", round(name_hits / total, 2), "TOKENIZATION")

    return ("NON-SENSITIVE", "NON-SENSITIVE", 0.55, "NONE")


def run_discovery() -> dict:
    """Inspect source_customers and return a discovery report."""
    started = time.perf_counter()
    coll = get_collection(COLL_SOURCE)

    sample_docs = list(coll.find({}, limit=200))
    if not sample_docs:
        # No source data — return empty report but still record it
        run_id = random_event_id("DISC")
        report = {
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_fields": 0,
            "pii_count": 0,
            "processing_time_ms": int((time.perf_counter() - started) * 1000),
            "status": "COMPLETED",
            "fields": [],
        }
        get_collection(COLL_DISCOVERY).insert_one(dict(report))
        return report

    # Collect all field names across samples
    field_names: set[str] = set()
    for doc in sample_docs:
        field_names.update(doc.keys())
    field_names.discard("_id")

    fields_out = []
    pii_count = 0
    for field in sorted(field_names):
        values = [doc.get(field) for doc in sample_docs if field in doc]
        detected_type, category, confidence, recommendation = _inspect_values(field, values)
        if category not in ("NON-SENSITIVE", "IDENTIFIER", "LOCATION"):
            pii_count += 1
        fields_out.append({
            "field": field,
            "detected_type": detected_type,
            "pii_category": category,
            "confidence": confidence,
            "recommendation": recommendation,
            "status": "DETECTED",
        })

    run_id = random_event_id("DISC")
    report = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_fields": len(fields_out),
        "pii_count": pii_count,
        "processing_time_ms": int((time.perf_counter() - started) * 1000),
        "status": "COMPLETED",
        "fields": fields_out,
    }
    get_collection(COLL_DISCOVERY).insert_one(dict(report))
    return report
