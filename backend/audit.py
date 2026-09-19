"""Audit event logging. Never store plaintext PII here."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.database import COLL_AUDIT, get_collection
from backend.token_service import random_event_id


def log_event(
    *,
    action: str,
    status: str,
    actor: str,
    role: str,
    subject: str | None = None,
    field: str | None = None,
    purpose: str | None = None,
    reason: str | None = None,
    reference: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Insert an audit event and return its event_id."""
    event_id = random_event_id("AUD")
    doc = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "role": role,
        "action": action,
        "subject": subject,
        "field": field,
        "purpose": purpose,
        "status": status,
        "reason": reason,
        "reference": reference,
    }
    if extra:
        # Only allow non-PII extras
        doc.update(extra)
    get_collection(COLL_AUDIT).insert_one(doc)
    return event_id
