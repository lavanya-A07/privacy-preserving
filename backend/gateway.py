"""Privacy Gateway: resolves protected tokens internally and dispatches emails."""
from __future__ import annotations

from datetime import datetime, timezone

from backend.audit import log_event
from backend.database import COLL_EMAIL, COLL_PROTECTED, get_collection
from backend.email_service import send_email
from backend.token_service import random_event_id
from backend.vault_service import lookup_plaintext


def resolve_recipient_for_customer(customer_id: str) -> str | None:
    """Look up the email token for a protected customer."""
    doc = get_collection(COLL_PROTECTED).find_one({"customer_id": customer_id})
    if not doc:
        return None
    return doc.get("email_token")


def send_via_gateway(
    *,
    customer_id: str,
    purpose: str,
    subject: str,
    message: str,
    actor: str,
    role: str,
) -> dict:
    """Resolve the recipient token, decrypt internally, send, and audit."""
    token = resolve_recipient_for_customer(customer_id)
    if not token:
        log_event(
            action="EMAIL_FAILED",
            status="FAILED",
            actor=actor,
            role=role,
            subject=customer_id,
            purpose=purpose,
            reason="Recipient token not found",
        )
        return {"ok": False, "reason": "Recipient token not found", "protected_recipient": ""}

    plaintext = lookup_plaintext(token)
    if not plaintext:
        log_event(
            action="EMAIL_FAILED",
            status="FAILED",
            actor=actor,
            role=role,
            subject=customer_id,
            purpose=purpose,
            reason="Vault lookup failed",
        )
        return {"ok": False, "reason": "Vault lookup failed", "protected_recipient": token}

    ok = send_email(plaintext, subject, message)

    event_id = log_event(
        action="EMAIL_SENT" if ok else "EMAIL_FAILED",
        status="SUCCESS" if ok else "FAILED",
        actor=actor,
        role=role,
        subject=customer_id,
        field="email",
        purpose=purpose,
        reason="Dispatched via SMTP" if ok else "SMTP dispatch failed",
    )

    # Store email event for reference (no plaintext)
    get_collection(COLL_EMAIL).insert_one({
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protected_recipient": token,
        "event_type": "SENT" if ok else "FAILED",
        "reason": "Dispatched" if ok else "SMTP failure",
        "status": "SUCCESS" if ok else "FAILED",
    })

    return {
        "ok": ok,
        "protected_recipient": token,
        "audit_event_id": event_id,
    }


def handle_bounce(
    *,
    protected_recipient: str | None,
    plaintext_email: str | None,
    event_type: str,
    reason: str,
    actor: str = "provider",
    role: str = "SYSTEM",
) -> dict:
    """Reverse-resolve a provider bounce and store only the protected token."""
    token = protected_recipient

    # If the provider sent a plaintext email, reverse-resolve to a token
    if not token and plaintext_email:
        # Search protected customers for the token whose vault decrypts to this email
        token = _reverse_resolve_email(plaintext_email)

    if not token:
        token = "EMAIL_UNKNOWN"

    event_id = random_event_id("BNC")
    get_collection(COLL_EMAIL).insert_one({
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protected_recipient": token,
        "event_type": event_type.upper(),
        "reason": reason,
        "status": "PROCESSED",
    })

    log_event(
        action="BOUNCE_RECEIVED",
        status="SUCCESS",
        actor=actor,
        role=role,
        subject=token,
        field="email",
        reason=reason,
        reference=event_type.upper(),
    )

    return {
        "event_id": event_id,
        "protected_recipient": token,
        "event_type": event_type.upper(),
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "PROCESSED",
    }


def _reverse_resolve_email(plaintext_email: str) -> str | None:
    """Find a protected customer whose email token maps to this address."""
    from backend.vault_service import lookup_plaintext  # local import to avoid cycles

    coll = get_collection(COLL_PROTECTED)
    for doc in coll.find({"email_token": {"$ne": None}}, {"email_token": 1}):
        token = doc.get("email_token")
        if not token:
            continue
        if lookup_plaintext(token) == plaintext_email:
            return token
    return None
