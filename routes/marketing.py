"""Marketing send-email and bounce webhook endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from backend.gateway import handle_bounce, send_via_gateway
from backend.models import (
    BounceWebhookRequest,
    BounceWebhookResponse,
    SendEmailRequest,
    SendEmailResponse,
)
from backend.security import Actor, get_current_actor

router = APIRouter(tags=["marketing"])


@router.post("/actions/send-email", response_model=SendEmailResponse)
def send_email(payload: SendEmailRequest, actor: Actor = Depends(get_current_actor)):
    result = send_via_gateway(
        customer_id=payload.customer_id,
        purpose=payload.purpose,
        subject=payload.subject,
        message=payload.message,
        actor=actor.name,
        role=actor.role,
    )
    if not result.get("ok"):
        # Still return 200 with status FAILED so the frontend can render it
        raise HTTPException(status_code=502, detail=result.get("reason") or "Email dispatch failed")

    return {
        "status": "SENT",
        "protected_recipient": result["protected_recipient"],
        "audit_event_id": result["audit_event_id"],
    }


@router.post("/webhooks/email", response_model=BounceWebhookResponse)
def email_webhook(payload: BounceWebhookRequest):
    """Provider callback. Accepts plaintext email OR protected recipient."""
    result = handle_bounce(
        protected_recipient=payload.protected_recipient,
        plaintext_email=payload.email,
        event_type=payload.event_type,
        reason=payload.reason,
    )
    return result
