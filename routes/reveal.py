"""Controlled reveal endpoint with backend-enforced authorization."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.audit import log_event
from backend.database import COLL_PROTECTED, get_collection
from backend.models import RevealRequest, RevealResponse
from backend.security import Actor, check_reveal_policy, get_current_actor
from backend.vault_service import lookup_plaintext

router = APIRouter(tags=["reveal"])


def _resolve_field(doc: dict, field: str) -> str | None:
    """Extract the token for the requested field and look up the plaintext."""
    field = field.lower()
    token_map = {
        "name": doc.get("name_token"),
        "email": doc.get("email_token"),
        "mobile": doc.get("mobile_protected"),
    }
    token = token_map.get(field)
    if not token:
        return None

    # Mobile uses FPE — the token stored in vault is the stable MOBILE_ token
    if field == "mobile":
        # Look up by the mobile token derived from the plaintext
        # We need to find the vault entry whose token decrypts to the original
        # The protection service stored a MOBILE_ token; use that
        from backend.token_service import make_token
        # We don't have the plaintext; scan the vault for a mobile entry
        # whose ciphertext, when decrypted, matches the protected value.
        # Simpler: the vault stores the original mobile under a MOBILE_ token.
        # We locate it by decrypting and comparing FPE output.
        from backend.fpe_service import decrypt_mobile
        # Scan vault for mobile entries
        vault = get_collection("secure_vault")
        for vdoc in vault.find({"field_type": "mobile"}, {"token": 1, "encrypted_value": 1, "nonce": 1}):
            try:
                plain = lookup_plaintext(vdoc["token"])
                if plain and __import__("services.fpe_service", fromlist=["encrypt_mobile"]).encrypt_mobile(plain) == token:
                    return plain
            except Exception:  # noqa: BLE001
                continue
        return None

    return lookup_plaintext(token)


@router.post("/reveal", response_model=RevealResponse)
def reveal(payload: RevealRequest, actor: Actor = Depends(get_current_actor)):
    # 1) Authorization decision — enforced by the backend
    allowed, reason = check_reveal_policy(actor, payload.field, payload.purpose)

    if not allowed:
        log_event(
            action="REVEAL_DENIED",
            status="DENIED",
            actor=actor.name,
            role=actor.role,
            subject=payload.subject_id,
            field=payload.field,
            purpose=payload.purpose,
            reason=reason,
            reference=payload.reference,
        )
        return {
            "status": "ACCESS_DENIED",
            "reason": reason,
        }

    # 2) Look up the protected customer
    doc = get_collection(COLL_PROTECTED).find_one({"customer_id": payload.subject_id})
    if not doc:
        log_event(
            action="REVEAL_DENIED",
            status="DENIED",
            actor=actor.name,
            role=actor.role,
            subject=payload.subject_id,
            field=payload.field,
            purpose=payload.purpose,
            reason="Subject not found",
            reference=payload.reference,
        )
        return {"status": "ACCESS_DENIED", "reason": "Subject not found"}

    # 3) Resolve the plaintext internally
    value = _resolve_field(doc, payload.field)
    if value is None:
        log_event(
            action="REVEAL_DENIED",
            status="DENIED",
            actor=actor.name,
            role=actor.role,
            subject=payload.subject_id,
            field=payload.field,
            purpose=payload.purpose,
            reason="Vault lookup failed",
            reference=payload.reference,
        )
        return {"status": "ACCESS_DENIED", "reason": "Vault lookup failed"}

    log_event(
        action="REVEAL_AUTHORIZED",
        status="SUCCESS",
        actor=actor.name,
        role=actor.role,
        subject=payload.subject_id,
        field=payload.field,
        purpose=payload.purpose,
        reason=reason,
        reference=payload.reference,
    )

    return {
        "status": "AUTHORIZED",
        "value": value,
        "purpose": payload.purpose,
        "reference": payload.reference,
    }
