"""Secure vault: AES-GCM encrypted mapping between tokens and originals.

The vault is NEVER exposed through the API. Only internal services may
read or write here.
"""
from __future__ import annotations

import base64
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.config import get_settings
from backend.database import COLL_VAULT, get_collection


def _aesgcm() -> AESGCM:
    return AESGCM(get_settings().vault_key)


def _encrypt(plaintext: str) -> tuple[str, str]:
    """Return (ciphertext_b64, nonce_b64)."""
    nonce = os.urandom(12)
    ct = _aesgcm().encrypt(nonce, str(plaintext).encode("utf-8"), associated_data=None)
    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()


def _decrypt(ct_b64: str, nonce_b64: str) -> str:
    ct = base64.b64decode(ct_b64)
    nonce = base64.b64decode(nonce_b64)
    pt = _aesgcm().decrypt(nonce, ct, associated_data=None)
    return pt.decode("utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def store_token(field_type: str, token: str, plaintext: str) -> None:
    """Upsert a vault record. Plaintext is encrypted before storage."""
    ct_b64, nonce_b64 = _encrypt(plaintext)
    coll = get_collection(COLL_VAULT)
    coll.update_one(
        {"token": token},
        {
            "$set": {
                "token": token,
                "field_type": field_type,
                "encrypted_value": ct_b64,
                "nonce": nonce_b64,
                "key_reference": "VAULT_AES_KEY_BASE64",
                "updated_at": _now(),
            },
            "$setOnInsert": {"created_at": _now()},
        },
        upsert=True,
    )


def lookup_plaintext(token: str) -> str | None:
    """Return the plaintext for a token, or None. Internal use only."""
    doc = get_collection(COLL_VAULT).find_one({"token": token})
    if not doc:
        return None
    try:
        return _decrypt(doc["encrypted_value"], doc["nonce"])
    except Exception:  # noqa: BLE001
        return None


def token_for_plaintext(field_type: str, plaintext: str) -> str | None:
    """Reverse lookup: find a token whose vault record decrypts to `plaintext`."""
    # Linear scan is acceptable for the demo scale (2k records).
    # In production, maintain a salted hash index.
    coll = get_collection(COLL_VAULT)
    for doc in coll.find({"field_type": field_type}, {"token": 1, "encrypted_value": 1, "nonce": 1}):
        try:
            if _decrypt(doc["encrypted_value"], doc["nonce"]) == plaintext:
                return doc["token"]
        except Exception:  # noqa: BLE001
            continue
    return None
