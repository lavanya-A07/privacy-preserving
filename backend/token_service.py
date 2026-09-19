"""Deterministic and random token generation for name/email tokenization."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from backend.config import get_settings

TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Crockford-ish, no confusing chars


def _b32(data: bytes, length: int) -> str:
    """Encode bytes to a URL-safe alphabet, truncated to `length` chars."""
    out = []
    for b in data:
        out.append(TOKEN_ALPHABET[b % len(TOKEN_ALPHABET)])
        if len(out) >= length:
            break
    while len(out) < length:
        out.append(TOKEN_ALPHABET[secrets.randbelow(len(TOKEN_ALPHABET))])
    return "".join(out)


def make_token(field_type: str, plaintext: str, *, stable: bool = True) -> str:
    """Return a token like NAME_XXXXXXXX or EMAIL_XXXXXXXX.

    When `stable=True`, the same plaintext yields the same token (HMAC-SHA256).
    When `stable=False`, a random token is generated (not linkable).
    """
    prefix = field_type.upper()
    secret = get_settings().token_secret

    if stable:
        digest = hmac.new(secret, f"{field_type}:{plaintext}".encode("utf-8"), hashlib.sha256).digest()
    else:
        digest = secrets.token_bytes(32)

    suffix = _b32(digest, 10)
    return f"{prefix}_{suffix}"


def make_customer_token(customer_id: str) -> str:
    return make_token("cust", customer_id, stable=True)


def token_from_email(email: str) -> str:
    return make_token("EMAIL", email, stable=True)


def token_from_name(name: str) -> str:
    return make_token("NAME", name, stable=True)


def random_event_id(prefix: str = "EVT") -> str:
    return f"{prefix}_{base64.urlsafe_b64encode(secrets.token_bytes(9)).decode().rstrip('=')}"
