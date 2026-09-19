"""Apply protection methods to source records."""
from __future__ import annotations

import hashlib

from backend.fpe_service import encrypt_mobile
from backend.token_service import make_token
from backend.vault_service import store_token


def protect_name(name: str, *, stable: bool = True) -> str:
    token = make_token("NAME", name, stable=stable)
    store_token("name", token, name)
    return token


def protect_email(email: str, *, stable: bool = True) -> str:
    token = make_token("EMAIL", email, stable=stable)
    store_token("email", token, email)
    return token


def protect_mobile_fpe(mobile: str) -> str:
    """Apply FPE. The vault stores the reversible mapping."""
    protected = encrypt_mobile(mobile)
    # Vault entry keyed by a derived token so reverse lookup works
    token = make_token("MOBILE", mobile, stable=True)
    store_token("mobile", token, mobile)
    return protected


def protect_hash(value: str) -> str:
    return "HASH_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def protect_mask(value: str) -> str:
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return s[:1] + "*" * (len(s) - 2) + s[-1:]


def apply_policy_to_record(record: dict, policies: dict[str, dict]) -> dict:
    """Transform a source record into a protected record per the active policies."""
    out: dict = {"customer_id": record.get("customer_id")}

    # name
    name_rule = policies.get("name", {})
    if name_rule.get("enabled", True) and record.get("name"):
        method = (name_rule.get("method") or "TOKENIZATION").upper()
        if method == "TOKENIZATION":
            out["name_token"] = protect_name(record["name"], stable=bool(name_rule.get("stable", True)))
        elif method == "HASHING":
            out["name_token"] = protect_hash(record["name"])
        elif method == "MASKING":
            out["name_token"] = protect_mask(record["name"])
        else:
            out["name_token"] = protect_name(record["name"])
    else:
        out["name_token"] = None

    # email
    email_rule = policies.get("email", {})
    if email_rule.get("enabled", True) and record.get("email"):
        method = (email_rule.get("method") or "TOKENIZATION").upper()
        if method == "TOKENIZATION":
            out["email_token"] = protect_email(record["email"], stable=bool(email_rule.get("stable", True)))
        elif method == "HASHING":
            out["email_token"] = protect_hash(record["email"])
        elif method == "MASKING":
            out["email_token"] = protect_mask(record["email"])
        else:
            out["email_token"] = protect_email(record["email"])
    else:
        out["email_token"] = None

    # mobile
    mobile_rule = policies.get("mobile", {})
    if mobile_rule.get("enabled", True) and record.get("mobile"):
        method = (mobile_rule.get("method") or "FPE").upper()
        if method == "FPE":
            out["mobile_protected"] = protect_mobile_fpe(record["mobile"])
        elif method == "HASHING":
            out["mobile_protected"] = protect_hash(record["mobile"])
        elif method == "MASKING":
            out["mobile_protected"] = protect_mask(record["mobile"])
        else:
            out["mobile_protected"] = protect_mobile_fpe(record["mobile"])
    else:
        out["mobile_protected"] = None

    # Non-sensitive pass-through
    out["city"] = record.get("city")
    out["segment"] = record.get("segment")
    return out
