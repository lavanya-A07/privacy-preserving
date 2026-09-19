"""Authentication stub + RBAC + purpose-based access control.

The frontend passes an `X-Role` header so the backend can enforce policy.
In production, replace `get_current_actor` with real JWT/OIDC validation.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, status

VALID_ROLES = {"ADMIN", "DATA_OPERATOR", "MARKETING", "PRIVACY_OFFICER"}

# Maps frontend role strings to canonical roles
ROLE_ALIASES = {
    "ADMIN": "ADMIN",
    "FACULTY": "DATA_OPERATOR",
    "DATA_OPERATOR": "DATA_OPERATOR",
    "MARKETING": "MARKETING",
    "PRIVACY_OFFICER": "PRIVACY_OFFICER",
}


class Actor:
    __slots__ = ("role", "name")

    def __init__(self, role: str, name: str) -> None:
        self.role = role
        self.name = name

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "name": self.name}


def get_current_actor(
    x_role: str | None = Header(default=None, alias="X-Role"),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
) -> Actor:
    """Extract the actor from request headers. Defaults to a safe guest role."""
    canonical = ROLE_ALIASES.get((x_role or "").upper(), None)
    if canonical is None:
        # Unauthenticated default — most restrictive
        canonical = "MARKETING"  # read-only-ish default
    return Actor(role=canonical, name=x_actor or canonical.lower())


def require_roles(*allowed: str):
    """Dependency factory that ensures the actor has one of the allowed roles."""
    def _checker(actor: Actor = None) -> Actor:  # type: ignore[assignment]
        # FastAPI will inject via Depends(get_current_actor)
        raise RuntimeError("Use require_roles_dep() instead")
    return _checker


def check_role(actor: Actor, *allowed: str) -> None:
    if actor.role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied for role",
        )


# ---------------------------------------------------------------- purpose
# Purpose + role + field matrix for controlled reveal.
# Format: REVEAL_POLICY[role][field] = {allowed_purposes}
REVEAL_POLICY: dict[str, dict[str, set[str]]] = {
    "ADMIN": {
        "name": {"Customer Support", "Legal Request", "Fraud Investigation", "Compliance Audit"},
        "email": {"Customer Support", "Legal Request", "Fraud Investigation", "Compliance Audit"},
        "mobile": {"Customer Support", "Legal Request", "Fraud Investigation", "Compliance Audit"},
    },
    "PRIVACY_OFFICER": {
        "email": {"Customer Support", "Legal Request", "Compliance Audit"},
        "mobile": {"Customer Support", "Legal Request", "Compliance Audit"},
        "name": {"Customer Support", "Legal Request", "Compliance Audit"},
    },
    "DATA_OPERATOR": {
        # Data operators cannot reveal PII by default
    },
    "MARKETING": {
        # Marketing cannot reveal any PII
    },
}


def check_reveal_policy(actor: Actor, field: str, purpose: str) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    field = (field or "").lower()
    purpose_norm = (purpose or "").strip()

    role_rules = REVEAL_POLICY.get(actor.role, {})
    if not role_rules:
        return False, "Role is not permitted to reveal protected fields"

    field_rules = role_rules.get(field)
    if not field_rules:
        return False, f"Role '{actor.role}' cannot reveal field '{field}'"

    if purpose_norm not in field_rules:
        return False, f"Purpose '{purpose_norm}' is not authorized for field '{field}'"

    return True, "Authorized purpose and role"
