"""Re-export protection helpers."""
from backend.protection_service import (  # noqa: F401
    apply_policy_to_record,
    protect_email,
    protect_mobile_fpe,
    protect_name,
)
