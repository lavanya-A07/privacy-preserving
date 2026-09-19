"""Thin re-export module so imports match the project layout."""
from backend.vault_service import (  # noqa: F401
    lookup_plaintext,
    store_token,
    token_for_plaintext,
)
