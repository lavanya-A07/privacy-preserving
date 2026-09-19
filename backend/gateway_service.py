"""Re-export for the services layer."""
from backend.gateway import (  # noqa: F401
    handle_bounce,
    resolve_recipient_for_customer,
    send_via_gateway,
)
