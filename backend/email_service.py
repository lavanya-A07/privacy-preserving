"""Email dispatch abstraction. Defaults to SMTP (Mailpit/MailHog on localhost)."""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from backend.config import get_settings

logger = logging.getLogger(__name__)


def send_email(to_address: str, subject: str, message: str) -> bool:
    """Send an email via SMTP. Returns True on success.

    Never log the recipient address or message body.
    """
    settings = get_settings()
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(message)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=5) as smtp:
            smtp.send_message(msg)
        logger.info("Email dispatched (recipient redacted)")
        return True
    except Exception as exc:  # noqa: BLE001
        # Do NOT include recipient or body in the log
        logger.warning("Email dispatch failed: %s", type(exc).__name__)
        return False
