from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage


def send_security_email(recipient: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    sender = os.getenv("SMTP_FROM")
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured.")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
    use_starttls = os.getenv("SMTP_STARTTLS", "true").lower() == "true"

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=15) as server:
                if username:
                    server.login(username, password or "")
                if server.send_message(message):
                    raise RuntimeError("Email delivery failed.")
            return

        with smtplib.SMTP(host, port, timeout=15) as server:
            if use_starttls:
                server.starttls()
            if username:
                server.login(username, password or "")
            if server.send_message(message):
                raise RuntimeError("Email delivery failed.")
    except (OSError, smtplib.SMTPException) as exc:
        raise RuntimeError("Email delivery failed.") from exc
