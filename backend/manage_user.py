from __future__ import annotations

import argparse
from datetime import datetime, timezone

from sqlalchemy import select

from backend.database import SessionLocal
from backend.models import AuditLog, AuthSession, User


def promote_admin(email: str) -> None:
    normalized_email = email.strip().lower()
    with SessionLocal() as db:
        user = db.execute(select(User).where(User.email == normalized_email)).scalar_one_or_none()
        if not user or not user.is_active or not user.is_verified:
            raise SystemExit("Target must be an existing, active, email-verified account.")
        user.role = "admin"
        user.token_version += 1
        now = datetime.now(timezone.utc)
        db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).update(
            {AuthSession.revoked_at: now}
        )
        db.add(
            AuditLog(
                actor_id=None,
                action="bootstrap_admin",
                target_type="user",
                target_id=str(user.id),
                details="Created through the restricted local administration CLI.",
            )
        )
        db.commit()
    print("Account promoted; existing sessions revoked. Sign in again.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Restricted LegalEase account administration.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    promote = subparsers.add_parser("promote-admin", help="Promote a verified account to administrator.")
    promote.add_argument("email")
    arguments = parser.parse_args()
    if arguments.command == "promote-admin":
        promote_admin(arguments.email)


if __name__ == "__main__":
    main()
