"""Track spent refresh-token hashes for session replay detection.

Revision ID: 0002_refresh_reuse_tracking
Revises: 0001_secure_multi_user_schema
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0002_refresh_reuse_tracking"
down_revision = "0001_secure_multi_user_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("auth_tokens")}
    if "session_id" not in columns:
        with op.batch_alter_table("auth_tokens") as batch:
            batch.add_column(sa.Column("session_id", sa.String(length=36), nullable=True))
            batch.create_foreign_key(
                "fk_auth_tokens_session_id_auth_sessions",
                "auth_sessions",
                ["session_id"],
                ["id"],
                ondelete="CASCADE",
            )
            batch.create_index("ix_auth_tokens_session_id", ["session_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("auth_tokens") as batch:
        batch.drop_index("ix_auth_tokens_session_id")
        batch.drop_constraint("fk_auth_tokens_session_id_auth_sessions", type_="foreignkey")
        batch.drop_column("session_id")
