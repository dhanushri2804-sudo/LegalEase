"""Add multi-user auth, organizations, sharing, and audit tables.

Revision ID: 0001_secure_multi_user_schema
Revises:
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import re
import secrets

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, select, update

revision = "0001_secure_multi_user_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    had_legacy_documents = "documents" in inspector.get_table_names()

    from backend.database import Base
    from backend import models  # noqa: F401

    Base.metadata.create_all(bind=bind)

    if not had_legacy_documents:
        if bind.dialect.name == "postgresql":
            _enable_postgresql_rls()
        return

    existing_columns = {column["name"] for column in inspect(bind).get_columns("documents")}
    with op.batch_alter_table("documents") as batch:
        if "owner_id" not in existing_columns:
            batch.add_column(sa.Column("owner_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_documents_owner_id_users",
                "users",
                ["owner_id"],
                ["id"],
                ondelete="CASCADE",
            )
        if "organization_id" not in existing_columns:
            batch.add_column(sa.Column("organization_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_documents_organization_id_organizations",
                "organizations",
                ["organization_id"],
                ["id"],
                ondelete="SET NULL",
            )

    users = sa.table(
        "users",
        sa.column("id", sa.Integer),
        sa.column("email", sa.String),
        sa.column("password_hash", sa.String),
        sa.column("role", sa.String),
        sa.column("is_active", sa.Boolean),
        sa.column("is_verified", sa.Boolean),
        sa.column("token_version", sa.Integer),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    documents = sa.table("documents", sa.column("id", sa.Integer), sa.column("owner_id", sa.Integer))
    legacy_user_id = bind.execute(select(users.c.id).where(users.c.email == "legacy-records@invalid.local")).scalar_one_or_none()
    if legacy_user_id is None:
        inserted = bind.execute(
            users.insert()
            .values(
                email="legacy-records@invalid.local",
                password_hash=f"disabled${secrets.token_hex(32)}",
                role="user",
                is_active=False,
                is_verified=False,
                token_version=0,
                created_at=datetime.now(timezone.utc),
            )
            .returning(users.c.id)
        )
        legacy_user_id = inserted.scalar_one()
    bind.execute(update(documents).where(documents.c.owner_id.is_(None)).values(owner_id=legacy_user_id))

    with op.batch_alter_table("documents") as batch:
        batch.alter_column("owner_id", existing_type=sa.Integer(), nullable=False)
        batch.create_index("ix_documents_owner_id", ["owner_id"], unique=False)
        batch.create_index("ix_documents_organization_id", ["organization_id"], unique=False)
    if bind.dialect.name == "postgresql":
        _enable_postgresql_rls()


def _enable_postgresql_rls() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.legalease_is_document_owner(target_document_id integer, target_user_id integer)
        RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT EXISTS (
                SELECT 1 FROM public.documents d
                WHERE d.id = target_document_id AND d.owner_id = target_user_id
            )
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.legalease_can_view_document(target_document_id integer, target_user_id integer)
        RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT public.legalease_is_document_owner(target_document_id, target_user_id)
                OR EXISTS (
                    SELECT 1 FROM public.document_shares s
                    JOIN public.users u ON u.id = s.user_id
                    WHERE s.document_id = target_document_id
                      AND s.user_id = target_user_id
                      AND (s.permission <> 'reviewer' OR u.role = 'legal_reviewer')
                )
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.legalease_can_edit_document(target_document_id integer, target_user_id integer)
        RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT public.legalease_is_document_owner(target_document_id, target_user_id)
                OR EXISTS (
                    SELECT 1 FROM public.document_shares s
                    WHERE s.document_id = target_document_id
                      AND s.user_id = target_user_id
                      AND s.permission = 'editor'
                )
        $$;
        """
    )
    op.execute("ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY legalease_document_select ON public.documents
        FOR SELECT USING (
            public.legalease_can_view_document(
                id, NULLIF(current_setting('app.user_id', true), '')::integer
            )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY legalease_document_insert ON public.documents
        FOR INSERT WITH CHECK (
            owner_id = NULLIF(current_setting('app.user_id', true), '')::integer
        )
        """
    )
    op.execute(
        """
        CREATE POLICY legalease_document_update ON public.documents
        FOR UPDATE
        USING (
            public.legalease_can_edit_document(
                id, NULLIF(current_setting('app.user_id', true), '')::integer
            )
        )
        WITH CHECK (
            public.legalease_can_edit_document(
                id, NULLIF(current_setting('app.user_id', true), '')::integer
            )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY legalease_document_delete ON public.documents
        FOR DELETE USING (
            owner_id = NULLIF(current_setting('app.user_id', true), '')::integer
        )
        """
    )
    op.execute("ALTER TABLE public.document_shares ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY legalease_share_select ON public.document_shares
        FOR SELECT USING (
            user_id = NULLIF(current_setting('app.user_id', true), '')::integer
            OR shared_by_id = NULLIF(current_setting('app.user_id', true), '')::integer
            OR public.legalease_is_document_owner(
                document_id, NULLIF(current_setting('app.user_id', true), '')::integer
            )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY legalease_share_owner_manage ON public.document_shares
        FOR ALL
        USING (
            public.legalease_is_document_owner(
                document_id, NULLIF(current_setting('app.user_id', true), '')::integer
            )
        )
        WITH CHECK (
            public.legalease_is_document_owner(
                document_id, NULLIF(current_setting('app.user_id', true), '')::integer
            )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY legalease_reviewer_update ON public.document_shares
        FOR UPDATE
        USING (
            user_id = NULLIF(current_setting('app.user_id', true), '')::integer
            AND permission = 'reviewer'
            AND EXISTS (
                SELECT 1 FROM public.users u
                WHERE u.id = NULLIF(current_setting('app.user_id', true), '')::integer
                  AND u.role = 'legal_reviewer'
            )
        )
        WITH CHECK (
            user_id = NULLIF(current_setting('app.user_id', true), '')::integer
            AND permission = 'reviewer'
            AND EXISTS (
                SELECT 1 FROM public.users u
                WHERE u.id = NULLIF(current_setting('app.user_id', true), '')::integer
                  AND u.role = 'legal_reviewer'
            )
        )
        """
    )
    role = os.getenv("APP_DB_ROLE", "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", role):
        raise RuntimeError("Set APP_DB_ROLE to the non-owner PostgreSQL runtime role before migration.")
    op.execute(f'GRANT SELECT, INSERT, DELETE ON ALL TABLES IN SCHEMA public TO "{role}"')
    op.execute(f'GRANT UPDATE ON public.users, public.auth_tokens, public.auth_sessions TO "{role}"')
    op.execute(
        f'GRANT UPDATE (title, document_type, party_details, terms, effective_date, jurisdiction, generated_content, updated_at) '
        f'ON public.documents TO "{role}"'
    )
    op.execute(
        f'GRANT UPDATE (review_status, review_comment, updated_at) ON public.document_shares TO "{role}"'
    )
    op.execute(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{role}"')
    op.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, DELETE ON TABLES TO "{role}"')
    op.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{role}"')
    for signature in (
        "public.legalease_is_document_owner(integer, integer)",
        "public.legalease_can_view_document(integer, integer)",
        "public.legalease_can_edit_document(integer, integer)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        op.execute(f'GRANT EXECUTE ON FUNCTION {signature} TO "{role}"')


def downgrade() -> None:
    raise RuntimeError("This security migration is intentionally irreversible; restore a database backup instead.")
