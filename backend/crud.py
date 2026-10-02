from __future__ import annotations

from typing import Sequence

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.models import Document, DocumentShare
from backend.schemas import DocumentCreate, DocumentUpdate


def create_document(db: Session, document_data: DocumentCreate, owner_id: int) -> Document:
    values = document_data.model_dump(exclude={"organization_id"})
    record = Document(**values, owner_id=owner_id, organization_id=document_data.organization_id)
    db.add(record)
    db.flush()
    return record


def get_accessible_document(db: Session, document_id: int, user_id: int, user_role: str) -> Document | None:
    return db.execute(
        select(Document)
        .outerjoin(DocumentShare, DocumentShare.document_id == Document.id)
        .where(
            Document.id == document_id,
            or_(
                Document.owner_id == user_id,
                (
                    (DocumentShare.user_id == user_id)
                    & ((DocumentShare.permission != "reviewer") | (user_role == "legal_reviewer"))
                ),
            ),
        )
    ).scalars().first()


def get_documents(
    db: Session,
    user_id: int,
    user_role: str,
    search: str | None = None,
    document_type: str | None = None,
) -> Sequence[Document]:
    query = (
        select(Document)
        .outerjoin(DocumentShare, DocumentShare.document_id == Document.id)
        .where(
            or_(
                Document.owner_id == user_id,
                (
                    (DocumentShare.user_id == user_id)
                    & ((DocumentShare.permission != "reviewer") | (user_role == "legal_reviewer"))
                ),
            )
        )
        .distinct()
    )

    if search and search.strip():
        search_value = f"%{search.strip()}%"
        query = query.where(
            or_(
                Document.title.ilike(search_value),
                Document.document_type.ilike(search_value),
                Document.party_details.ilike(search_value),
                Document.terms.ilike(search_value),
                Document.generated_content.ilike(search_value),
            )
        )

    if document_type and document_type.strip():
        query = query.where(Document.document_type == document_type.strip())

    query = query.order_by(Document.created_at.desc())
    return db.execute(query).scalars().all()


def update_document(
    db: Session,
    document_id: int,
    document_data: DocumentUpdate,
    user_id: int,
    user_role: str,
) -> Document | None:
    record = get_accessible_document(db, document_id, user_id, user_role)
    if not record:
        return None
    if record.owner_id != user_id:
        editable_share = db.execute(
            select(DocumentShare.id).where(
                DocumentShare.document_id == record.id,
                DocumentShare.user_id == user_id,
                DocumentShare.permission == "editor",
            )
        ).first()
        if not editable_share:
            return None

    update_values = document_data.model_dump(exclude_unset=True)
    for field, value in update_values.items():
        if value is not None or field in {"effective_date", "jurisdiction"}:
            setattr(record, field, value)

    db.flush()
    return record


def delete_document(db: Session, document_id: int, owner_id: int) -> bool:
    record = db.execute(
        select(Document).where(Document.id == document_id, Document.owner_id == owner_id)
    ).scalar_one_or_none()
    if not record:
        return False

    db.delete(record)
    db.flush()
    return True
