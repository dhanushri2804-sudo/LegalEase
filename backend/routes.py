from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Literal, Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.ai_core.gemini_generator import GeminiDocumentGenerator
from backend.auth_routes import router as auth_router
from backend.crud import (
    create_document,
    delete_document,
    get_accessible_document,
    get_documents,
    update_document,
)
from backend.database import get_db
from backend.models import (
    AuditLog,
    AuthSession,
    Document,
    DocumentShare,
    Organization,
    OrganizationMembership,
    User,
)
from backend.schemas import (
    AdminUserOut,
    AdminUserUpdate,
    DocumentCreate,
    DocumentOut,
    DocumentUpdate,
    GenerateRequest,
    GenerateResponse,
    OrganizationCreate,
    OrganizationOut,
    ReviewInput,
    ShareCreate,
    ShareOut,
)
from backend.security import (
    create_download_token,
    get_current_user,
    is_expired,
    require_roles,
    set_database_user_context,
)
from backend.utils.document_formatter import format_docx, format_pdf, format_txt

router = APIRouter()
router.include_router(auth_router)


def _slugify(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    return cleaned.strip("-") or "document"


def _audit(db: Session, user: User, action: str, target_type: str, target_id: int | str) -> None:
    db.add(AuditLog(actor_id=user.id, action=action, target_type=target_type, target_id=str(target_id)))


def _authorized_document(db: Session, document_id: int, user: User) -> Document:
    document = get_accessible_document(db, document_id, user.id, user.role)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found.")
    return document


def _require_owner(db: Session, document: Document, user: User) -> None:
    if document.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Document not found.")


@router.get("/")
def read_root() -> dict:
    return {"app": "LegalEase", "message": "Welcome to the LegalEase API."}


@router.get("/health")
def health_check(db: Session = Depends(get_db)) -> dict:
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected", "backend": "running"}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="Database connection failed.") from exc


@router.post("/generate", response_model=GenerateResponse)
def generate_document(payload: GenerateRequest, user: User = Depends(get_current_user)):
    del user
    try:
        generator = GeminiDocumentGenerator()
        result = generator.generate_document(payload.model_dump())
        return GenerateResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Document generation is not configured.") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to generate the document at this time.") from exc


@router.post("/documents", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
def save_document(
    payload: DocumentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Document:
    if payload.organization_id is not None:
        membership = db.execute(
            select(OrganizationMembership.id).where(
                OrganizationMembership.organization_id == payload.organization_id,
                OrganizationMembership.user_id == user.id,
            )
        ).first()
        if not membership:
            raise HTTPException(status_code=404, detail="Organization not found.")
    try:
        record = create_document(db, payload, owner_id=user.id)
        _audit(db, user, "document_created", "document", record.id)
        db.commit()
        db.refresh(record)
        return record
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error while saving the document.") from exc


@router.get("/documents", response_model=list[DocumentOut])
def list_documents(
    search: Optional[str] = Query(default=None, max_length=200),
    document_type: Optional[str] = Query(default=None, max_length=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return get_documents(db, user_id=user.id, user_role=user.role, search=search, document_type=document_type)


@router.get("/documents/{document_id}", response_model=DocumentOut)
def get_document(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Document:
    document = _authorized_document(db, document_id, user)
    _audit(db, user, "document_viewed", "document", document.id)
    db.commit()
    return document


@router.put("/documents/{document_id}", response_model=DocumentOut)
def update_document_route(
    document_id: int,
    payload: DocumentUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Document:
    _authorized_document(db, document_id, user)
    try:
        updated = update_document(db, document_id, payload, user.id, user.role)
        if not updated:
            raise HTTPException(status_code=404, detail="Document not found.")
        _audit(db, user, "document_updated", "document", document_id)
        db.commit()
        db.refresh(updated)
        return updated
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error while updating the document.") from exc


@router.delete("/documents/{document_id}")
def delete_document_route(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    document = _authorized_document(db, document_id, user)
    _require_owner(db, document, user)
    try:
        _audit(db, user, "document_deleted", "document", document_id)
        deleted = delete_document(db, document_id, owner_id=user.id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Document not found.")
        db.commit()
        return {"message": "Document deleted successfully", "document_id": document_id}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error while deleting the document.") from exc


def _document_export(document_id: int, db: Session, user: User, file_type: str) -> tuple[Document, bytes, str, str]:
    record = _authorized_document(db, document_id, user)
    _audit(db, user, "document_exported", "document", document_id)
    db.commit()
    filename = f"{_slugify(record.title)}.{file_type}"
    if file_type == "txt":
        return record, format_txt(record).encode("utf-8"), filename, "text/plain; charset=utf-8"
    if file_type == "docx":
        return (
            record,
            format_docx(record),
            filename,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    return record, format_pdf(record), filename, "application/pdf"


@router.get("/documents/{document_id}/permissions")
def document_permissions(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    document = _authorized_document(db, document_id, user)
    share = db.execute(
        select(DocumentShare).where(
            DocumentShare.document_id == document_id,
            DocumentShare.user_id == user.id,
        )
    ).scalar_one_or_none()
    is_owner = document.owner_id == user.id
    permission = "owner" if is_owner else (share.permission if share else "viewer")
    return {
        "is_owner": is_owner,
        "can_edit": is_owner or permission == "editor",
        "can_share": is_owner,
        "can_delete": is_owner,
        "can_review": bool(share and share.permission == "reviewer" and user.role == "legal_reviewer"),
        "permission": permission,
    }


@router.post("/documents/{document_id}/signed-export/{file_type}")
def create_signed_export_url(
    document_id: int,
    file_type: Literal["txt", "docx", "pdf"],
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _authorized_document(db, document_id, user)
    return {
        "url": f"/downloads/{create_download_token(user, request.state.session_id, document_id, file_type)}",
        "expires_in": 60,
    }


@router.get("/downloads/{signed_token}", response_model=None)
def download_signed_export(
    signed_token: str,
    db: Session = Depends(get_db),
) -> Response | StreamingResponse:
    try:
        payload = jwt.decode(signed_token, os.getenv("JWT_SECRET_KEY", ""), algorithms=["HS256"])
        if payload.get("type") != "download":
            raise jwt.InvalidTokenError("Wrong token type")
        user_id = int(payload["sub"])
        document_id = int(payload["doc"])
        file_type = payload["file"]
        session_id = str(payload["sid"])
        token_version = int(payload["ver"])
        if file_type not in {"txt", "docx", "pdf"}:
            raise jwt.InvalidTokenError("Invalid export type")
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Download link is invalid or expired.") from exc

    user = db.get(User, user_id)
    auth_session = db.get(AuthSession, session_id)
    if (
        not user
        or not user.is_active
        or not user.is_verified
        or user.token_version != token_version
        or not auth_session
        or auth_session.user_id != user.id
        or auth_session.revoked_at is not None
        or is_expired(auth_session.expires_at)
    ):
        raise HTTPException(status_code=401, detail="Download link is invalid or expired.")
    set_database_user_context(db, user.id)
    record, data, filename, media_type = _document_export(document_id, db, user, file_type)
    del record
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if file_type == "txt":
        return Response(content=data, media_type=media_type, headers=headers)
    return StreamingResponse(iter([data]), media_type=media_type, headers=headers)


@router.post("/documents/{document_id}/export/txt")
def export_txt(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    _, data, filename, media_type = _document_export(document_id, db, user, "txt")
    return Response(content=data, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/documents/{document_id}/export/docx")
def export_docx(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    _, data, filename, media_type = _document_export(document_id, db, user, "docx")
    return StreamingResponse(iter([data]), media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/documents/{document_id}/export/pdf")
def export_pdf(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    _, data, filename, media_type = _document_export(document_id, db, user, "pdf")
    return StreamingResponse(iter([data]), media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/documents/{document_id}/shares", response_model=list[ShareOut])
def list_shares(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[DocumentShare]:
    document = _authorized_document(db, document_id, user)
    _require_owner(db, document, user)
    return db.execute(select(DocumentShare).where(DocumentShare.document_id == document_id)).scalars().all()


@router.post("/documents/{document_id}/shares", response_model=ShareOut, status_code=status.HTTP_201_CREATED)
def share_document(
    document_id: int,
    payload: ShareCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DocumentShare:
    document = _authorized_document(db, document_id, user)
    _require_owner(db, document, user)
    recipient = db.execute(select(User).where(User.email == payload.email.strip().lower())).scalar_one_or_none()
    if not recipient or not recipient.is_active or not recipient.is_verified or recipient.id == user.id:
        raise HTTPException(status_code=404, detail="Eligible recipient not found.")
    if payload.permission == "reviewer" and recipient.role != "legal_reviewer":
        raise HTTPException(status_code=422, detail="Reviewer access can only be granted to a legal reviewer.")

    share = db.execute(
        select(DocumentShare).where(
            DocumentShare.document_id == document_id,
            DocumentShare.user_id == recipient.id,
        )
    ).scalar_one_or_none()
    if share:
        db.delete(share)
        db.flush()
    share = DocumentShare(
        document_id=document_id,
        user_id=recipient.id,
        shared_by_id=user.id,
        permission=payload.permission,
    )
    db.add(share)
    _audit(db, user, "document_shared", "document", document_id)
    db.commit()
    db.refresh(share)
    return share


@router.delete("/documents/{document_id}/shares/{share_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_share(
    document_id: int,
    share_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    document = _authorized_document(db, document_id, user)
    _require_owner(db, document, user)
    share = db.execute(
        select(DocumentShare).where(
            DocumentShare.id == share_id,
            DocumentShare.document_id == document_id,
        )
    ).scalar_one_or_none()
    if not share:
        raise HTTPException(status_code=404, detail="Share not found.")
    db.delete(share)
    _audit(db, user, "document_share_revoked", "document", document_id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/documents/{document_id}/review", response_model=ShareOut)
def review_document(
    document_id: int,
    payload: ReviewInput,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DocumentShare:
    if user.role != "legal_reviewer":
        raise HTTPException(status_code=403, detail="Only legal reviewers can submit a review.")
    _authorized_document(db, document_id, user)
    share = db.execute(
        select(DocumentShare).where(
            DocumentShare.document_id == document_id,
            DocumentShare.user_id == user.id,
            DocumentShare.permission == "reviewer",
        )
    ).scalar_one_or_none()
    if not share:
        raise HTTPException(status_code=404, detail="Document not found.")
    share.review_status = payload.status
    share.review_comment = payload.comment
    _audit(db, user, "document_reviewed", "document", document_id)
    db.commit()
    db.refresh(share)
    return share


@router.post("/organizations", response_model=OrganizationOut, status_code=status.HTTP_201_CREATED)
def create_organization(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Organization:
    organization = Organization(name=payload.name.strip(), created_by_id=user.id)
    db.add(organization)
    db.flush()
    db.add(OrganizationMembership(organization_id=organization.id, user_id=user.id, role="owner"))
    db.add(AuditLog(actor_id=user.id, action="organization_created", target_type="organization", target_id=str(organization.id)))
    db.commit()
    db.refresh(organization)
    return organization


@router.get("/organizations", response_model=list[OrganizationOut])
def list_organizations(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Organization]:
    return db.execute(
        select(Organization)
        .join(OrganizationMembership, OrganizationMembership.organization_id == Organization.id)
        .where(OrganizationMembership.user_id == user.id)
    ).scalars().all()


@router.get("/admin/users", response_model=list[AdminUserOut])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("admin")),
) -> list[AdminUserOut]:
    _audit(db, admin, "user_accounts_listed", "user", "all")
    db.commit()
    rows = db.execute(select(User).order_by(User.id)).scalars().all()
    return [AdminUserOut.model_validate(user) for user in rows]


@router.patch("/admin/users/{user_id}")
def update_user_account(
    user_id: int,
    payload: AdminUserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles("admin")),
) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status_code=422, detail="At least one account field must be supplied.")
    if user.id == admin.id and values.get("role", user.role) != "admin":
        raise HTTPException(status_code=400, detail="Administrators cannot remove their own admin role.")
    if "role" in values:
        user.role = values["role"]
    if "is_active" in values:
        user.is_active = values["is_active"]
    user.token_version += 1
    revoked_at = datetime.now(timezone.utc)
    db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).update(
        {AuthSession.revoked_at: revoked_at}
    )
    _audit(db, admin, "user_account_updated", "user", user.id)
    db.commit()
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
    }
