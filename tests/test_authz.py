from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-with-more-than-thirty-two-characters"
os.environ["ACCESS_TOKEN_MINUTES"] = "10"

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.limits import limiter
from backend.main import app
from backend.models import AuthSession, Document, User
from backend.security import hash_password


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    mail_messages: list[tuple[str, str]] = []

    def fake_send(recipient: str, subject: str, body: str) -> None:
        mail_messages.append((recipient, body))

    monkeypatch.setattr("backend.auth_routes.send_security_email", fake_send)
    limiter.enabled = False

    def override_db():
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with TestClient(app, base_url="http://localhost") as test_client:
        test_client.mail_messages = mail_messages
        test_client.test_session_factory = test_session
        yield test_client
    app.dependency_overrides.clear()
    limiter.enabled = True
    Base.metadata.drop_all(engine)
    engine.dispose()


def create_verified_user(client: TestClient, email: str, password: str = "LongSecurePassword!234") -> dict:
    response = client.post("/auth/register", json={"email": email, "password": password})
    assert response.status_code == 202
    token = client.mail_messages[-1][1].splitlines()[2]
    verified = client.post("/auth/verify-email", json={"token": token})
    assert verified.status_code == 200
    return {"email": email, "password": password}


def sign_in(client: TestClient, account: dict) -> dict:
    response = client.post("/auth/login", json=account)
    assert response.status_code == 200, response.text
    assert "refresh_token" not in response.json()
    assert "httponly" in response.headers.get("set-cookie", "").lower()
    return response.json()


def headers(session: dict) -> dict:
    return {"Authorization": f"Bearer {session['access_token']}"}


def document_payload() -> dict:
    return {
        "title": "Employment Agreement Draft",
        "document_type": "Employment Contract",
        "party_details": "First party and second party details",
        "terms": "Compensation and responsibilities specified by the parties.",
        "effective_date": "2026-10-01",
        "jurisdiction": "Example jurisdiction",
        "generated_content": "A sufficiently long test legal draft document.",
    }


def create_doc(client: TestClient, session: dict) -> int:
    response = client.post("/documents", json=document_payload(), headers=headers(session))
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_registration_verification_and_role_escalation_rejected(client: TestClient):
    response = client.post(
        "/auth/register",
        json={"email": "user@example.test", "password": "LongSecurePassword!234", "role": "admin"},
    )
    assert response.status_code == 202
    token = client.mail_messages[-1][1].splitlines()[2]
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
    user = sign_in(client, {"email": "user@example.test", "password": "LongSecurePassword!234"})
    assert user["user"]["role"] == "user"
    assert client.get("/auth/me", headers=headers(user)).json()["email"] == "user@example.test"
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400


def test_idor_crud_exports_and_admin_content_isolation(client: TestClient):
    owner = create_verified_user(client, "owner@example.test")
    other = create_verified_user(client, "other@example.test")
    owner_session = sign_in(client, owner)
    other_session = sign_in(client, other)
    document_id = create_doc(client, owner_session)

    assert client.get(f"/documents/{document_id}", headers=headers(other_session)).status_code == 404
    assert client.put(
        f"/documents/{document_id}",
        json={"generated_content": "Attempted unauthorized alteration."},
        headers=headers(other_session),
    ).status_code == 404
    assert client.delete(f"/documents/{document_id}", headers=headers(other_session)).status_code == 404
    for file_type in ("txt", "docx", "pdf"):
        assert client.post(
            f"/documents/{document_id}/export/{file_type}",
            headers=headers(other_session),
        ).status_code == 404
        assert client.post(
            f"/documents/{document_id}/signed-export/{file_type}",
            headers=headers(other_session),
        ).status_code == 404
    assert client.get("/documents", headers=headers(other_session)).json() == []

    admin_user = create_verified_user(client, "admin@example.test")
    session_factory = client.test_session_factory
    with session_factory() as db:
        admin_row = db.execute(select(User).where(User.email == admin_user["email"])).scalar_one()
        admin_row.role = "admin"
        db.commit()
    admin_session = sign_in(client, admin_user)
    assert client.get(f"/documents/{document_id}", headers=headers(admin_session)).status_code == 404
    assert client.get("/admin/users", headers=headers(admin_session)).status_code == 200


def test_explicit_shares_and_reviewer_permissions(client: TestClient):
    owner_account = create_verified_user(client, "owner2@example.test")
    reviewer_account = create_verified_user(client, "reviewer@example.test")
    viewer_account = create_verified_user(client, "viewer@example.test")
    session_factory = client.test_session_factory
    with session_factory() as db:
        reviewer = db.execute(select(User).where(User.email == reviewer_account["email"])).scalar_one()
        reviewer.role = "legal_reviewer"
        db.commit()

    owner_session = sign_in(client, owner_account)
    reviewer_session = sign_in(client, reviewer_account)
    viewer_session = sign_in(client, viewer_account)
    document_id = create_doc(client, owner_session)
    shared = client.post(
        f"/documents/{document_id}/shares",
        json={"email": viewer_account["email"], "permission": "viewer"},
        headers=headers(owner_session),
    )
    assert shared.status_code == 201
    assert client.get(f"/documents/{document_id}", headers=headers(viewer_session)).status_code == 200
    assert client.post(
        f"/documents/{document_id}/review",
        json={"status": "approved", "comment": "Looks good."},
        headers=headers(reviewer_session),
    ).status_code == 404
    assert client.put(
        f"/documents/{document_id}",
        json={"generated_content": "Viewer changes are blocked by server."},
        headers=headers(viewer_session),
    ).status_code == 404
    assert client.post(
        f"/documents/{document_id}/shares",
        json={"email": reviewer_account["email"], "permission": "reviewer"},
        headers=headers(owner_session),
    ).status_code == 201
    reviewed = client.post(
        f"/documents/{document_id}/review",
        json={"status": "changes_requested", "comment": "Please clarify the termination section."},
        headers=headers(reviewer_session),
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["review_status"] == "changes_requested"

    shares = client.get(f"/documents/{document_id}/shares", headers=headers(owner_session)).json()
    reviewer_share = next(row for row in shares if row["user_id"] == reviewer_session["user"]["id"])
    revoked = client.delete(
        f"/documents/{document_id}/shares/{reviewer_share['id']}",
        headers=headers(owner_session),
    )
    assert revoked.status_code == 204
    assert client.get(f"/documents/{document_id}", headers=headers(reviewer_session)).status_code == 404


def test_signed_export_and_refresh_rotation_logout_and_expiry(client: TestClient):
    account = create_verified_user(client, "session@example.test")
    session = sign_in(client, account)
    document_id = create_doc(client, session)
    signed = client.post(
        f"/documents/{document_id}/signed-export/pdf",
        headers=headers(session),
    )
    assert signed.status_code == 200
    signed_download = client.get(signed.json()["url"])
    assert signed_download.status_code == 200
    assert signed_download.content.startswith(b"%PDF")

    expired = jwt.encode(
        {
            "sub": str(session["user"]["id"]),
            "ver": 0,
            "sid": "not-a-session",
            "iat": datetime.now(timezone.utc) - timedelta(minutes=2),
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
            "type": "access",
        },
        os.environ["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401

    old_refresh = client.cookies.get("legalease_refresh")
    csrf = client.cookies.get("legalease_csrf")
    refreshed = client.post("/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"] != session["access_token"]
    current_csrf = client.cookies.get("legalease_csrf")
    client.cookies.clear()
    client.cookies.set("legalease_refresh", old_refresh, path="/auth")
    client.cookies.set("legalease_csrf", current_csrf, path="/auth")
    replayed = client.post(
        "/auth/refresh",
        headers={"X-CSRF-Token": current_csrf},
    )
    assert replayed.status_code == 401
    assert client.get("/auth/me", headers=headers(refreshed.json())).status_code == 401

    client.cookies.clear()
    logged_back_in = sign_in(client, account)
    csrf = client.cookies.get("legalease_csrf")
    logout_response = client.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout_response.status_code == 204
    assert client.get(f"/documents/{document_id}", headers=headers(logged_back_in)).status_code == 401
    assert client.get(signed.json()["url"]).status_code == 401


def test_password_reset_revokes_existing_sessions(client: TestClient):
    account = create_verified_user(client, "reset@example.test")
    old_session = sign_in(client, account)
    requested = client.post("/auth/password-reset/request", json={"email": account["email"]})
    assert requested.status_code == 202
    token = client.mail_messages[-1][1].splitlines()[2]
    reset = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "AnEvenLongerSecurePassword!567"},
    )
    assert reset.status_code == 200
    assert client.get("/auth/me", headers=headers(old_session)).status_code == 401
    assert client.post("/auth/password-reset/confirm", json={
        "token": token,
        "new_password": "AnEvenLongerSecurePassword!567",
    }).status_code == 400
    assert client.post(
        "/auth/login",
        json={"email": account["email"], "password": "AnEvenLongerSecurePassword!567"},
    ).status_code == 200


def test_owner_can_export_and_change_only_own_document(client: TestClient):
    account = create_verified_user(client, "owner3@example.test")
    session = sign_in(client, account)
    document_id = create_doc(client, session)
    updated = client.put(
        f"/documents/{document_id}",
        json={"generated_content": "Owner can update this safe draft text."},
        headers=headers(session),
    )
    assert updated.status_code == 200
    assert updated.json()["generated_content"] == "Owner can update this safe draft text."
    for file_type, content_type in (
        ("txt", "text/plain"),
        ("docx", "application/vnd.openxmlformats-officedocument"),
        ("pdf", "application/pdf"),
    ):
        output = client.post(f"/documents/{document_id}/export/{file_type}", headers=headers(session))
        assert output.status_code == 200
        assert content_type in output.headers["content-type"]


def test_editor_share_and_signed_link_rechecks_revoked_permission(client: TestClient):
    owner_account = create_verified_user(client, "share-owner@example.test")
    editor_account = create_verified_user(client, "editor@example.test")
    owner_session = sign_in(client, owner_account)
    editor_session = sign_in(client, editor_account)
    document_id = create_doc(client, owner_session)
    share = client.post(
        f"/documents/{document_id}/shares",
        json={"email": editor_account["email"], "permission": "editor"},
        headers=headers(owner_session),
    )
    assert share.status_code == 201
    update_response = client.put(
        f"/documents/{document_id}",
        json={"generated_content": "An explicitly shared editor can change this draft."},
        headers=headers(editor_session),
    )
    assert update_response.status_code == 200
    assert client.delete(f"/documents/{document_id}", headers=headers(editor_session)).status_code == 404

    signed_url = client.post(
        f"/documents/{document_id}/signed-export/txt",
        headers=headers(editor_session),
    ).json()["url"]
    owner_shares = client.get(f"/documents/{document_id}/shares", headers=headers(owner_session)).json()
    share_id = next(row["id"] for row in owner_shares if row["user_id"] == editor_session["user"]["id"])
    assert client.delete(
        f"/documents/{document_id}/shares/{share_id}",
        headers=headers(owner_session),
    ).status_code == 204
    assert client.get(signed_url).status_code == 404


def test_admin_role_change_and_deactivation_revoke_sessions(client: TestClient):
    admin_account = create_verified_user(client, "account-admin@example.test")
    target_account = create_verified_user(client, "account-target@example.test")
    session_factory = client.test_session_factory
    with session_factory() as db:
        admin_row = db.execute(select(User).where(User.email == admin_account["email"])).scalar_one()
        admin_row.role = "admin"
        target = db.execute(select(User).where(User.email == target_account["email"])).scalar_one()
        target_id = target.id
        db.commit()
    admin_session = sign_in(client, admin_account)
    target_session = sign_in(client, target_account)

    promoted = client.patch(
        f"/admin/users/{target_id}",
        json={"role": "legal_reviewer"},
        headers=headers(admin_session),
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "legal_reviewer"
    assert client.get("/auth/me", headers=headers(target_session)).status_code == 401
    target_session = sign_in(client, target_account)
    deactivated = client.patch(
        f"/admin/users/{target_id}",
        json={"is_active": False},
        headers=headers(admin_session),
    )
    assert deactivated.status_code == 200
    assert client.get("/auth/me", headers=headers(target_session)).status_code == 401
    assert client.post("/auth/login", json=target_account).status_code == 403
