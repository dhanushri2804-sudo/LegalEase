from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import AuthSession, User

PASSWORD_HASHER = PasswordHasher()
bearer_scheme = HTTPBearer(auto_error=False)


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("JWT_SECRET_KEY must be set to a random value of at least 32 characters.")
    return secret


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be between 12 and 256 characters.")
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_expired(expiry: datetime) -> bool:
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry <= datetime.now(timezone.utc)


def set_database_user_context(db: Session, user_id: int) -> None:
    if db.bind and db.bind.dialect.name == "postgresql":
        db.execute(select(func.set_config("app.user_id", str(user_id), True)))


def create_access_token(user: User, session_id: str) -> str:
    now = datetime.now(timezone.utc)
    expires_minutes = int(os.getenv("ACCESS_TOKEN_MINUTES", "10"))
    return jwt.encode(
        {
            "sub": str(user.id),
            "ver": user.token_version,
            "iat": now,
            "exp": now + timedelta(minutes=expires_minutes),
            "jti": secrets.token_urlsafe(16),
            "sid": session_id,
            "type": "access",
        },
        _jwt_secret(),
        algorithm="HS256",
    )
def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def create_download_token(
    user: User,
    session_id: str,
    document_id: int,
    file_type: Literal["txt", "docx", "pdf"],
) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user.id),
            "doc": document_id,
            "file": file_type,
            "sid": session_id,
            "ver": user.token_version,
            "iat": now,
            "exp": now + timedelta(seconds=60),
            "jti": secrets.token_urlsafe(16),
            "type": "download",
        },
        _jwt_secret(),
        algorithm="HS256",
    )


def require_csrf(request: Request) -> None:
    cookie_token = request.cookies.get("legalease_csrf")
    header_token = request.headers.get("x-csrf-token")
    if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed.")


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(credentials.credentials, _jwt_secret(), algorithms=["HS256"])
        if payload.get("type") != "access":
            raise jwt.InvalidTokenError("Wrong token type")
        user_id = int(payload["sub"])
        token_version = int(payload.get("ver", -1))
        session_id = str(payload["sid"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is unavailable or the session has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    set_database_user_context(db, user.id)
    request.state.user_id = user.id
    request.state.session_id = session_id
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        return user

    return dependency
