import os
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.limits import limiter
from backend.mail import send_security_email
from backend.models import AuditLog, AuthSession, AuthToken, User
from backend.schemas import (
    AuthUserOut,
    LoginRequest,
    LoginResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    RegisterRequest,
    TokenInput,
)
from backend.security import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    hash_token,
    is_expired,
    require_csrf,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = logging.getLogger(__name__)
REFRESH_COOKIE = "legalease_refresh"
CSRF_COOKIE = "legalease_csrf"


def _token_expiry(row: AuthToken) -> bool:
    return is_expired(row.expires_at)


def _refresh_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=int(os.getenv("REFRESH_TOKEN_DAYS", "14")))


def _set_session_cookies(response: Response, refresh_token: str, csrf_token: str) -> None:
    secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    cookie_lifetime = int(os.getenv("REFRESH_TOKEN_DAYS", "14")) * 24 * 60 * 60
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=cookie_lifetime,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/auth",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=cookie_lifetime,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/auth",
    )


def _clear_session_cookies(response: Response) -> None:
    secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    response.delete_cookie(REFRESH_COOKIE, path="/auth", secure=secure, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/auth", secure=secure, httponly=False, samesite="strict")


def _issue_access(user: User, session_id: str) -> LoginResponse:
    return LoginResponse(
        access_token=create_access_token(user, session_id),
        expires_in=int(os.getenv("ACCESS_TOKEN_MINUTES", "10")) * 60,
        user=AuthUserOut.model_validate(user),
    )


def _new_one_time_token(db: Session, user: User, purpose: str, lifetime: timedelta) -> str:
    db.execute(
        update(AuthToken)
        .where(
            AuthToken.user_id == user.id,
            AuthToken.purpose == purpose,
            AuthToken.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )
    raw_token = secrets.token_urlsafe(32)
    db.add(
        AuthToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            purpose=purpose,
            expires_at=datetime.now(timezone.utc) + lifetime,
        )
    )
    db.flush()
    return raw_token


def _send_account_email(user: User, raw_token: str, purpose: str) -> None:
    if purpose == "email_verification":
        subject = "Verify your LegalEase email"
        instructions = "Enter this one-time verification token in LegalEase:"
    else:
        subject = "Reset your LegalEase password"
        instructions = "Enter this one-time password reset token in LegalEase:"
    send_security_email(user.email, subject, f"{instructions}\n\n{raw_token}\n\nIf you did not request this, ignore this email.")


@router.post("/register", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    email = payload.email.strip().lower()
    if db.execute(select(User.id).where(User.email == email)).first():
        return {"message": "If registration can be completed, a verification email will be sent."}

    try:
        user = User(email=email, password_hash=hash_password(payload.password), role="user")
        db.add(user)
        db.flush()
        raw_token = _new_one_time_token(db, user, "email_verification", timedelta(hours=24))
        db.add(AuditLog(actor_id=user.id, action="user_registered", target_type="user", target_id=str(user.id)))
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except IntegrityError:
        db.rollback()
        return {"message": "If registration can be completed, a verification email will be sent."}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Registration is temporarily unavailable.") from exc

    try:
        _send_account_email(user, raw_token, "email_verification")
    except RuntimeError:
        logger.error("Email delivery failed during account verification setup.")
    return {"message": "If registration can be completed, a verification email will be sent."}


@router.post("/verify-email")
@limiter.limit("10/hour")
def verify_email(payload: TokenInput, request: Request, db: Session = Depends(get_db)) -> dict:
    record = db.execute(
        select(AuthToken).where(
            AuthToken.token_hash == hash_token(payload.token),
            AuthToken.purpose == "email_verification",
            AuthToken.revoked_at.is_(None),
        )
        .with_for_update()
    ).scalar_one_or_none()
    if not record or _token_expiry(record):
        raise HTTPException(status_code=400, detail="Verification token is invalid or expired.")
    user = db.get(User, record.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Verification token is invalid or expired.")

    record.revoked_at = datetime.now(timezone.utc)
    user.is_verified = True
    db.add(user)
    db.add(AuditLog(actor_id=user.id, action="email_verified", target_type="user", target_id=str(user.id)))
    db.commit()
    return {"message": "Email verified. You can now sign in."}


@router.post("/verification/resend", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
def resend_verification(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    user = db.execute(select(User).where(User.email == payload.email.strip().lower())).scalar_one_or_none()
    if not user or user.is_verified or not user.is_active or not verify_password(payload.password, user.password_hash):
        return {"message": "If the account requires verification, an email will be sent."}
    raw_token = _new_one_time_token(db, user, "email_verification", timedelta(hours=24))
    db.commit()
    try:
        _send_account_email(user, raw_token, "email_verification")
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Email delivery is not configured.") from exc
    return {"message": "If the account requires verification, an email will be sent."}


@router.post("/login", response_model=LoginResponse)
@limiter.limit("10/minute")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.execute(select(User).where(User.email == payload.email.strip().lower())).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated.")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verify your email before signing in.")

    refresh_token = create_refresh_token()
    session_id = str(uuid.uuid4())
    db.add(
        AuthSession(
            id=session_id,
            user_id=user.id,
            refresh_hash=hash_token(refresh_token),
            expires_at=_refresh_expiry(),
        )
    )
    db.add(AuditLog(actor_id=user.id, action="login", target_type="user", target_id=str(user.id)))
    db.commit()

    csrf_token = secrets.token_urlsafe(32)
    _set_session_cookies(response, refresh_token, csrf_token)
    return _issue_access(user, session_id)


@router.post("/refresh", response_model=LoginResponse, dependencies=[Depends(require_csrf)])
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> LoginResponse:
    raw_token = request.cookies.get(REFRESH_COOKIE)
    if not raw_token:
        raise HTTPException(status_code=401, detail="Refresh session is missing.")
    session = db.execute(
        select(AuthSession).where(
            AuthSession.refresh_hash == hash_token(raw_token),
            AuthSession.revoked_at.is_(None),
        )
        .with_for_update()
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if not session:
        spent_token = db.execute(
            select(AuthToken).where(
                AuthToken.token_hash == hash_token(raw_token),
                AuthToken.purpose == "refresh",
                AuthToken.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
        if spent_token and spent_token.session_id:
            reused_session = db.get(AuthSession, spent_token.session_id)
            if reused_session and reused_session.revoked_at is None:
                reused_session.revoked_at = now
                db.add(
                    AuditLog(
                        actor_id=reused_session.user_id,
                        action="refresh_token_reuse",
                        target_type="session",
                        target_id=reused_session.id,
                    )
                )
                db.commit()
        raise HTTPException(status_code=401, detail="Refresh session is invalid or expired.")
    if not session or is_expired(session.expires_at):
        raise HTTPException(status_code=401, detail="Refresh session is invalid or expired.")
    user = db.get(User, session.user_id)
    if not user or not user.is_active or not user.is_verified:
        session.revoked_at = now
        db.commit()
        raise HTTPException(status_code=401, detail="Account is unavailable.")

    rotated_token = create_refresh_token()
    new_expiry = _refresh_expiry()
    db.add(
        AuthToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            purpose="refresh",
            session_id=session.id,
            expires_at=new_expiry,
        )
    )
    session.refresh_hash = hash_token(rotated_token)
    session.expires_at = new_expiry
    db.add(AuditLog(actor_id=user.id, action="token_refresh", target_type="session", target_id=session.id))
    db.commit()
    _set_session_cookies(response, rotated_token, secrets.token_urlsafe(32))
    return _issue_access(user, session.id)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_csrf)])
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    raw_token = request.cookies.get(REFRESH_COOKIE)
    if raw_token:
        session = db.execute(select(AuthSession).where(AuthSession.refresh_hash == hash_token(raw_token))).scalar_one_or_none()
        if session and session.revoked_at is None:
            session.revoked_at = datetime.now(timezone.utc)
            db.add(AuditLog(actor_id=session.user_id, action="logout", target_type="session", target_id=session.id))
            db.commit()
    _clear_session_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=AuthUserOut)
def current_user(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/hour")
def request_password_reset(payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    user = db.execute(select(User).where(User.email == payload.email.strip().lower())).scalar_one_or_none()
    if user and user.is_active:
        token = _new_one_time_token(db, user, "password_reset", timedelta(minutes=30))
        db.commit()
        try:
            _send_account_email(user, token, "password_reset")
        except RuntimeError:
            logger.warning("Security email delivery failed for a password reset request.")
    return {"message": "If the account exists, password reset instructions will be sent."}


@router.post("/password-reset/confirm")
@limiter.limit("10/hour")
def confirm_password_reset(payload: PasswordResetConfirm, request: Request, db: Session = Depends(get_db)) -> dict:
    raw_token = payload.token

    record = db.execute(
        select(AuthToken).where(
            AuthToken.token_hash == hash_token(raw_token),
            AuthToken.purpose == "password_reset",
            AuthToken.revoked_at.is_(None),
        )
        .with_for_update()
    ).scalar_one_or_none()
    if not record or _token_expiry(record):
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired.")
    user = db.get(User, record.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired.")

    now = datetime.now(timezone.utc)
    try:
        password_hash = hash_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record.revoked_at = now
    user.password_hash = password_hash
    user.token_version += 1
    db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).update(
        {AuthSession.revoked_at: now}
    )
    db.add(AuditLog(actor_id=user.id, action="password_reset", target_type="user", target_id=str(user.id)))
    db.commit()
    return {"message": "Password updated. Please sign in again."}
