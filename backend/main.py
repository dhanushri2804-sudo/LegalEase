from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.database import engine
from backend.limits import limiter
from backend.routes import router

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8501")
ALLOW_ORIGINS = [FRONTEND_URL]
if os.getenv("ENVIRONMENT", "development").lower() != "production":
    ALLOW_ORIGINS.extend(["http://127.0.0.1:8501", "http://localhost:8000"])


def _verify_postgres_rls() -> None:
    with engine.connect() as connection:
        role = connection.execute(
            text(
                "SELECT rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname = current_user"
            )
        ).one()
        if role.rolsuper or role.rolbypassrls:
            raise RuntimeError("The application database role must not be a PostgreSQL superuser or BYPASSRLS role.")

        for table_name in ("documents", "document_shares"):
            table = connection.execute(
                text(
                    "SELECT relrowsecurity, pg_get_userbyid(relowner) = current_user AS owned_by_app "
                    "FROM pg_class WHERE oid = to_regclass(:qualified_table)"
                ),
                {"qualified_table": f"public.{table_name}"},
            ).one_or_none()
            if not table or not table.relrowsecurity or table.owned_by_app:
                raise RuntimeError(f"PostgreSQL RLS must be enabled and the app role must not own {table_name}.")
        policies = dict(
            connection.execute(
                text(
                    "SELECT tablename, count(*) AS policy_count FROM pg_policies "
                    "WHERE schemaname = 'public' AND tablename IN ('documents', 'document_shares') "
                    "GROUP BY tablename"
                )
            ).all()
        )
        if policies.get("documents", 0) < 4 or policies.get("document_shares", 0) < 3:
            raise RuntimeError("Required LegalEase PostgreSQL row-level policies are missing.")


@asynccontextmanager
async def lifespan(_: FastAPI):
    secret = os.getenv("JWT_SECRET_KEY", "")
    if len(secret) < 32 or any(marker in secret.lower() for marker in ("change-me", "replace", "your_secret", "example")):
        raise RuntimeError("Configure JWT_SECRET_KEY with at least 32 random characters before startup.")
    try:
        access_minutes = int(os.getenv("ACCESS_TOKEN_MINUTES", "10"))
        refresh_days = int(os.getenv("REFRESH_TOKEN_DAYS", "14"))
    except ValueError as exc:
        raise RuntimeError("Token lifetime settings must be integers.") from exc
    if not 1 <= access_minutes <= 30 or not 1 <= refresh_days <= 30:
        raise RuntimeError("Access tokens must last 1–30 minutes and refresh sessions 1–30 days.")
    if os.getenv("ENVIRONMENT", "development").lower() == "production":
        if os.getenv("COOKIE_SECURE", "false").lower() != "true":
            raise RuntimeError("COOKIE_SECURE=true is required in production.")
        if os.getenv("FORCE_HTTPS", "false").lower() != "true":
            raise RuntimeError("FORCE_HTTPS=true is required in production.")
        if engine.dialect.name != "postgresql":
            raise RuntimeError("PostgreSQL is required in production.")
        if not os.getenv("BACKEND_URL", "").startswith("https://"):
            raise RuntimeError("BACKEND_URL must use HTTPS in production.")
        if not (os.getenv("SMTP_USE_SSL", "false").lower() == "true" or os.getenv("SMTP_STARTTLS", "true").lower() == "true"):
            raise RuntimeError("SMTP TLS is required in production.")
        if not os.getenv("SMTP_HOST") or not os.getenv("SMTP_FROM"):
            raise RuntimeError("SMTP_HOST and SMTP_FROM are required in production.")
        if not os.getenv("RATE_LIMIT_STORAGE_URI", "").startswith(("redis://", "rediss://")):
            raise RuntimeError("A shared Redis rate-limit store is required in production.")
        if any(origin.startswith("http://") for origin in ALLOW_ORIGINS):
            raise RuntimeError("Production FRONTEND_URL and CORS origins must use HTTPS.")
        if "*" in allowed_hosts:
            raise RuntimeError("Wildcard ALLOWED_HOSTS are not permitted in production.")
        _verify_postgres_rls()
    yield


app = FastAPI(
    title="LegalEase",
    description="AI-assisted legal document drafts with secure multi-user access.",
    version="2.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(request, exc: RequestValidationError):
    del request
    sanitized = [
        {"loc": error.get("loc"), "msg": error.get("msg"), "type": error.get("type")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": sanitized})


@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc: SQLAlchemyError):
    del request
    logger.error("Database operation failed (%s).", type(exc).__name__)
    return JSONResponse(status_code=503, content={"detail": "Database operation failed. Please try again."})


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)

allowed_hosts = [host.strip() for host in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if host.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
if os.getenv("FORCE_HTTPS", "false").lower() == "true":
    from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

    app.add_middleware(HTTPSRedirectMiddleware)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if os.getenv("COOKIE_SECURE", "false").lower() == "true":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

app.include_router(router)
