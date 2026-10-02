# LegalEase – secure multi-user legal draft generator

LegalEase keeps the Streamlit UI, FastAPI service, Gemini generation, editing, and TXT/DOCX/PDF export, and adds PostgreSQL persistence, verified accounts, scoped sessions, sharing, reviewer workflow, and server-enforced ownership.

LegalEase generates draft documents, not legal advice. It does not guarantee validity or enforceability. Documents should be reviewed by a qualified legal professional.

## Security and data boundaries

- New registrations always receive the `user` role. The server derives `owner_id` from the verified access token; client-supplied owner IDs are not accepted.
- Access JWTs expire after 10 minutes by default. Rotating refresh credentials are opaque, stored only as hashes, placed in `HttpOnly`, `SameSite=Strict` cookies, and checked against revocable database sessions. The Streamlit server holds cookies/access credentials in that user's server-side session; the UI never renders them.
- Refresh and logout require a matching CSRF cookie/header. In production cookies require `Secure=true`.
- Email verification and password-reset codes are random, single-use, short-lived, and stored as hashes. Configure SMTP; token values and document contents are not logged.
- Owners can read/edit/delete/share their own documents. Shared recipients can only access explicitly shared documents; `viewer`, `editor`, and `reviewer` permissions are enforced by the API. A legal reviewer can submit a review only for a document explicitly shared with reviewer permission. Admins manage accounts/roles but do not inherit document access.
- Export requests are authorized. The UI obtains a 60-second signed download URL; the URL handler rechecks account and document permissions before returning the export.
- PostgreSQL deployments use row-level policies as an additional document/share access boundary. The web process must connect as a non-owner, non-superuser PostgreSQL role.
- This version stores documents in the private PostgreSQL database. Do not expose its database or backups publicly; use encrypted volumes/backups and strict least-privilege access.

No application is production-secure by configuration alone. Deploy behind a maintained TLS-terminating reverse proxy, set trusted hosts/origins, use a secrets manager and private network, configure email, backups, monitoring, incident response, and privacy/retention policies. Streamlit is not a substitute for a purpose-built identity gateway; protect it behind HTTPS and keep its sessions isolated.

## Layout

```text
LegalEase/
├── backend/
│   ├── ai_core/gemini_generator.py
│   ├── migrations/versions/0001_secure_multi_user_schema.py
│   ├── migrations/versions/0002_refresh_reuse_tracking.py
│   ├── utils/document_formatter.py
│   ├── auth_routes.py
│   ├── crud.py
│   ├── database.py
│   ├── limits.py
│   ├── mail.py
│   ├── main.py
│   ├── manage_user.py
│   ├── models.py
│   ├── routes.py
│   ├── schemas.py
│   └── security.py
├── frontend/app.py
├── tests/test_authz.py
├── alembic.ini
├── .env.example
├── requirements.txt
└── README.md
```

## Local setup (Windows / VS Code)

1. Install Python 3.11+ and PostgreSQL 15+.
2. Create a migration owner, a separate restricted runtime role, and an empty database. Run the SQL below as a PostgreSQL administrator, substituting unique secrets. Apply migrations as the schema owner and run the app using the non-owner `legalease_app` role:

```sql
CREATE ROLE legalease_migrator LOGIN PASSWORD 'unique-migration-secret';
CREATE ROLE legalease_app LOGIN PASSWORD 'unique-runtime-secret';
CREATE DATABASE legalease OWNER legalease_migrator;
GRANT CONNECT ON DATABASE legalease TO legalease_app;
```

3. From the project root in PowerShell:

```powershell
 python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

4. Edit `.env`:
   - Set `DATABASE_URL` to the runtime PostgreSQL login, e.g. `postgresql+psycopg://legalease_app:<password>@localhost:5432/legalease`.
   - Generate a random `JWT_SECRET_KEY` of at least 32 characters (use a secret manager in deployment). Do not use the sample.
   - Set `GEMINI_API_KEY` from Google AI Studio and choose a supported `GEMINI_MODEL`.
   - Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, credentials, and TLS settings to deliver verification and reset email.
   - For local HTTP only, keep `COOKIE_SECURE=false`. Production must use HTTPS and set it to `true`.
   - Set `APP_DB_ROLE` to the same non-owner runtime database role in `.env` before applying the migration.

5. Run schema migrations with the database schema-owner connection temporarily set as `DATABASE_URL`:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://legalease_migrator:<password>@localhost:5432/legalease"
$env:APP_DB_ROLE = "legalease_app"
alembic upgrade head
Remove-Item Env:DATABASE_URL
```

The migration grants the runtime role table/sequence access and narrowly grants execution on the security-definer functions used by RLS. Ensure the role already exists and is neither a table owner nor a superuser. Review your PostgreSQL grants before exposing the service.

6. Start FastAPI in terminal 1:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --no-access-log
```

7. Start Streamlit in terminal 2. Stop any older Streamlit process first, then use the project virtual environment's Python explicitly so a globally installed Streamlit version is not used. Set only its backend URL; do not load the backend `.env` into the frontend process:

```powershell
$env:BACKEND_URL = "http://localhost:8000"
.\.venv\Scripts\python.exe -m streamlit run .\frontend\app.py
```

Open http://localhost:8501, register, verify using the code delivered by SMTP, then sign in. API documentation is at http://localhost:8000/docs and health check at http://localhost:8000/health. In Swagger's **Authorize** dialog, paste the access token without a `Bearer ` prefix; Swagger adds the scheme. Do not paste credentials into shared terminals or issue trackers.

For local-only automated tests, SQLite is used in an isolated in-memory database. It is not the production database.

## API overview

Public or unauthenticated:

- `GET /`, `GET /health`
- `POST /auth/register`, `POST /auth/verify-email`, `POST /auth/verification/resend`
- `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`
- `POST /auth/password-reset/request`, `POST /auth/password-reset/confirm`

All other account, document, organization, share, review, and download endpoints require verified user authentication, except short-lived signed `GET /downloads/{signed_token}` URLs. Authorization is rechecked when a signed download is redeemed.

- `GET /auth/me`
- `POST /generate`
- `GET|POST /documents`, `GET|PUT|DELETE /documents/{id}`
- `GET /documents/{id}/permissions`
- `POST /documents/{id}/shares`, `GET /documents/{id}/shares`, `DELETE /documents/{id}/shares/{share_id}`
- `POST /documents/{id}/review`
- `POST /documents/{id}/export/{txt|docx|pdf}` (authenticated direct export)
- `POST /documents/{id}/signed-export/{txt|docx|pdf}` (60-second URL for UI downloads)
- `POST|GET /organizations`
- `GET /admin/users`, `PATCH /admin/users/{user_id}` (admin account/role/deactivation controls only)

Example: register a user with `POST /auth/register` using JSON `{ "email": "...", "password": "12+ characters" }`, verify with `{ "token": "<email code>" }`, then log in. Login returns a short-lived access token and sets the refresh/CSRF cookies. Send the access value only in an `Authorization: Bearer <access_token>` header. Never store a refresh token in the frontend or local storage.

For a document create request, send fields `title`, `document_type`, `party_details`, `terms`, `effective_date`, `jurisdiction`, and `generated_content`. Do not send `owner_id`; it is derived by the API. All document IDs are scoped to authenticated ownership/shares. Inaccessible IDs return 404.

## First administrator

Register and verify a dedicated account, then run this restricted operator command from a trusted server terminal using the application database configuration:

```powershell
python -m backend.manage_user promote-admin admin@example.com
```

It promotes only an existing active, verified account, writes an audit event, and revokes its current sessions. Subsequent role changes and account deactivation are available through `/admin/users/{user_id}`. Admin privileges do not reveal document content.

## Database and migration notes

SQLAlchemy models include `User`, `AuthSession`, `AuthToken`, `Organization`, `OrganizationMembership`, `Document`, `DocumentShare`, and `AuditLog`, with foreign keys and uniqueness/role constraints. Alembic owns schema changes; do not use `create_all()` in production.

The migration recognizes the earlier SQLite schema. Existing unowned documents are assigned to a disabled, unverified legacy placeholder account so no new user or administrator inherits old legal content. Those old drafts remain in the database but are not visible through the API. Back up the database before migrating; manually validate or transfer legacy records only under an approved data-owner process.

## Tests

```powershell
pytest -q tests/test_authz.py
```

The suite checks registration/verification, attempted role escalation, current-user auth, expired access tokens, refresh rotation and logout, password-reset session revocation, owner access, cross-user IDOR across CRUD/exports, admin content isolation, explicit viewer/reviewer sharing, revocation, and export formats. Before deployment, also test migrations and RLS against the exact PostgreSQL major version and non-owner role you will operate.

## Deployment checklist

1. Use PostgreSQL with TLS in transit where applicable, encrypted storage, private networking, automated encrypted backups, and a separate migration owner versus non-owner runtime role.
2. Deploy API and Streamlit behind an HTTPS reverse proxy. Set `ENVIRONMENT=production`, `FORCE_HTTPS=true`, `COOKIE_SECURE=true`, HTTPS `FRONTEND_URL` and `BACKEND_URL`, public-only `ALLOWED_HOSTS`, and exact trusted origins. Set `RATE_LIMIT_STORAGE_URI` to a private Redis/Rediss service. Configure Uvicorn proxy-header trust only for the proxy addresses.
3. Supply JWT/Gemini/SMTP/database secrets from a secret manager. Rotate secrets with a planned session invalidation. Never commit `.env`; never enable access logs that record signed download URL paths (`--no-access-log`).
4. Enable request limits at the proxy as well as the app, protect SMTP, monitor auth failures without logging credentials/tokens/content, and establish security alerting and retention/deletion procedures.
5. Test secure cookies, CSRF, deactivation, role updates, session revocation, RLS, document isolation, and signed-export expiry in the deployed topology before accepting real legal documents.
6. Multi-tenant organizations currently provide membership-bound document association but do not automatically expose documents to other members. Use explicit document sharing. Add an audited organization invitation/administration workflow before relying on team provisioning.

This project provides a hardened baseline, not a compliance certification. Obtain a security review and legal/privacy review appropriate to your deployment and jurisdictions.
