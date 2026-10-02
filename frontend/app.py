from __future__ import annotations

import os
from typing import Any

import requests
import streamlit as st

API_BASE_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
DOCUMENT_TYPES = [
    "Employment Contract",
    "Lease Agreement",
    "Non-Disclosure Agreement (NDA)",
    "Freelance Contract",
    "General Agreement",
]

st.set_page_config(page_title="LegalEase", page_icon="⚖️", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: #f5f7fa; }
    [data-testid="stSidebar"] { background: #102a43; }
    [data-testid="stSidebar"] * { color: #f5f7fa !important; }
    h1, h2, h3 { color: #102a43; }
    div.stButton > button { background: #176b87; color: white; border: 0; border-radius: 8px; }
    div.stButton > button:hover { background: #0f526b; color: white; }
    </style>
    """,
    unsafe_allow_html=True,
)


def api_session() -> requests.Session:
    if "http_session" not in st.session_state:
        st.session_state.http_session = requests.Session()
    return st.session_state.http_session


def api_request(
    method: str,
    path: str,
    *,
    authenticated: bool = True,
    retry_refresh: bool = True,
    **kwargs: Any,
) -> requests.Response:
    session = api_session()
    headers = dict(kwargs.pop("headers", {}))
    if authenticated:
        access_token = st.session_state.get("access_token")
        if not access_token:
            raise RuntimeError("Your session has expired. Please sign in again.")
        headers["Authorization"] = f"Bearer {access_token}"

    response = session.request(method, f"{API_BASE_URL}{path}", headers=headers, timeout=kwargs.pop("timeout", 30), **kwargs)
    if response.status_code == 401 and authenticated and retry_refresh and session.cookies.get("legalease_refresh"):
        csrf = session.cookies.get("legalease_csrf")
        if csrf:
            refreshed = session.post(
                f"{API_BASE_URL}/auth/refresh",
                headers={"X-CSRF-Token": csrf},
                timeout=20,
            )
            if refreshed.ok:
                session_data = refreshed.json()
                st.session_state.access_token = session_data["access_token"]
                st.session_state.current_user = session_data["user"]
                headers["Authorization"] = f"Bearer {session_data['access_token']}"
                response = session.request(method, f"{API_BASE_URL}{path}", headers=headers, timeout=kwargs.pop("timeout", 30), **kwargs)
            else:
                clear_local_session()
                raise RuntimeError("Your session expired. Please sign in again.")
        else:
            clear_local_session()
            raise RuntimeError("Your session expired. Please sign in again.")
    if response.status_code == 401 and authenticated:
        clear_local_session()
        raise RuntimeError("Your session expired. Please sign in again.")
    return response


def clear_local_session() -> None:
    st.session_state.pop("access_token", None)
    st.session_state.pop("current_user", None)
    st.session_state.pop("http_session", None)


def response_detail(response: requests.Response, fallback: str) -> str:
    try:
        payload = response.json()
        return str(payload.get("detail") or payload.get("message") or fallback)
    except (ValueError, AttributeError):
        return fallback


def require_ok(response: requests.Response, fallback: str) -> requests.Response:
    if response.status_code >= 400:
        raise RuntimeError(response_detail(response, fallback))
    return response


def current_user() -> dict | None:
    user = st.session_state.get("current_user")
    if not user:
        return None
    try:
        response = api_request("GET", "/auth/me", timeout=15)
        if response.ok:
            user = response.json()
            st.session_state.current_user = user
            return user
        if response.status_code == 403:
            clear_local_session()
            return None
        require_ok(response, "Unable to load account information.")
    except RuntimeError:
        clear_local_session()
        st.session_state.session_notice = "Your session expired or was revoked. Please sign in again."
        return None
    except requests.RequestException:
        clear_local_session()
        st.session_state.session_notice = "The account service could not validate your session. Please sign in again."
        return None
    return None


def login(email: str, password: str) -> None:
    response = api_request(
        "POST",
        "/auth/login",
        authenticated=False,
        json={"email": email, "password": password},
        timeout=30,
    )
    require_ok(response, "Sign in failed.")
    payload = response.json()
    st.session_state.access_token = payload["access_token"]
    st.session_state.current_user = payload["user"]
    st.session_state.pop("session_notice", None)


def download_data(document_id: int, file_type: str) -> bytes:
    signed = require_ok(
        api_request("POST", f"/documents/{document_id}/signed-export/{file_type}", timeout=30),
        "Export authorization failed.",
    ).json()
    response = api_session().get(
        f"{API_BASE_URL}{signed['url']}",
        timeout=60,
    )
    require_ok(response, "The download link expired. Please try again.")
    return response.content


def auth_page(page: str) -> None:
    st.title("LegalEase")
    st.caption("Secure access to your legal document drafts.")
    if "session_notice" in st.session_state:
        st.warning(st.session_state.pop("session_notice"))

    if page == "Register":
        st.subheader("Create account")
        with st.form("register"):
            email = st.text_input("Email")
            password = st.text_input("Password (12+ characters)", type="password")
            confirm = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Register")
        if submitted:
            if password != confirm:
                st.error("Passwords do not match.")
            else:
                try:
                    response = api_request(
                        "POST",
                        "/auth/register",
                        authenticated=False,
                        json={"email": email, "password": password},
                        timeout=30,
                    )
                    require_ok(response, "Registration could not be completed.")
                    st.success(response.json().get("message", "Check your email for a verification code."))
                except (requests.RequestException, RuntimeError) as exc:
                    st.error(str(exc))
        return

    if page == "Verify email":
        st.subheader("Verify email")
        with st.form("verify"):
            token = st.text_input("One-time verification code")
            submitted = st.form_submit_button("Verify")
        if submitted:
            try:
                response = api_request(
                    "POST",
                    "/auth/verify-email",
                    authenticated=False,
                    json={"token": token},
                )
                require_ok(response, "Verification failed.")
                st.success(response.json()["message"])
            except (requests.RequestException, RuntimeError) as exc:
                st.error(str(exc))
        with st.form("resend"):
            st.caption("Resend a verification message")
            email = st.text_input("Account email", key="resend_email")
            password = st.text_input("Password", type="password", key="resend_password")
            resend = st.form_submit_button("Resend verification")
        if resend:
            try:
                response = api_request(
                    "POST",
                    "/auth/verification/resend",
                    authenticated=False,
                    json={"email": email, "password": password},
                )
                require_ok(response, "Unable to resend verification.")
                st.info(response.json()["message"])
            except (requests.RequestException, RuntimeError) as exc:
                st.error(str(exc))
        return

    if page == "Reset password":
        st.subheader("Reset password")
        with st.form("reset_request"):
            email = st.text_input("Account email")
            request_reset = st.form_submit_button("Send reset instructions")
        if request_reset:
            try:
                response = api_request(
                    "POST",
                    "/auth/password-reset/request",
                    authenticated=False,
                    json={"email": email},
                )
                require_ok(response, "Unable to request a password reset.")
                st.info(response.json()["message"])
            except (requests.RequestException, RuntimeError) as exc:
                st.error(str(exc))
        with st.form("reset_confirm"):
            token = st.text_input("One-time password reset code")
            password = st.text_input("New password (12+ characters)", type="password")
            confirm = st.text_input("Confirm new password", type="password")
            reset = st.form_submit_button("Set new password")
        if reset:
            if password != confirm:
                st.error("Passwords do not match.")
            else:
                try:
                    response = api_request(
                        "POST",
                        "/auth/password-reset/confirm",
                        authenticated=False,
                        json={"token": token, "new_password": password},
                    )
                    require_ok(response, "Password reset failed.")
                    st.success(response.json()["message"])
                except (requests.RequestException, RuntimeError) as exc:
                    st.error(str(exc))
        return

    st.subheader("Sign in")
    with st.form("login"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        try:
            login(email, password)
            st.rerun()
        except (requests.RequestException, RuntimeError) as exc:
            st.error(str(exc))


def create_document_page() -> None:
    st.title("Create a legal document")
    with st.form("document_form"):
        document_type = st.selectbox("Document type", DOCUMENT_TYPES)
        col1, col2 = st.columns(2)
        with col1:
            first_party_name = st.text_input("First party name")
            first_party_role = st.text_input("First party role")
            second_party_name = st.text_input("Second party name")
            second_party_role = st.text_input("Second party role")
        with col2:
            additional_parties = st.text_area("Additional parties (optional)", height=100)
            effective_date = st.date_input("Effective date")
            jurisdiction = st.text_input("Jurisdiction (optional)")
            company_name = st.text_input("Company name (optional)")
        terms = st.text_area("Terms and conditions", height=160)
        submitted = st.form_submit_button("Generate document")

    if submitted:
        if not all([first_party_name, first_party_role, second_party_name, second_party_role]) or len(terms.strip()) < 10:
            st.error("Complete all party fields and provide at least 10 characters of terms.")
        else:
            payload = {
                "document_type": document_type,
                "first_party_name": first_party_name,
                "first_party_role": first_party_role,
                "second_party_name": second_party_name,
                "second_party_role": second_party_role,
                "additional_parties": additional_parties,
                "effective_date": effective_date.isoformat(),
                "terms_and_conditions": terms,
                "jurisdiction": jurisdiction,
                "optional_company_name": company_name,
            }
            with st.spinner("Generating your private draft..."):
                try:
                    response = require_ok(
                        api_request("POST", "/generate", json=payload, timeout=120),
                        "Document generation failed.",
                    )
                    generated = response.json()
                    st.session_state.generated_title = generated["title"]
                    st.session_state.generated_document = generated["generated_content"]
                    st.session_state.generated_values = {
                        "document_type": document_type,
                        "party_details": (
                            f"First Party: {first_party_name} ({first_party_role})\n"
                            f"Second Party: {second_party_name} ({second_party_role})\n"
                            f"Additional Parties: {additional_parties or 'Not specified'}"
                        ),
                        "terms": terms,
                        "effective_date": effective_date.isoformat(),
                        "jurisdiction": jurisdiction or None,
                    }
                except (requests.RequestException, RuntimeError) as exc:
                    st.error(str(exc))

    if st.session_state.get("generated_document"):
        st.subheader("Review and edit draft")
        edited = st.text_area(
            "Generated document",
            value=st.session_state.generated_document,
            height=450,
            key="draft_editor",
        )
        st.session_state.generated_document = edited
        if st.button("Save to my documents"):
            info = st.session_state.generated_values
            payload = {
                "title": st.session_state.generated_title,
                "document_type": info["document_type"],
                "party_details": info["party_details"],
                "terms": info["terms"],
                "effective_date": info["effective_date"],
                "jurisdiction": info["jurisdiction"],
                "generated_content": edited,
            }
            try:
                response = require_ok(api_request("POST", "/documents", json=payload), "Unable to save document.")
                st.session_state.last_saved_id = response.json()["id"]
                st.success("Document saved.")
            except (requests.RequestException, RuntimeError) as exc:
                st.error(str(exc))
        st.caption("AI-generated draft; not guaranteed legally valid. Have it reviewed by a qualified legal professional.")


def my_documents_page(user: dict) -> None:
    st.title("My Documents")
    col_search, col_type = st.columns([2, 1])
    with col_search:
        search = st.text_input("Search your documents and documents shared with you")
    with col_type:
        doc_type = st.selectbox("Document type", ["All types"] + DOCUMENT_TYPES)
    filters = {}
    if search:
        filters["search"] = search
    if doc_type != "All types":
        filters["document_type"] = doc_type
    try:
        response = require_ok(api_request("GET", "/documents", params=filters), "Unable to load documents.")
        documents = response.json()
    except (requests.RequestException, RuntimeError) as exc:
        st.error(str(exc))
        return
    if not documents:
        st.info("No accessible documents found.")
        return

    for item in documents:
        document_id = item["id"]
        is_owner = item["owner_id"] == user["id"]
        with st.expander(f"{item['title']} · {item['document_type']} · {item['created_at'][:10]}"):
            try:
                detail = require_ok(api_request("GET", f"/documents/{document_id}"), "Unable to open this document.").json()
                permissions = require_ok(
                    api_request("GET", f"/documents/{document_id}/permissions"),
                    "Unable to check document permissions.",
                ).json()
            except (requests.RequestException, RuntimeError) as exc:
                st.error(str(exc))
                continue
            edited = st.text_area("Document content", value=detail["generated_content"], height=300, key=f"content_{document_id}")
            if permissions["can_share"]:
                st.caption("Access is authorized per document; administrator status does not grant document access.")
            if permissions["can_edit"]:
                if st.button("Save edits", key=f"save_{document_id}"):
                    try:
                        response = require_ok(
                            api_request("PUT", f"/documents/{document_id}", json={"generated_content": edited}),
                            "You do not have edit permission for this document.",
                        )
                        st.success("Changes saved.")
                    except (requests.RequestException, RuntimeError) as exc:
                        st.error(str(exc))
            if permissions["can_share"]:
                st.markdown("#### Share or revoke access")
                with st.form(f"share_{document_id}"):
                    recipient_email = st.text_input("Verified account email", key=f"email_{document_id}")
                    permission = st.selectbox(
                        "Permission",
                        ["viewer", "editor", "reviewer"],
                        key=f"permission_{document_id}",
                    )
                    share_submit = st.form_submit_button("Share document")
                if share_submit:
                    try:
                        response = require_ok(
                            api_request(
                                "POST",
                                f"/documents/{document_id}/shares",
                                json={"email": recipient_email, "permission": permission},
                            ),
                            "Unable to share document.",
                        )
                        st.success(f"Shared with account ID {response.json()['user_id']}.")
                    except (requests.RequestException, RuntimeError) as exc:
                        st.error(str(exc))
                try:
                    shares_response = require_ok(api_request("GET", f"/documents/{document_id}/shares"), "Unable to list shares.")
                    for share in shares_response.json():
                        st.write(
                            f"Account {share['user_id']} · {share['permission']} · review: {share['review_status']}"
                        )
                        if st.button("Revoke", key=f"revoke_{share['id']}"):
                            try:
                                require_ok(
                                    api_request("DELETE", f"/documents/{document_id}/shares/{share['id']}"),
                                    "Unable to revoke share.",
                                )
                                st.rerun()
                            except (requests.RequestException, RuntimeError) as exc:
                                st.error(str(exc))
                except (requests.RequestException, RuntimeError) as exc:
                    st.error(str(exc))
            elif permissions["can_review"]:
                st.markdown("#### Submit review")
                with st.form(f"review_{document_id}"):
                    review_status = st.selectbox("Decision", ["approved", "changes_requested"], key=f"review_status_{document_id}")
                    review_comment = st.text_area("Review comment", key=f"review_comment_{document_id}")
                    review_submit = st.form_submit_button("Submit review")
                if review_submit:
                    try:
                        require_ok(
                            api_request(
                                "POST",
                                f"/documents/{document_id}/review",
                                json={"status": review_status, "comment": review_comment},
                            ),
                            "Review not permitted. The document must be explicitly shared with you for review.",
                        )
                        st.success("Review submitted.")
                    except (requests.RequestException, RuntimeError) as exc:
                        st.error(str(exc))
            columns = st.columns(3)
            for column, file_type in zip(columns, ("txt", "docx", "pdf")):
                try:
                    file_data = download_data(document_id, file_type)
                    mime = {
                        "txt": "text/plain",
                        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "pdf": "application/pdf",
                    }[file_type]
                    column.download_button(
                        f"Download {file_type.upper()}",
                        data=file_data,
                        file_name=f"legalease-{document_id}.{file_type}",
                        mime=mime,
                        key=f"download_{file_type}_{document_id}",
                    )
                except (requests.RequestException, RuntimeError) as exc:
                    column.error("Download failed or expired. Please try again.")
            if is_owner and st.button("Delete document", key=f"delete_{document_id}"):
                try:
                    require_ok(api_request("DELETE", f"/documents/{document_id}"), "Unable to delete document.")
                    st.success("Document deleted.")
                    st.rerun()
                except (requests.RequestException, RuntimeError) as exc:
                    st.error(str(exc))


def main() -> None:
    user = current_user()
    if user:
        pages = ["Home", "Create Document", "My Documents", "About LegalEase"]
        selected = st.sidebar.radio("Navigation", pages)
        st.sidebar.divider()
        st.sidebar.write(f"**Account:** {user['email']}")
        st.sidebar.write(f"**Role:** {user['role'].replace('_', ' ').title()}")
        if st.sidebar.button("Log out"):
            session = api_session()
            csrf = session.cookies.get("legalease_csrf")
            logout_failed = False
            if csrf:
                try:
                    response = session.post(
                        f"{API_BASE_URL}/auth/logout",
                        headers={"X-CSRF-Token": csrf},
                        timeout=15,
                    )
                    logout_failed = response.status_code >= 400
                except requests.RequestException:
                    logout_failed = True
            clear_local_session()
            if logout_failed:
                st.session_state.session_notice = (
                    "The server could not confirm logout. The local session was cleared; "
                    "the server-side refresh session will expire automatically."
                )
            st.rerun()
        if selected == "Home":
            st.title("LegalEase")
            st.subheader("AI-Powered Legal Document Generator")
            st.write("Create, edit, securely save, share for review, and export legal document drafts.")
            try:
                docs_response = require_ok(api_request("GET", "/documents"), "Unable to load document statistics.")
                st.metric("Documents you can access", len(docs_response.json()))
            except (requests.RequestException, RuntimeError) as exc:
                st.error(str(exc))
            st.info("AI-generated drafts are not legal advice and should be reviewed by a qualified legal professional.")
        elif selected == "Create Document":
            create_document_page()
        elif selected == "My Documents":
            my_documents_page(user)
        else:
            st.title("About LegalEase")
            st.write("LegalEase helps individuals and teams prepare draft legal documents. It does not guarantee legal validity.")
            st.warning(
                "Production deployments must use HTTPS, managed secrets, configured transactional email, PostgreSQL backups, "
                "private storage, monitoring, and organization-specific privacy controls."
            )
        return

    choice = st.sidebar.radio("Account", ["Sign in", "Register", "Verify email", "Reset password"])
    auth_page({"Sign in": "Login"}.get(choice, choice))
    st.caption("LegalEase drafts are informational. Consult a qualified legal professional before use.")


main()
