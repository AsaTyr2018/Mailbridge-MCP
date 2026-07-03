from __future__ import annotations

from contextlib import asynccontextmanager
import json
from pathlib import Path
import time
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .audit import audit
from .config import settings
from .db import db, migrate
from . import mailops
from .mcp_server import mcp
from . import users
from . import auth_context
from . import syncops
from . import automation
from . import syncjobs


mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app_: FastAPI):
    migrate()
    syncjobs.start_worker()
    async with mcp.session_manager.run():
        try:
            yield
        finally:
            syncjobs.stop_worker()


app = FastAPI(title="Mailbridge MCP", lifespan=lifespan)


def csrf_token(request: Request) -> str:
    token = request.cookies.get(users.CSRF_COOKIE)
    if not token:
        token = users.make_csrf_token()
        request.state.set_csrf_cookie = token
    return token


def csrf_context(request: Request) -> dict[str, str]:
    return {"csrf_token": csrf_token(request)}


templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"), context_processors=[csrf_context])


def request_remote_addr(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    real_ip = request.headers.get("x-real-ip", "")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else ""


async def mcp_request_meta(request: Request, user: dict[str, Any]) -> dict[str, Any]:
    automation_token = getattr(request.state, "automation_token", None)
    meta: dict[str, Any] = {
        "remote_addr": request_remote_addr(request),
        "user_agent": request.headers.get("user-agent", ""),
        "path": request.url.path,
        "token_id": automation_token.get("token_id", "") if automation_token else user.get("mcp_token_id", ""),
        "started_at": time.perf_counter(),
    }
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        return meta
    try:
        body = await request.body()
        payload = json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return meta
    messages = payload if isinstance(payload, list) else [payload]
    for message in messages:
        if not isinstance(message, dict):
            continue
        method = str(message.get("method", ""))
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if method == "initialize":
            meta["intent"] = "initialize"
            meta["mcp_version"] = str(params.get("protocolVersion", ""))
            client_info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
            meta["client_name"] = str(client_info.get("name", ""))
            meta["client_version"] = str(client_info.get("version", ""))
        elif method == "tools/call":
            meta["intent"] = str(params.get("name", "tools/call"))
        elif method:
            meta["intent"] = method
    return meta


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    is_mcp_path = path == "/mcp" or path.startswith("/mcp/")
    if is_mcp_path:
        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        bearer = token if scheme.lower() == "bearer" else ""
        user = users.find_user_by_mcp_token(bearer)
        automation_token = None
        if not user:
            automation_match = automation.find_user_by_automation_token(bearer)
            if automation_match:
                user, automation_token = automation_match
        if not user:
            return JSONResponse({"detail": "invalid MCP bearer token"}, status_code=401)
        request.state.mcp_user = user
        request.state.automation_token = automation_token
        context_token = auth_context.set_mcp_user(user)
        automation_context_token = auth_context.set_automation_token(automation_token)
        request_meta = await mcp_request_meta(request, user)
        if automation_token and request_meta.get("client_name", "") in {"", "mcp"}:
            request_meta["client_name"] = f"mailbridge-automation:{automation_token.get('name', automation_token.get('token_id', 'unknown'))}"
            request_meta["client_version"] = str(automation_token.get("token_id", ""))
        request_token = auth_context.set_mcp_request(request_meta)
        try:
            return await call_next(request)
        finally:
            auth_context.reset_mcp_user(context_token)
            auth_context.reset_automation_token(automation_context_token)
            auth_context.reset_mcp_request(request_token)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and path not in {"/login", "/register"} and not is_mcp_path:
        expected = request.cookies.get(users.CSRF_COOKIE, "")
        if path.startswith("/api/"):
            submitted = request.headers.get("x-csrf-token", "")
        else:
            form = await request.form()
            submitted = str(form.get("csrf_token", ""))
        if not submitted or not expected or not hmac_compare(submitted, expected):
            return JSONResponse({"detail": "invalid CSRF token"}, status_code=403)
    public_paths = {"/healthz", "/login", "/register", "/sso/mcp"}
    if not is_mcp_path and path not in public_paths and not path.startswith("/static"):
        user = current_user(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        request.state.user = user
    response = await call_next(request)
    if hasattr(request.state, "set_csrf_cookie"):
        response.set_cookie(
            users.CSRF_COOKIE,
            request.state.set_csrf_cookie,
            httponly=False,
            samesite="lax",
            secure=settings.secure_cookies,
        )
    return response


app.mount("/mcp", mcp_app)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def current_user(request: Request) -> dict[str, Any] | None:
    user_id = users.user_id_from_session(request.cookies.get(users.SESSION_COOKIE))
    if not user_id:
        return None
    user = users.get_user(user_id)
    if not user or not user["is_active"]:
        return None
    return user


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def require_admin(request: Request) -> dict[str, Any]:
    user = getattr(request.state, "user", None) or current_user(request)
    if not user or not user["is_admin"]:
        raise HTTPException(status_code=403, detail="admin required")
    return user


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, notice: str | None = None):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "notice": notice,
            "registration_enabled": users.registration_enabled() or users.user_count() == 0,
        },
    )


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    user = users.authenticate(str(form.get("username", "")), str(form.get("password", "")))
    if not user:
        return RedirectResponse("/login?notice=Login%20failed", status_code=303)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(users.SESSION_COOKIE, users.make_session_token(int(user["id"])), httponly=True, samesite="lax", secure=settings.secure_cookies)
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(users.SESSION_COOKIE)
    return response


@app.get("/sso/mcp")
def mcp_magic_login(request: Request, token: str = ""):
    user = users.consume_magic_login_token(token)
    if not user:
        return RedirectResponse("/login?notice=Magic%20link%20expired%20or%20already%20used", status_code=303)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(users.SESSION_COOKIE, users.make_session_token(int(user["id"])), httponly=True, samesite="lax", secure=settings.secure_cookies)
    audit(actor_type="human", actor_id=str(user["id"]), interface="http", action="web_sso_login", status="ok", remote_addr=request_remote_addr(request), user_agent=request.headers.get("user-agent", ""))
    return response


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, notice: str | None = None):
    if not users.registration_enabled() and users.user_count() > 0:
        raise HTTPException(status_code=404, detail="registration disabled")
    return templates.TemplateResponse(request, "register.html", {"notice": notice, "first_user": users.user_count() == 0})


@app.post("/register")
async def register(request: Request):
    if not users.registration_enabled() and users.user_count() > 0:
        raise HTTPException(status_code=404, detail="registration disabled")
    form = await request.form()
    try:
        user, token = users.create_user(str(form.get("username", "")), str(form.get("password", "")))
    except Exception as exc:
        return RedirectResponse(f"/register?notice={quote(str(exc))}", status_code=303)
    response = templates.TemplateResponse(
        request,
        "token_once.html",
        {
            "user": user,
            "token": token,
            "title": "User created",
            "message": "Your personal MCP bearer token is shown once. Store it now.",
            "return_url": "/",
        },
    )
    response.set_cookie(users.SESSION_COOKIE, users.make_session_token(int(user["id"])), httponly=True, samesite="lax", secure=settings.secure_cookies)
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request, notice: str | None = None):
    user = getattr(request.state, "user", None) or current_user(request)
    accounts = mailops.list_accounts(user=user)
    with db() as conn:
        if user and not user.get("is_admin"):
            message_count = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM messages m
                JOIN accounts a ON a.id = m.account_id
                WHERE a.owner_user_id = ?
                """,
                (user["id"],),
            ).fetchone()["c"]
        else:
            message_count = conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"]
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "accounts": accounts,
            "message_count": message_count,
            "mcp_url": f"{settings.public_url.rstrip('/')}/mcp/",
            "bearer_security": mailops.bearer_security_summary(user=user),
            "notice": notice,
            "user": user,
        },
    )


@app.get("/accounts", response_class=HTMLResponse)
def accounts_page(request: Request, notice: str | None = None):
    user = getattr(request.state, "user", None) or current_user(request)
    return templates.TemplateResponse(
        request,
        "accounts.html",
        {
            "accounts": mailops.list_accounts(user=user),
            "sync_jobs": syncjobs.list_sync_jobs(user=user, limit=10),
            "notice": notice,
            "user": user,
        },
    )


@app.get("/accounts/new", response_class=HTMLResponse)
def new_account_page(request: Request, notice: str | None = None):
    user = getattr(request.state, "user", None) or current_user(request)
    return templates.TemplateResponse(
        request,
        "account_new.html",
        {
            "account": {},
            "notice": notice,
            "user": user,
        },
    )


@app.post("/accounts/cache/flush")
def flush_own_mail_cache(request: Request):
    user = getattr(request.state, "user", None) or current_user(request)
    try:
        result = mailops.flush_mail_cache(user=user)
        return RedirectResponse(
            f"/accounts?notice=Mail%20cache%20flushed:%20{result['deleted_messages']}%20indexed%20messages%20removed",
            status_code=303,
        )
    except Exception as exc:
        return RedirectResponse(f"/accounts?notice=Mail%20cache%20flush%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/mcp-token/renew", response_class=HTMLResponse)
def renew_own_token(request: Request):
    user = getattr(request.state, "user", None) or current_user(request)
    token = users.revoke_user_token(int(user["id"]))
    refreshed_user = users.get_user(int(user["id"]))
    return templates.TemplateResponse(
        request,
        "token_once.html",
        {
            "user": refreshed_user,
            "token": token,
            "title": "Bearer token renewed",
            "message": "The previous MCP bearer token is invalid now. Existing Codex sessions using it will fail until updated.",
            "return_url": "/",
        },
    )


@app.get("/drafts", response_class=HTMLResponse)
def drafts_page(request: Request, notice: str | None = None):
    user = getattr(request.state, "user", None) or current_user(request)
    return templates.TemplateResponse(
        request,
        "drafts.html",
        {
            "notice": notice,
            "user": user,
            "drafts": mailops.list_pending_drafts(user=user),
        },
    )


@app.get("/mail-history", response_class=HTMLResponse)
def mail_history_page(request: Request, notice: str | None = None):
    user = getattr(request.state, "user", None) or current_user(request)
    return templates.TemplateResponse(
        request,
        "mail_history.html",
        {
            "notice": notice,
            "user": user,
            "messages": mailops.list_mail_history(user=user),
        },
    )


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, notice: str | None = None):
    user = getattr(request.state, "user", None) or current_user(request)
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "notice": notice,
            "user": user,
            "audit_rows": mailops.list_audit_events(user=user),
        },
    )


@app.get("/security-audit", response_class=HTMLResponse)
def security_audit_page(request: Request, notice: str | None = None):
    user = getattr(request.state, "user", None) or current_user(request)
    return templates.TemplateResponse(
        request,
        "security_audit.html",
        {
            "notice": notice,
            "user": user,
            "audit_rows": mailops.list_security_audit_events(user=user),
        },
    )


def _bool_form(value: str | None) -> bool:
    return value in {"1", "true", "on", "yes"}


def _account_form(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": data.get("name", "").strip(),
        "enabled": _bool_form(data.get("enabled")),
        "email_address": data.get("email_address", "").strip(),
        "display_name": data.get("display_name", "").strip(),
        "imap_host": data.get("imap_host", "").strip(),
        "imap_port": int(data.get("imap_port") or 993),
        "imap_tls_mode": data.get("imap_tls_mode", "ssl"),
        "imap_username": data.get("imap_username", "").strip(),
        "imap_password": data.get("imap_password", ""),
        "smtp_host": data.get("smtp_host", "").strip(),
        "smtp_port": int(data.get("smtp_port") or 587),
        "smtp_tls_mode": data.get("smtp_tls_mode", "starttls"),
        "smtp_username": data.get("smtp_username", "").strip(),
        "smtp_password": data.get("smtp_password", ""),
        "sync_folders": data.get("sync_folders", "INBOX").strip() or "INBOX",
        "mail_index_mode": data.get("mail_index_mode", "metadata_only"),
        "sync_calendar_enabled": _bool_form(data.get("sync_calendar_enabled")),
        "sync_contacts_enabled": _bool_form(data.get("sync_contacts_enabled")),
        "mcp_read_enabled": _bool_form(data.get("mcp_read_enabled")),
        "mcp_search_enabled": _bool_form(data.get("mcp_search_enabled")),
        "mcp_calendar_enabled": _bool_form(data.get("mcp_calendar_enabled")),
        "mcp_contacts_enabled": _bool_form(data.get("mcp_contacts_enabled")),
        "mcp_draft_enabled": _bool_form(data.get("mcp_draft_enabled")),
        "mcp_send_mode": data.get("mcp_send_mode", "interactive_requires_ok"),
        "max_search_results": int(data.get("max_search_results") or 20),
        "max_message_bytes": int(data.get("max_message_bytes") or 20000),
        "allowed_recipient_domains": data.get("allowed_recipient_domains", "").strip(),
        "blocked_recipient_domains": data.get("blocked_recipient_domains", "").strip(),
    }


@app.post("/accounts")
async def create_account(request: Request):
    form = await request.form()
    user = getattr(request.state, "user", None)
    data = dict(form)
    try:
        account_data = _account_form(data)
        if _bool_form(data.get("autodiscover_account")):
            password = str(data.get("autodiscover_password") or data.get("imap_password") or data.get("smtp_password") or "")
            discovered = mailops.autodiscover_account_settings(account_data["email_address"], password)
            account_data.update(discovered)
        _validate_account_transport(account_data)
        account_id = mailops.create_account(account_data, user=user)
    except Exception as exc:
        return RedirectResponse(f"/accounts/new?notice=Create%20failed:%20{quote(str(exc))}", status_code=303)
    notice = "Account created"
    if _bool_form(data.get("autodiscover_sync_profiles")):
        try:
            result = syncops.autodiscover_sync_profiles(account_id, user=user)
            notice = f"Account created. Sync autodiscovery created {len(result['created'])}, skipped {len(result['skipped'])}, failed {len(result['failed'])}"
        except Exception as exc:
            notice = f"Account created. Sync autodiscovery failed: {exc}"
    return RedirectResponse(f"/accounts?notice={quote(notice)}", status_code=303)


def _validate_account_transport(data: dict[str, Any]) -> None:
    required = [
        "email_address",
        "imap_host",
        "imap_username",
        "imap_password",
        "smtp_host",
        "smtp_username",
        "smtp_password",
    ]
    missing = [key for key in required if not str(data.get(key, "")).strip()]
    if missing:
        raise ValueError("missing account fields: " + ", ".join(missing))


@app.get("/accounts/{account_id}", response_class=HTMLResponse)
def edit_account(request: Request, account_id: int, notice: str | None = None):
    user = getattr(request.state, "user", None)
    account = mailops.get_account(account_id, user=user)
    if not account:
        raise HTTPException(status_code=404, detail="account not found")
    return templates.TemplateResponse(
        request,
        "account.html",
        {
            "account": account,
            "user": user,
            "notice": notice,
            "sync_profiles": syncops.list_sync_profiles(account_id, user=user),
        },
    )


@app.post("/accounts/{account_id}")
async def update_account(request: Request, account_id: int):
    form = await request.form()
    user = getattr(request.state, "user", None)
    try:
        mailops.update_account(account_id, _account_form(dict(form)), user=user)
    except Exception as exc:
        return RedirectResponse(f"/accounts/{account_id}?notice=Update%20failed:%20{quote(str(exc))}", status_code=303)
    return RedirectResponse(f"/accounts/{account_id}?notice=Account%20updated", status_code=303)


@app.post("/accounts/{account_id}/delete")
def delete_account_scoped(request: Request, account_id: int):
    mailops.delete_account(account_id, user=getattr(request.state, "user", None))
    return RedirectResponse("/accounts?notice=Account%20deleted", status_code=303)


@app.post("/accounts/{account_id}/test-imap")
def test_imap(request: Request, account_id: int):
    try:
        result = mailops.test_imap(account_id, user=getattr(request.state, "user", None))
        return RedirectResponse(f"/accounts?notice=IMAP%20test%20ok:%20{quote(str(result))}", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/accounts?notice=IMAP%20test%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/accounts/{account_id}/test-smtp")
def test_smtp(request: Request, account_id: int):
    try:
        result = mailops.test_smtp(account_id, user=getattr(request.state, "user", None))
        return RedirectResponse(f"/accounts?notice=SMTP%20test%20ok:%20{quote(str(result))}", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/accounts?notice=SMTP%20test%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/accounts/{account_id}/maintenance/resync")
def maintenance_resync(request: Request, account_id: int):
    try:
        result = syncjobs.enqueue_sync_job(account_id, limit=1000, mode="manual_full", user=getattr(request.state, "user", None), requested_by="http")
        already = "%20already%20running" if result.get("already_running") else ""
        return RedirectResponse(f"/accounts?notice=Resync%20queued{already}:%20job%20{result['id']}", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/accounts?notice=Resync%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/sync-jobs/{job_id}/cancel")
def cancel_sync_job(request: Request, job_id: int):
    try:
        syncjobs.cancel_sync_job(job_id, user=getattr(request.state, "user", None))
        return RedirectResponse("/accounts?notice=Sync%20job%20cancel%20requested", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/accounts?notice=Sync%20job%20cancel%20failed:%20{quote(str(exc))}", status_code=303)


@app.get("/api/sync-jobs/{job_id}")
def api_sync_job(request: Request, job_id: int):
    return syncjobs.get_sync_job(job_id, user=getattr(request.state, "user", None))


@app.post("/accounts/{account_id}/sync-profiles")
async def create_sync_profile(request: Request, account_id: int):
    form = await request.form()
    user = getattr(request.state, "user", None)
    try:
        syncops.create_sync_profile(
            account_id,
            {
                "kind": str(form.get("kind", "")),
                "provider": str(form.get("provider", "")),
                "name": str(form.get("name", "")),
                "base_url": str(form.get("base_url", "")),
                "username": str(form.get("username", "")),
                "password": str(form.get("password", "")),
                "enabled": _bool_form(form.get("enabled")),
            },
            user=user,
        )
        return RedirectResponse(f"/accounts/{account_id}?notice=Sync%20profile%20created", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/accounts/{account_id}?notice=Sync%20profile%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/accounts/{account_id}/sync-profiles/autodiscover")
def autodiscover_sync_profiles(request: Request, account_id: int):
    user = getattr(request.state, "user", None)
    try:
        result = syncops.autodiscover_sync_profiles(account_id, user=user)
        created = len(result["created"])
        skipped = len(result["skipped"])
        failed = len(result["failed"])
        return RedirectResponse(
            f"/accounts/{account_id}?notice=Autodiscovery:%20created%20{created},%20skipped%20{skipped},%20failed%20{failed}",
            status_code=303,
        )
    except Exception as exc:
        return RedirectResponse(f"/accounts/{account_id}?notice=Autodiscovery%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/sync-profiles/{profile_id}/test")
def test_sync_profile(request: Request, profile_id: int):
    user = getattr(request.state, "user", None)
    try:
        profile = syncops.get_sync_profile(profile_id, user=user)
        result = syncops.test_sync_profile(profile_id, user=user)
        return RedirectResponse(f"/accounts/{profile['account_id']}?notice=Sync%20test:%20{quote(str(result)[:240])}", status_code=303)
    except Exception as exc:
        try:
            account_id = syncops.get_sync_profile(profile_id, user=user)["account_id"]
        except Exception:
            account_id = ""
        return RedirectResponse(f"/accounts/{account_id}?notice=Sync%20test%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/sync-profiles/{profile_id}/discover")
def discover_sync_profile(request: Request, profile_id: int):
    user = getattr(request.state, "user", None)
    try:
        profile = syncops.get_sync_profile(profile_id, user=user)
        result = syncops.discover_sync_profile(profile_id, user=user)
        return RedirectResponse(f"/accounts/{profile['account_id']}?notice=Discover:%20{quote(str(result)[:240])}", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/?notice=Discover%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/sync-profiles/{profile_id}/sync")
def run_sync_profile(request: Request, profile_id: int):
    user = getattr(request.state, "user", None)
    try:
        profile = syncops.get_sync_profile(profile_id, user=user)
        result = syncops.sync_profile(profile_id, user=user)
        return RedirectResponse(f"/accounts/{profile['account_id']}?notice=Sync:%20{quote(str(result)[:240])}", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/?notice=Sync%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/sync-profiles/{profile_id}/delete")
def delete_sync_profile(request: Request, profile_id: int):
    user = getattr(request.state, "user", None)
    try:
        profile = syncops.get_sync_profile(profile_id, user=user)
        syncops.delete_sync_profile(profile_id, user=user)
        return RedirectResponse(f"/accounts/{profile['account_id']}?notice=Sync%20profile%20deleted", status_code=303)
    except Exception as exc:
        return RedirectResponse(f"/?notice=Delete%20failed:%20{quote(str(exc))}", status_code=303)


@app.get("/api/accounts")
def api_accounts(request: Request):
    return mailops.list_accounts(user=getattr(request.state, "user", None))


@app.post("/api/accounts/autodiscover")
async def api_account_autodiscover(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        payload = await request.json()
    else:
        payload = dict(await request.form())
    email_address = str(payload.get("email_address", "")).strip()
    password = str(payload.get("password", ""))
    try:
        discovered = mailops.autodiscover_account_settings(email_address, password)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    fields = [
        "email_address",
        "imap_host",
        "imap_port",
        "imap_tls_mode",
        "imap_username",
        "smtp_host",
        "smtp_port",
        "smtp_tls_mode",
        "smtp_username",
    ]
    return {"ok": True, "settings": {key: discovered[key] for key in fields}}


@app.get("/api/accounts/{account_id}/sync-status")
def api_sync_status(request: Request, account_id: int):
    user = getattr(request.state, "user", None)
    account = mailops.get_account(account_id, user=user)
    if not account:
        raise HTTPException(status_code=404, detail="account not found")
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE account_id = ?", (account_id,)).fetchone()["c"]
    return {
        "account_id": account_id,
        "last_sync_at": account["last_sync_at"],
        "last_sync_error": account["last_sync_error"],
        "indexed_messages": count,
        "calendar_enabled": account["sync_calendar_enabled"],
        "contacts_enabled": account["sync_contacts_enabled"],
    }


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, notice: str | None = None):
    require_admin(request)
    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "notice": notice,
            "user": getattr(request.state, "user", None),
            "users": users.list_users(),
            "registration_enabled": users.registration_enabled(),
        },
    )


@app.post("/admin/registration")
async def admin_registration(request: Request):
    require_admin(request)
    form = await request.form()
    users.set_registration_enabled(_bool_form(form.get("registration_enabled")))
    return RedirectResponse("/admin?notice=Registration%20updated", status_code=303)


@app.post("/admin/cache/flush")
def admin_flush_mail_cache(request: Request):
    admin = require_admin(request)
    try:
        result = mailops.flush_mail_cache(user=admin, all_users=True)
        return RedirectResponse(
            f"/admin?notice=Global%20mail%20cache%20flushed:%20{result['deleted_messages']}%20indexed%20messages%20removed",
            status_code=303,
        )
    except Exception as exc:
        return RedirectResponse(f"/admin?notice=Global%20mail%20cache%20flush%20failed:%20{quote(str(exc))}", status_code=303)


@app.post("/admin/users/{user_id}/lock")
def admin_lock_user(request: Request, user_id: int):
    admin = require_admin(request)
    if user_id == admin["id"]:
        return RedirectResponse("/admin?notice=Cannot%20lock%20yourself", status_code=303)
    users.set_user_active(user_id, False)
    return RedirectResponse("/admin?notice=User%20locked", status_code=303)


@app.post("/admin/users/{user_id}/unlock")
def admin_unlock_user(request: Request, user_id: int):
    require_admin(request)
    users.set_user_active(user_id, True)
    return RedirectResponse("/admin?notice=User%20unlocked", status_code=303)


@app.post("/admin/users/{user_id}/revoke-token")
def admin_revoke_token(request: Request, user_id: int):
    require_admin(request)
    token = users.revoke_user_token(user_id)
    target_user = users.get_user(user_id)
    return templates.TemplateResponse(
        request,
        "token_once.html",
        {
            "user": getattr(request.state, "user", None),
            "token": token,
            "title": f"Bearer token renewed for {target_user['username'] if target_user else user_id}",
            "message": "The previous MCP bearer token is invalid now. Share this token through a secure channel.",
            "return_url": "/admin",
        },
    )


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(request: Request, user_id: int):
    admin = require_admin(request)
    if user_id == admin["id"]:
        return RedirectResponse("/admin?notice=Cannot%20delete%20yourself", status_code=303)
    users.delete_user(user_id)
    return RedirectResponse("/admin?notice=User%20deleted", status_code=303)
