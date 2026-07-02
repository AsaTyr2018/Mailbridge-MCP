from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings

from . import mailops
from . import syncops
from . import automation
from .audit import audit
from .auth_context import get_automation_token, get_mcp_user
from .db import db


mcp = FastMCP(
    "mailbridge",
    instructions=(
        "Mailbridge exposes user-configured mail accounts to Codex. "
        "Search before reading exact messages. Do not request broad mailbox dumps. "
        "Interactive sends require showing the final message content to the user and receiving active ok. "
        "Automatic sends require prior scoped consent."
    ),
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        allowed_hosts=[
            "127.0.0.1",
            "127.0.0.1:18082",
            "localhost",
            "localhost:18082",
            "192.168.1.172",
            "192.168.1.172:18082",
        ],
        allowed_origins=[
            "http://127.0.0.1:18082",
            "http://localhost:18082",
            "http://192.168.1.172:18082",
        ],
    ),
)


def _require(permission: str, account_id: int | None = None) -> None:
    automation.require_allowed(get_automation_token(), permission, account_id)


def _message_account_id(message_id: int) -> int:
    with db() as conn:
        row = conn.execute("SELECT account_id FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row:
        raise ValueError("message not found")
    return int(row["account_id"])


@mcp.tool()
def list_accounts() -> list[dict[str, Any]]:
    """List configured accounts and their MCP permissions."""
    user = get_mcp_user()
    automation_token = get_automation_token()
    _require("list_accounts")
    accounts = mailops.list_accounts(user=user)
    if automation_token:
        allowed_ids = set(automation_token.get("allowed_account_ids") or [])
        accounts = [account for account in accounts if int(account["id"]) in allowed_ids]
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="list_accounts", status="ok")
    return [
        {
            "id": account["id"],
            "name": account["name"],
            "enabled": account["enabled"],
            "email_address": account["email_address"],
            "last_sync_at": account["last_sync_at"],
            "last_sync_error": account["last_sync_error"],
            "mcp_read_enabled": account["mcp_read_enabled"],
            "mcp_search_enabled": account["mcp_search_enabled"],
            "mcp_calendar_enabled": account["mcp_calendar_enabled"],
            "mcp_contacts_enabled": account["mcp_contacts_enabled"],
            "mcp_draft_enabled": account["mcp_draft_enabled"],
            "mcp_send_mode": account["mcp_send_mode"],
        }
        for account in accounts
    ]


@mcp.tool()
def get_account_status(account_id: int) -> dict[str, Any]:
    """Return sync and health status for one account."""
    user = get_mcp_user()
    _require("list_accounts", account_id)
    account = mailops.get_account(account_id, user=user)
    if not account:
        audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="get_account_status", status="error", account_id=account_id, error_message="account not found")
        raise ValueError("account not found")
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="get_account_status", status="ok", account_id=account_id)
    return {
        "id": account["id"],
        "name": account["name"],
        "enabled": account["enabled"],
        "last_sync_at": account["last_sync_at"],
        "last_sync_error": account["last_sync_error"],
        "sync_calendar_enabled": account["sync_calendar_enabled"],
        "sync_contacts_enabled": account["sync_contacts_enabled"],
    }


@mcp.tool()
def sync_account(account_id: int, limit: int = 100) -> dict[str, Any]:
    """Trigger IMAP sync and local indexing for an account."""
    _require("sync", account_id)
    safe_limit = max(1, min(limit, 1000))
    return mailops.sync_account(account_id, limit=safe_limit, user=get_mcp_user())


@mcp.tool()
def search_mail(account_id: int, query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Search the local mail index with text and supported Gmail-style filters."""
    _require("search", account_id)
    return mailops.search_mail(account_id, query, limit, user=get_mcp_user())


@mcp.tool()
def get_message(message_id: int) -> dict[str, Any]:
    """Read one indexed message by exact id."""
    _require("read", _message_account_id(message_id))
    return mailops.get_message(message_id, user=get_mcp_user())


@mcp.tool()
def list_attachments(message_id: int) -> dict[str, Any]:
    """List attachments for one indexed message without returning attachment content."""
    account_id = _message_account_id(message_id)
    _require("read", account_id)
    _require("attachments", account_id)
    return mailops.list_attachments(message_id, user=get_mcp_user())


@mcp.tool()
def get_attachment(message_id: int, attachment_index: int = 0, filename: str = "", max_bytes: int = 1000000) -> dict[str, Any]:
    """Read one attachment as base64 content with a hard size cap."""
    account_id = _message_account_id(message_id)
    _require("read", account_id)
    _require("attachments", account_id)
    return mailops.get_attachment(message_id, attachment_index=attachment_index, filename=filename, max_bytes=max_bytes, user=get_mcp_user())


@mcp.tool()
def get_thread(thread_id: str, account_id: int) -> list[dict[str, Any]]:
    """Read indexed messages with a matching thread id."""
    _require("read", account_id)
    user = get_mcp_user()
    results = mailops.search_mail(account_id, f'"{thread_id}"', limit=20, user=user)
    return [mailops.get_message(int(item["id"]), user=user) for item in results]


@mcp.tool()
def analyze_thread(thread_id: str, account_id: int) -> dict[str, Any]:
    """Return a lightweight structured extraction from a thread."""
    _require("read", account_id)
    messages = get_thread(thread_id, account_id)
    participants = sorted({m.get("sender", "") for m in messages if m.get("sender")})
    latest = messages[-1] if messages else None
    return {
        "thread_id": thread_id,
        "message_count": len(messages),
        "participants": participants,
        "latest_subject": latest.get("subject") if latest else "",
        "latest_sent_at": latest.get("sent_at") if latest else "",
        "summary_hint": "Use the returned messages as source material; no model-side summary is generated by Mailbridge.",
    }


@mcp.tool()
def search_contacts(account_id: int, query: str, limit: int = 20) -> dict[str, Any]:
    """Search locally synced contacts from CardDAV or ActiveSync-backed profiles."""
    user = get_mcp_user()
    _require("contacts", account_id)
    try:
        return mailops.search_contacts(account_id, query, limit, user=user)
    except Exception as exc:
        audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="search_contacts", status="error", account_id=account_id, error_message=str(exc))
        raise


@mcp.tool()
def list_calendar_events(account_id: int, start_at: str, end_at: str, limit: int = 50) -> dict[str, Any]:
    """List locally synced calendar events from CalDAV or ActiveSync-backed profiles."""
    user = get_mcp_user()
    _require("calendar", account_id)
    try:
        return mailops.list_calendar_events(account_id, start_at, end_at, limit, user=user)
    except Exception as exc:
        audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="list_calendar_events", status="error", account_id=account_id, error_message=str(exc))
        raise


@mcp.tool()
def list_sync_profiles(account_id: int) -> list[dict[str, Any]]:
    """List contact/calendar sync profiles for an account."""
    user = get_mcp_user()
    _require("sync_profiles", account_id)
    profiles = syncops.list_sync_profiles(account_id, user=user)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="list_sync_profiles", status="ok", account_id=account_id)
    return profiles


@mcp.tool()
def sync_profile(profile_id: int) -> dict[str, Any]:
    """Run one configured contact/calendar sync profile."""
    user = get_mcp_user()
    return syncops.sync_profile(profile_id, user=user)


@mcp.tool()
def create_contact(
    account_id: int,
    display_name: str,
    email: str,
    phone: str = "",
    company: str = "",
    profile_id: int | None = None,
) -> dict[str, Any]:
    """Create a contact through a writable CardDAV or ActiveSync-backed profile."""
    user = get_mcp_user()
    _require("contacts_write", account_id)
    return syncops.create_contact(
        account_id,
        {"display_name": display_name, "email": email, "phone": phone, "company": company},
        user=user,
        profile_id=profile_id,
    )


@mcp.tool()
def update_contact(
    contact_id: int,
    display_name: str = "",
    email: str = "",
    phone: str = "",
    company: str = "",
) -> dict[str, Any]:
    """Update a locally indexed contact and write the change back to its provider."""
    user = get_mcp_user()
    _require("contacts_write")
    data = {key: value for key, value in {"display_name": display_name, "email": email, "phone": phone, "company": company}.items() if value != ""}
    return syncops.update_contact(contact_id, data, user=user)


@mcp.tool()
def delete_contact(contact_id: int) -> dict[str, Any]:
    """Delete a contact from its provider and local index."""
    user = get_mcp_user()
    _require("contacts_write")
    return syncops.delete_contact(contact_id, user=user)


@mcp.tool()
def create_calendar_event(
    account_id: int,
    title: str,
    starts_at: str,
    ends_at: str = "",
    location: str = "",
    description: str = "",
    attendees: str = "",
    profile_id: int | None = None,
) -> dict[str, Any]:
    """Create a calendar event through a writable CalDAV or ActiveSync-backed profile."""
    user = get_mcp_user()
    _require("calendar_write", account_id)
    return syncops.create_calendar_event(
        account_id,
        {
            "title": title,
            "starts_at": starts_at,
            "ends_at": ends_at,
            "location": location,
            "description": description,
            "attendees": attendees,
        },
        user=user,
        profile_id=profile_id,
    )


@mcp.tool()
def update_calendar_event(
    event_id: int,
    title: str = "",
    starts_at: str = "",
    ends_at: str = "",
    location: str = "",
    description: str = "",
    attendees: str = "",
) -> dict[str, Any]:
    """Update a locally indexed calendar event and write the change back to its provider."""
    user = get_mcp_user()
    _require("calendar_write")
    data = {
        key: value
        for key, value in {
            "title": title,
            "starts_at": starts_at,
            "ends_at": ends_at,
            "location": location,
            "description": description,
            "attendees": attendees,
        }.items()
        if value != ""
    }
    return syncops.update_calendar_event(event_id, data, user=user)


@mcp.tool()
def delete_calendar_event(event_id: int) -> dict[str, Any]:
    """Delete a calendar event from its provider and local index."""
    user = get_mcp_user()
    _require("calendar_write")
    return syncops.delete_calendar_event(event_id, user=user)


@mcp.tool()
def create_draft(
    account_id: int,
    to_recipients: str,
    subject: str,
    body_text: str,
    cc_recipients: str = "",
    bcc_recipients: str = "",
    in_reply_to_message_id: int | None = None,
) -> dict[str, Any]:
    """Create a mail draft for approval or verified send."""
    _require("draft", account_id)
    return mailops.create_draft(
        account_id,
        to_recipients,
        subject,
        body_text,
        cc_recipients,
        bcc_recipients,
        in_reply_to_message_id,
        user=get_mcp_user(),
    )


@mcp.tool()
def create_forward_draft(
    message_id: int,
    to_recipients: str,
    note: str = "",
    cc_recipients: str = "",
    bcc_recipients: str = "",
) -> dict[str, Any]:
    """Create a forward draft for one message. Sending still uses send_draft policy."""
    account_id = _message_account_id(message_id)
    _require("read", account_id)
    _require("draft", account_id)
    _require("forward", account_id)
    return mailops.create_forward_draft(message_id, to_recipients, note=note, cc_recipients=cc_recipients, bcc_recipients=bcc_recipients, user=get_mcp_user())


@mcp.tool()
def list_drafts() -> list[dict[str, Any]]:
    """List recent drafts."""
    user = get_mcp_user()
    _require("draft")
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="list_drafts", status="ok")
    return mailops.list_drafts(user=user)


@mcp.tool()
def send_draft(draft_id: int, interactive_ok: bool = False, automation_consent_id: int | None = None) -> dict[str, Any]:
    """Send a draft only after interactive ok or prior automation consent."""
    _require("send")
    return mailops.send_draft(draft_id, interactive_ok=interactive_ok, automation_consent_id=automation_consent_id, user=get_mcp_user())


@mcp.tool()
def create_automation_token(name: str, account_names: list[str], permissions: list[str] | None = None) -> dict[str, Any]:
    """Create a user-scoped automation token for MASH or another personal automation client. The token is shown once."""
    user = get_mcp_user()
    if get_automation_token():
        raise PermissionError("automation tokens cannot create further automation tokens")
    token_record, token = automation.create_automation_token(
        user,
        name=name,
        account_names=account_names,
        permissions=permissions or automation.DEFAULT_PERMISSIONS,
    )
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="create_automation_token", status="ok", token_id=token_record["token_id"])
    return {"token": token, "record": token_record}


@mcp.tool()
def list_automation_tokens() -> list[dict[str, Any]]:
    """List this user's automation tokens without revealing token secrets."""
    user = get_mcp_user()
    if get_automation_token():
        raise PermissionError("automation tokens cannot list automation tokens")
    return automation.list_automation_tokens(user)


@mcp.tool()
def revoke_automation_token(token_id: int) -> dict[str, Any]:
    """Revoke one of this user's automation tokens."""
    user = get_mcp_user()
    if get_automation_token():
        raise PermissionError("automation tokens cannot revoke automation tokens")
    return automation.revoke_automation_token(token_id, user)


@mcp.tool()
def move_messages(account_id: int, message_ids: list[int], target_folder: str, source_folder: str = "") -> dict[str, Any]:
    """Move indexed messages to another folder. Automation tokens must have move permission for the account."""
    _require("move", account_id)
    return mailops.move_messages(account_id, message_ids, target_folder, source_folder=source_folder, user=get_mcp_user())
