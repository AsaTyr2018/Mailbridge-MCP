from __future__ import annotations

import base64
import imaplib
import json
import re
import socket
import smtplib
import ssl
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Callable

from .audit import audit
from .db import db
from .security import secret_box


def row_to_account(row: Any, *, include_secret: bool = False) -> dict[str, Any]:
    result = dict(row)
    result["enabled"] = bool(result["enabled"])
    for key in [
        "sync_calendar_enabled",
        "sync_contacts_enabled",
        "mcp_read_enabled",
        "mcp_search_enabled",
        "mcp_calendar_enabled",
        "mcp_contacts_enabled",
        "mcp_draft_enabled",
    ]:
        result[key] = bool(result[key])
    if include_secret:
        result["imap_password"] = secret_box.decrypt(result.pop("imap_secret"))
        result["smtp_password"] = secret_box.decrypt(result.pop("smtp_secret"))
    else:
        result.pop("imap_secret", None)
        result.pop("smtp_secret", None)
    return result


def list_accounts(user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    with db() as conn:
        if user and not user.get("is_admin"):
            rows = conn.execute("SELECT * FROM accounts WHERE owner_user_id = ? ORDER BY name", (user["id"],)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM accounts ORDER BY name").fetchall()
    return [row_to_account(row) for row in rows]


def get_account(account_id: int, *, include_secret: bool = False, user: dict[str, Any] | None = None) -> dict[str, Any] | None:
    with db() as conn:
        if user and not user.get("is_admin"):
            row = conn.execute("SELECT * FROM accounts WHERE id = ? AND owner_user_id = ?", (account_id, user["id"])).fetchone()
        else:
            row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    return row_to_account(row, include_secret=include_secret) if row else None


def create_account(data: dict[str, Any], user: dict[str, Any] | None = None) -> int:
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO accounts (
                owner_user_id, name, enabled, email_address, display_name,
                imap_host, imap_port, imap_tls_mode, imap_username, imap_secret,
                smtp_host, smtp_port, smtp_tls_mode, smtp_username, smtp_secret,
                sync_folders, sync_calendar_enabled, sync_contacts_enabled, mail_index_mode,
                mcp_read_enabled, mcp_search_enabled, mcp_calendar_enabled,
                mcp_contacts_enabled, mcp_draft_enabled, mcp_send_mode,
                max_search_results, max_message_bytes,
                allowed_recipient_domains, blocked_recipient_domains
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"] if user else None,
                data["name"],
                int(data.get("enabled", True)),
                data["email_address"],
                data.get("display_name", ""),
                data["imap_host"],
                int(data.get("imap_port", 993)),
                data.get("imap_tls_mode", "ssl"),
                data["imap_username"],
                secret_box.encrypt(data.get("imap_password", "")),
                data["smtp_host"],
                int(data.get("smtp_port", 587)),
                data.get("smtp_tls_mode", "starttls"),
                data["smtp_username"],
                secret_box.encrypt(data.get("smtp_password", "")),
                data.get("sync_folders", "INBOX"),
                int(data.get("sync_calendar_enabled", False)),
                int(data.get("sync_contacts_enabled", False)),
                data.get("mail_index_mode", "metadata_only"),
                int(data.get("mcp_read_enabled", True)),
                int(data.get("mcp_search_enabled", True)),
                int(data.get("mcp_calendar_enabled", False)),
                int(data.get("mcp_contacts_enabled", False)),
                int(data.get("mcp_draft_enabled", True)),
                data.get("mcp_send_mode", "interactive_requires_ok"),
                int(data.get("max_search_results", 20)),
                int(data.get("max_message_bytes", 20000)),
                data.get("allowed_recipient_domains", ""),
                data.get("blocked_recipient_domains", ""),
            ),
        )
        account_id = int(cur.lastrowid)
    audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="account_create", status="ok", account_id=account_id)
    return account_id


def autodiscover_account_settings(email_address: str, password: str) -> dict[str, Any]:
    email_address = email_address.strip()
    if not email_address or "@" not in email_address:
        raise ValueError("valid email address required for autodiscovery")
    if not password:
        raise ValueError("password required for autodiscovery")
    domain = email_address.split("@", 1)[1].lower()
    hosts, smtp_hosts = _mail_autodiscovery_hosts(domain)
    imap_result = _autodiscover_imap(hosts, email_address, password)
    smtp_result = _autodiscover_smtp(smtp_hosts, email_address, password)
    return {
        "email_address": email_address,
        "imap_host": imap_result["host"],
        "imap_port": imap_result["port"],
        "imap_tls_mode": imap_result["tls_mode"],
        "imap_username": email_address,
        "imap_password": password,
        "smtp_host": smtp_result["host"],
        "smtp_port": smtp_result["port"],
        "smtp_tls_mode": smtp_result["tls_mode"],
        "smtp_username": email_address,
        "smtp_password": password,
        "imap_test": imap_result,
        "smtp_test": smtp_result,
    }


def _autodiscover_imap(hosts: list[str], username: str, password: str) -> dict[str, Any]:
    attempts = []
    auth_hint = ""
    for host in hosts:
        for port, tls_mode in ((993, "ssl"), (143, "starttls")):
            try:
                if tls_mode == "ssl":
                    client = imaplib.IMAP4_SSL(host, port, timeout=8)
                else:
                    client = imaplib.IMAP4(host, port, timeout=8)
                    client.starttls(ssl_context=ssl.create_default_context())
                try:
                    client.login(username, password)
                    return {"ok": True, "host": host, "port": port, "tls_mode": tls_mode}
                finally:
                    try:
                        client.logout()
                    except Exception:
                        pass
            except Exception as exc:
                message = str(exc)
                if _is_google_app_password_error(message):
                    auth_hint = _google_app_password_message()
                attempts.append(f"{host}:{port}/{tls_mode}: {message}")
    if auth_hint:
        raise ValueError(auth_hint)
    raise ValueError("IMAP autodiscovery failed: " + " | ".join(attempts[:6]))


def _autodiscover_smtp(hosts: list[str], username: str, password: str) -> dict[str, Any]:
    attempts = []
    auth_hint = ""
    for host in hosts:
        for port, tls_mode in ((587, "starttls"), (465, "ssl")):
            try:
                if tls_mode == "ssl":
                    client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=8)
                else:
                    client = smtplib.SMTP(host, port, timeout=8)
                    client.ehlo()
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                try:
                    client.login(username, password)
                    return {"ok": True, "host": host, "port": port, "tls_mode": tls_mode}
                finally:
                    try:
                        client.quit()
                    except Exception:
                        pass
            except (OSError, socket.timeout, smtplib.SMTPException) as exc:
                message = str(exc)
                if _is_google_app_password_error(message):
                    auth_hint = _google_app_password_message()
                attempts.append(f"{host}:{port}/{tls_mode}: {message}")
    if auth_hint:
        raise ValueError(auth_hint)
    raise ValueError("SMTP autodiscovery failed: " + " | ".join(attempts[:6]))


def _mail_autodiscovery_hosts(domain: str) -> tuple[list[str], list[str]]:
    if domain in {"gmail.com", "googlemail.com"}:
        return ["imap.gmail.com", "imap.googlemail.com"], ["smtp.gmail.com", "smtp.googlemail.com"]
    return (
        list(dict.fromkeys([f"mail.{domain}", f"imap.{domain}", domain])),
        list(dict.fromkeys([f"mail.{domain}", f"smtp.{domain}", domain])),
    )


def _is_google_app_password_error(message: str) -> bool:
    lowered = message.lower()
    return "application-specific password required" in lowered or "answer/185833" in lowered


def _google_app_password_message() -> str:
    return (
        "Google rejected IMAP/SMTP password login. Use a Google App Password for Gmail/Googlemail "
        "or OAuth2 support must be added later. Enable 2-Step Verification and create an app password: "
        "https://support.google.com/accounts/answer/185833"
    )


def update_account(account_id: int, data: dict[str, Any], user: dict[str, Any] | None = None) -> None:
    current = get_account(account_id, include_secret=True, user=user)
    if not current:
        raise ValueError("account not found")
    imap_secret = secret_box.encrypt(data.get("imap_password") or current["imap_password"])
    smtp_secret = secret_box.encrypt(data.get("smtp_password") or current["smtp_password"])
    with db() as conn:
        conn.execute(
            """
            UPDATE accounts SET
                name = ?, enabled = ?, email_address = ?, display_name = ?,
                imap_host = ?, imap_port = ?, imap_tls_mode = ?, imap_username = ?, imap_secret = ?,
                smtp_host = ?, smtp_port = ?, smtp_tls_mode = ?, smtp_username = ?, smtp_secret = ?,
                sync_folders = ?, sync_calendar_enabled = ?, sync_contacts_enabled = ?, mail_index_mode = ?,
                mcp_read_enabled = ?, mcp_search_enabled = ?, mcp_calendar_enabled = ?,
                mcp_contacts_enabled = ?, mcp_draft_enabled = ?, mcp_send_mode = ?,
                max_search_results = ?, max_message_bytes = ?,
                allowed_recipient_domains = ?, blocked_recipient_domains = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                data["name"],
                int(data.get("enabled", False)),
                data["email_address"],
                data.get("display_name", ""),
                data["imap_host"],
                int(data.get("imap_port", 993)),
                data.get("imap_tls_mode", "ssl"),
                data["imap_username"],
                imap_secret,
                data["smtp_host"],
                int(data.get("smtp_port", 587)),
                data.get("smtp_tls_mode", "starttls"),
                data["smtp_username"],
                smtp_secret,
                data.get("sync_folders", "INBOX"),
                int(data.get("sync_calendar_enabled", False)),
                int(data.get("sync_contacts_enabled", False)),
                data.get("mail_index_mode", "metadata_only"),
                int(data.get("mcp_read_enabled", False)),
                int(data.get("mcp_search_enabled", False)),
                int(data.get("mcp_calendar_enabled", False)),
                int(data.get("mcp_contacts_enabled", False)),
                int(data.get("mcp_draft_enabled", False)),
                data.get("mcp_send_mode", "interactive_requires_ok"),
                int(data.get("max_search_results", 20)),
                int(data.get("max_message_bytes", 20000)),
                data.get("allowed_recipient_domains", ""),
                data.get("blocked_recipient_domains", ""),
                account_id,
            ),
        )
    if data.get("mail_index_mode", "metadata_only") in {"metadata_only", "headers"}:
        _purge_index_content(account_id, data.get("mail_index_mode", "metadata_only"))
    audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="account_update", status="ok", account_id=account_id)


def _purge_index_content(account_id: int, mode: str) -> None:
    if mode == "full_text":
        return
    with db() as conn:
        if mode == "headers":
            conn.execute(
                """
                UPDATE messages
                SET snippet = '', text_body = '', attachment_names = '', indexed_at = CURRENT_TIMESTAMP
                WHERE account_id = ?
                """,
                (account_id,),
            )
        else:
            conn.execute(
                """
                UPDATE messages
                SET snippet = '', text_body = '', attachment_names = '', headers_json = '{}', indexed_at = CURRENT_TIMESTAMP
                WHERE account_id = ?
                """,
                (account_id,),
            )


def delete_account(account_id: int, user: dict[str, Any] | None = None) -> None:
    account = get_account(account_id, user=user)
    if not account:
        raise ValueError("account not found")
    with db() as conn:
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="account_delete", status="ok", account_id=account_id)


def _imap_connect(account: dict[str, Any]) -> imaplib.IMAP4:
    if account["imap_tls_mode"] == "ssl":
        client: imaplib.IMAP4 = imaplib.IMAP4_SSL(account["imap_host"], int(account["imap_port"]))
    else:
        client = imaplib.IMAP4(account["imap_host"], int(account["imap_port"]))
        if account["imap_tls_mode"] == "starttls":
            client.starttls(ssl_context=ssl.create_default_context())
    client.login(account["imap_username"], account["imap_password"])
    return client


def test_imap(account_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    client = _imap_connect(account)
    try:
        status, boxes = client.list()
        return {"ok": status == "OK", "mailboxes": len(boxes or [])}
    finally:
        try:
            client.logout()
        except Exception:
            pass


def test_smtp(account_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    client: smtplib.SMTP
    if account["smtp_tls_mode"] == "ssl":
        client = smtplib.SMTP_SSL(account["smtp_host"], int(account["smtp_port"]), timeout=20)
    else:
        client = smtplib.SMTP(account["smtp_host"], int(account["smtp_port"]), timeout=20)
    try:
        client.ehlo()
        if account["smtp_tls_mode"] == "starttls":
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        client.login(account["smtp_username"], account["smtp_password"])
        return {"ok": True}
    finally:
        try:
            client.quit()
        except Exception:
            pass


def _message_text(msg: EmailMessage) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        if parts:
            return "\n".join(parts)
    try:
        if msg.get_content_type() == "text/plain":
            return msg.get_content()
    except Exception:
        return ""
    return ""


def _address_header(msg: EmailMessage, header: str) -> str:
    return ", ".join(addr for _, addr in getaddresses(msg.get_all(header, [])) if addr)


def _attachment_names(msg: EmailMessage) -> str:
    names: list[str] = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        filename = part.get_filename()
        if filename:
            names.append(filename)
    return ", ".join(names)


def _parse_fetch_size_flags(fetch_meta: str) -> tuple[int, str]:
    size_match = re.search(r"RFC822\.SIZE\s+(\d+)", fetch_meta, flags=re.IGNORECASE)
    flags_match = re.search(r"FLAGS\s+\(([^)]*)\)", fetch_meta, flags=re.IGNORECASE)
    return (
        int(size_match.group(1)) if size_match else 0,
        flags_match.group(1) if flags_match else fetch_meta,
    )


def _extract_fetch_payload(msg_data: list[Any]) -> tuple[str, bytes]:
    raw = b""
    meta = ""
    for item in msg_data:
        if isinstance(item, tuple):
            try:
                meta = item[0].decode("utf-8", errors="ignore")
            except Exception:
                meta = str(item[0])
            raw = item[1]
            break
        if isinstance(item, bytes) and not meta:
            meta = item.decode("utf-8", errors="ignore")
        elif item is not None and not meta:
            meta = str(item)
    return meta, raw


ProgressCallback = Callable[[dict[str, Any]], None]


def _sync_fetch_spec(index_mode: str) -> str:
    if index_mode == "full_text":
        return "(RFC822 FLAGS)"
    if index_mode == "headers":
        return "(BODY.PEEK[HEADER] RFC822.SIZE FLAGS)"
    return "(BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC BCC SUBJECT MESSAGE-ID REFERENCES IN-REPLY-TO DELIVERED-TO)] RFC822.SIZE FLAGS)"


def _upsert_message_rows(rows: list[tuple[Any, ...]]) -> None:
    if not rows:
        return
    with db() as conn:
        conn.executemany(
            """
            INSERT INTO messages (
                account_id, folder, imap_uid, rfc822_message_id, thread_id,
                subject, sender, recipients, cc, bcc, delivered_to, sent_at,
                snippet, text_body, attachment_names, size_bytes, headers_json, flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id, folder, imap_uid) DO UPDATE SET
                subject = excluded.subject,
                sender = excluded.sender,
                recipients = excluded.recipients,
                cc = excluded.cc,
                bcc = excluded.bcc,
                delivered_to = excluded.delivered_to,
                sent_at = excluded.sent_at,
                snippet = excluded.snippet,
                text_body = excluded.text_body,
                attachment_names = excluded.attachment_names,
                size_bytes = excluded.size_bytes,
                headers_json = excluded.headers_json,
                flags = excluded.flags,
                indexed_at = CURRENT_TIMESTAMP
            """,
            rows,
        )


def _chunked(items: list[Any], size: int) -> list[list[Any]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def refresh_cached_flags(
    account_id: int,
    *,
    user: dict[str, Any] | None = None,
    max_messages: int | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    with db() as conn:
        limit_sql = " LIMIT ?" if max_messages else ""
        params: list[Any] = [account_id]
        if max_messages:
            params.append(max(1, int(max_messages)))
        rows = conn.execute(
            f"""
            SELECT id, folder, imap_uid, flags
            FROM messages
            WHERE account_id = ?
            ORDER BY indexed_at DESC, id DESC
            {limit_sql}
            """,
            params,
        ).fetchall()
    by_folder: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_folder.setdefault(str(row["folder"]), []).append(dict(row))
    checked = 0
    updated = 0
    errors: list[dict[str, Any]] = []
    client = _imap_connect(account)
    try:
        for folder, folder_rows in by_folder.items():
            if progress:
                progress({"phase": "flags", "folder": folder, "processed": checked, "updated_flags": updated, "total_estimate": len(rows)})
            status, _ = client.select(folder, readonly=True)
            if status != "OK":
                errors.append({"folder": folder, "error": "folder not selectable"})
                continue
            for chunk in _chunked(folder_rows, 100):
                update_rows: list[tuple[str, int]] = []
                for row in chunk:
                    status, msg_data = client.uid("fetch", str(row["imap_uid"]).encode("ascii"), "(FLAGS)")
                    checked += 1
                    if status != "OK" or not msg_data:
                        continue
                    fetch_meta, _raw = _extract_fetch_payload(msg_data)
                    _size, flags_text = _parse_fetch_size_flags(fetch_meta)
                    if flags_text != str(row.get("flags") or ""):
                        update_rows.append((flags_text, int(row["id"])))
                if update_rows:
                    with db() as conn:
                        conn.executemany("UPDATE messages SET flags = ?, indexed_at = CURRENT_TIMESTAMP WHERE id = ?", update_rows)
                    updated += len(update_rows)
                if progress:
                    progress({"phase": "flags", "folder": folder, "processed": checked, "updated_flags": updated, "total_estimate": len(rows)})
    finally:
        try:
            client.logout()
        except Exception:
            pass
    return {"checked": checked, "updated_flags": updated, "errors": errors}


def sync_account(
    account_id: int,
    *,
    limit: int = 100,
    user: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
    reconcile_flags: bool = True,
    flag_reconcile_limit: int | None = None,
    audit_actor_type: str = "mcp_client",
    audit_actor_id: str | None = None,
    audit_interface: str = "mcp",
    audit_token_id: str = "",
    audit_client_name: str = "",
    audit_client_version: str = "",
    audit_remote_addr: str = "",
    audit_user_agent: str = "",
    audit_intent: str = "",
    audit_target_resource: str | None = None,
) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    if not account["enabled"]:
        raise ValueError("account disabled")
    index_mode = account.get("mail_index_mode") or "metadata_only"
    indexed = 0
    total_estimate = 0
    client = _imap_connect(account)
    try:
        folders = [folder.strip() for folder in account["sync_folders"].split(",") if folder.strip()]
        for folder in folders:
            status, _ = client.select(folder, readonly=True)
            if status != "OK":
                continue
            status, data = client.uid("search", None, "ALL")
            if status != "OK" or not data or not data[0]:
                continue
            uids = data[0].split()[-limit:]
            total_estimate += len(uids)
            if progress:
                progress({"phase": "index", "folder": folder, "processed": indexed, "indexed": indexed, "total_estimate": total_estimate})
            batch_rows: list[tuple[Any, ...]] = []
            fetch_spec = _sync_fetch_spec(index_mode)
            for uid in uids:
                status, msg_data = client.uid("fetch", uid, fetch_spec)
                if status != "OK" or not msg_data:
                    continue
                fetch_meta, raw = _extract_fetch_payload(msg_data)
                if not raw:
                    continue
                msg = BytesParser(policy=policy.default).parsebytes(raw)
                text_body = _message_text(msg) if index_mode == "full_text" else ""
                subject = str(msg.get("subject", ""))
                sender = str(msg.get("from", ""))
                recipients = _address_header(msg, "to")
                cc = _address_header(msg, "cc")
                bcc = _address_header(msg, "bcc")
                delivered_to = _address_header(msg, "delivered-to")
                attachment_names = _attachment_names(msg) if index_mode == "full_text" else ""
                size_bytes, flags_text = _parse_fetch_size_flags(fetch_meta)
                sent_at = ""
                if msg.get("date"):
                    try:
                        sent_at = parsedate_to_datetime(str(msg.get("date"))).isoformat()
                    except Exception:
                        sent_at = str(msg.get("date"))
                snippet = " ".join(text_body.split())[:500] if index_mode == "full_text" else ""
                headers = {k: str(v) for k, v in msg.items()} if index_mode in {"headers", "full_text"} else {}
                batch_rows.append(
                    (
                        account_id,
                        folder,
                        uid.decode("ascii"),
                        str(msg.get("message-id", "")),
                        str(msg.get("references", msg.get("in-reply-to", msg.get("message-id", "")))),
                        subject,
                        sender,
                        recipients,
                        cc,
                        bcc,
                        delivered_to,
                        sent_at,
                        snippet,
                        text_body,
                        attachment_names,
                        size_bytes or len(raw),
                        json.dumps(headers),
                        flags_text,
                    )
                )
                indexed += 1
                if len(batch_rows) >= 50:
                    _upsert_message_rows(batch_rows)
                    batch_rows = []
                    if progress:
                        progress({"phase": "index", "folder": folder, "processed": indexed, "indexed": indexed, "total_estimate": total_estimate})
            _upsert_message_rows(batch_rows)
            if progress:
                progress({"phase": "index", "folder": folder, "processed": indexed, "indexed": indexed, "total_estimate": total_estimate})
        flag_result = {"checked": 0, "updated_flags": 0, "errors": []}
        if reconcile_flags:
            flag_result = refresh_cached_flags(account_id, user=user, max_messages=flag_reconcile_limit, progress=progress)
        with db() as conn:
            conn.execute(
                "UPDATE accounts SET last_sync_at = CURRENT_TIMESTAMP, last_sync_error = NULL WHERE id = ?",
                (account_id,),
            )
        audit(
            actor_type=audit_actor_type,
            actor_id=audit_actor_id or str(user["id"] if user else "codex"),
            interface=audit_interface,
            action="sync_account",
            status="ok",
            account_id=account_id,
            target_resource=audit_target_resource,
            token_id=audit_token_id,
            client_name=audit_client_name,
            client_version=audit_client_version,
            remote_addr=audit_remote_addr,
            user_agent=audit_user_agent,
            intent=audit_intent or "sync_account",
        )
        return {"ok": True, "indexed": indexed, "updated_flags": int(flag_result["updated_flags"]), "checked_flags": int(flag_result["checked"])}
    except Exception as exc:
        with db() as conn:
            conn.execute(
                "UPDATE accounts SET last_sync_error = ? WHERE id = ?",
                (str(exc), account_id),
            )
        audit(
            actor_type=audit_actor_type,
            actor_id=audit_actor_id or str(user["id"] if user else "codex"),
            interface=audit_interface,
            action="sync_account",
            status="error",
            account_id=account_id,
            target_resource=audit_target_resource,
            token_id=audit_token_id,
            client_name=audit_client_name,
            client_version=audit_client_version,
            remote_addr=audit_remote_addr,
            user_agent=audit_user_agent,
            intent=audit_intent or "sync_account",
            error_message=str(exc),
        )
        raise
    finally:
        try:
            client.logout()
        except Exception:
            pass


def _interval_modifier(value: str, unit: str) -> str:
    amount = max(1, int(value))
    units = {
        "d": "days",
        "m": "months",
        "y": "years",
    }
    return f"-{amount} {units.get(unit, 'days')}"


def _date_value(value: str) -> str:
    return value.replace("/", "-")


def _size_bytes(value: str, unit: str | None) -> int:
    amount = int(value)
    multipliers = {
        "k": 1000,
        "m": 1000 * 1000,
        "g": 1000 * 1000 * 1000,
    }
    return amount * multipliers.get((unit or "").lower(), 1)


def _like_param(value: str) -> str:
    return f"%{value.strip().strip('\"').lower()}%"


def _strip_wrappers(query: str) -> str:
    return query.replace("{", " ").replace("}", " ").replace("(", " ").replace(")", " ")


def _fts_term(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.upper() in {"OR", "AND", "NOT"}:
        return value.upper()
    if value.startswith('"') and value.endswith('"') and len(value) > 1:
        phrase = value[1:-1].replace('"', '""')
        return f'"{phrase}"'
    negated = value.startswith("-") and len(value) > 1
    exact = value.startswith("+") and len(value) > 1
    if negated or exact:
        value = value[1:]
    value = re.sub(r"[^\w.@-]+", " ", value, flags=re.UNICODE).strip()
    if not value:
        return ""
    if any(ch in value for ch in ".@-"):
        value = f'"{value.replace(chr(34), chr(34) * 2)}"'
    return f"NOT {value}" if negated else value


def _build_fts_query(remaining: str) -> str:
    pieces = re.findall(r'"[^"]+"|\S+', _strip_wrappers(remaining))
    terms = [_fts_term(piece) for piece in pieces]
    terms = [term for term in terms if term]
    if not terms:
        return ""
    # Keep explicit OR, otherwise FTS5's default AND behavior is useful for agent queries.
    return " ".join(terms)


def _parse_search_query(query: str) -> tuple[str, list[str], list[Any]]:
    where: list[str] = []
    params: list[Any] = []
    remaining = query
    field_columns = {
        "from": "m.sender",
        "to": "m.recipients",
        "cc": "m.cc",
        "bcc": "m.bcc",
        "subject": "m.subject",
    }

    def remove(pattern: str, handler) -> None:
        nonlocal remaining
        matches = list(re.finditer(pattern, remaining, flags=re.IGNORECASE))
        for match in matches:
            handler(match)
        remaining = re.sub(pattern, " ", remaining, flags=re.IGNORECASE)

    remove(
        r"\b(from|to|cc|bcc|subject):([^\s{}()]+)\s+OR\s+\1:([^\s{}()]+)",
        lambda match: (
            where.append(f"(lower({field_columns[match.group(1).lower()]}) LIKE ? OR lower({field_columns[match.group(1).lower()]}) LIKE ?)"),
            params.extend([_like_param(match.group(2)), _like_param(match.group(3))]),
        ),
    )
    remove(
        r"\{((?:(?:from|to|cc|bcc|subject):[^\s{}()]+\s*){2,})\}",
        lambda match: (
            where.append(
                "("
                + " OR ".join(
                    f"lower({field_columns[item.split(':', 1)[0].lower()]}) LIKE ?"
                    for item in match.group(1).split()
                    if item.split(":", 1)[0].lower() in field_columns
                )
                + ")"
            ),
            params.extend(_like_param(item.split(":", 1)[1]) for item in match.group(1).split() if item.split(":", 1)[0].lower() in field_columns),
        ),
    )

    remove(
        r"\bnewer_than:(\d+)([dmy])\b",
        lambda match: (
            where.append("m.sent_at IS NOT NULL AND m.sent_at != '' AND julianday(m.sent_at) >= julianday('now', ?)"),
            params.append(_interval_modifier(match.group(1), match.group(2).lower())),
        ),
    )
    remove(
        r"\bolder_than:(\d+)([dmy])\b",
        lambda match: (
            where.append("m.sent_at IS NOT NULL AND m.sent_at != '' AND julianday(m.sent_at) <= julianday('now', ?)"),
            params.append(_interval_modifier(match.group(1), match.group(2).lower())),
        ),
    )
    remove(
        r"\b(?:after|newer):(\d{4}[/-]\d{1,2}[/-]\d{1,2})",
        lambda match: (
            where.append("m.sent_at IS NOT NULL AND m.sent_at != '' AND date(m.sent_at) >= date(?)"),
            params.append(_date_value(match.group(1))),
        ),
    )
    remove(
        r"\b(?:before|older):(\d{4}[/-]\d{1,2}[/-]\d{1,2})",
        lambda match: (
            where.append("m.sent_at IS NOT NULL AND m.sent_at != '' AND date(m.sent_at) <= date(?)"),
            params.append(_date_value(match.group(1))),
        ),
    )
    remove(
        r"\bfrom:([^\s]+)",
        lambda match: (where.append("lower(m.sender) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\bto:([^\s]+)",
        lambda match: (where.append("lower(m.recipients) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\bcc:([^\s]+)",
        lambda match: (where.append("lower(m.cc) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\bbcc:([^\s]+)",
        lambda match: (where.append("lower(m.bcc) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\bdeliveredto:([^\s]+)",
        lambda match: (where.append("lower(m.delivered_to) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\bsubject:([^\s]+)",
        lambda match: (where.append("lower(m.subject) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\brfc822msgid:([^\s]+)",
        lambda match: (where.append("lower(m.rfc822_message_id) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\blist:([^\s]+)",
        lambda match: (where.append("lower(m.headers_json) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\bin:([^\s]+)",
        lambda match: None
        if match.group(1).lower() == "anywhere"
        else (where.append("lower(m.folder) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\blabel:([^\s]+)",
        lambda match: (where.append("lower(m.folder) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\bcategory:([^\s]+)",
        lambda match: None,
    )
    remove(
        r"\bis:(unread|read|starred|important|muted)\b",
        lambda match: (where.append("instr(m.flags, ?) = 0"), params.append("\\Seen"))
        if match.group(1).lower() == "unread"
        else (where.append("instr(m.flags, ?) > 0"), params.append("\\Seen"))
        if match.group(1).lower() == "read"
        else (where.append("instr(m.flags, ?) > 0"), params.append("\\Flagged"))
        if match.group(1).lower() == "starred"
        else where.append("lower(m.flags) LIKE '%important%'")
        if match.group(1).lower() == "important"
        else where.append("lower(m.flags) LIKE '%muted%'"),
    )
    remove(
        r"\bhas:attachment\b",
        lambda match: where.append("m.attachment_names != ''"),
    )
    remove(
        r"\bfilename:([^\s]+)",
        lambda match: (where.append("lower(m.attachment_names) LIKE ?"), params.append(_like_param(match.group(1)))),
    )
    remove(
        r"\b(?:size|larger):(\d+)([kmgKMG]?)\b",
        lambda match: (where.append("m.size_bytes >= ?"), params.append(_size_bytes(match.group(1), match.group(2)))),
    )
    remove(
        r"\bsmaller:(\d+)([kmgKMG]?)\b",
        lambda match: (where.append("m.size_bytes <= ?"), params.append(_size_bytes(match.group(1), match.group(2)))),
    )
    remove(
        r"\bhas:(drive|document|spreadsheet|presentation|youtube|userlabels|nouserlabels|yellow-star|red-bang)\b",
        lambda match: None,
    )

    fts_query = _build_fts_query(remaining)
    if fts_query in {"OR", "AND", "NOT"}:
        fts_query = ""
    return fts_query, where, params


def search_mail(account_id: int, query: str, limit: int | None = None, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    account = get_account(account_id, user=user)
    if not account or not account["mcp_search_enabled"]:
        raise ValueError("mail search not allowed for account")
    effective_limit = min(limit or account["max_search_results"], account["max_search_results"])
    fts_query, extra_where, extra_params = _parse_search_query(query)
    where_parts = ["m.account_id = ?", *extra_where]
    params: list[Any] = [account_id, *extra_params]
    if fts_query:
        where_parts.insert(0, "messages_fts MATCH ?")
        params.insert(0, fts_query)
        from_clause = "FROM messages_fts f JOIN messages m ON m.id = f.rowid"
        order_clause = "ORDER BY bm25(messages_fts)"
    else:
        from_clause = "FROM messages m"
        order_clause = "ORDER BY m.sent_at DESC, m.id DESC"
    params.append(effective_limit)
    with db() as conn:
        rows = conn.execute(
            f"""
            SELECT m.id, m.account_id, m.folder, m.subject, m.sender, m.recipients,
                   m.cc, m.bcc, m.delivered_to, m.sent_at, m.snippet,
                   m.attachment_names, m.size_bytes, m.indexed_at
            {from_clause}
            WHERE {" AND ".join(where_parts)}
            {order_clause}
            LIMIT ?
            """,
            params,
        ).fetchall()
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="search_mail", status="ok", account_id=account_id)
    return [dict(row) for row in rows]


def flush_mail_cache(*, user: dict[str, Any] | None = None, all_users: bool = False) -> dict[str, Any]:
    if all_users and (not user or not user.get("is_admin")):
        raise PermissionError("admin required")
    with db() as conn:
        if all_users:
            count = conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"]
            conn.execute("DELETE FROM messages")
            conn.execute("UPDATE accounts SET last_sync_at = NULL, last_sync_error = NULL")
            account_count = conn.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()["c"]
        else:
            if not user:
                raise ValueError("user required")
            count = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM messages m
                JOIN accounts a ON a.id = m.account_id
                WHERE a.owner_user_id = ?
                """,
                (int(user["id"]),),
            ).fetchone()["c"]
            conn.execute(
                """
                DELETE FROM messages
                WHERE account_id IN (SELECT id FROM accounts WHERE owner_user_id = ?)
                """,
                (int(user["id"]),),
            )
            conn.execute(
                """
                UPDATE accounts
                SET last_sync_at = NULL, last_sync_error = NULL
                WHERE owner_user_id = ?
                """,
                (int(user["id"]),),
            )
            account_count = conn.execute("SELECT COUNT(*) AS c FROM accounts WHERE owner_user_id = ?", (int(user["id"]),)).fetchone()["c"]
    audit(
        actor_type="human",
        actor_id=str(user["id"] if user else "admin"),
        interface="http",
        action="flush_mail_cache_all" if all_users else "flush_mail_cache",
        status="ok",
        target_resource="all" if all_users else f"user:{user['id'] if user else ''}",
        policy_decision=f"deleted_messages:{count}",
    )
    return {"ok": True, "deleted_messages": int(count), "affected_accounts": int(account_count), "scope": "all" if all_users else "user"}


def _live_message_body(account: dict[str, Any], row: dict[str, Any], max_bytes: int, user: dict[str, Any] | None = None) -> tuple[str, bool, str, str]:
    raw = _live_message_raw(account, row, user=user)
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body = _message_text(msg)
    attachment_names = _attachment_names(msg)
    encoded = body.encode("utf-8")
    if len(encoded) > max_bytes:
        return encoded[:max_bytes].decode("utf-8", errors="ignore"), True, attachment_names, "live_imap_truncated"
    return body, False, attachment_names, "live_imap"


def _live_message_raw(account: dict[str, Any], row: dict[str, Any], user: dict[str, Any] | None = None) -> bytes:
    full_account = get_account(int(account["id"]), include_secret=True, user=user)
    if not full_account:
        raise ValueError("account not found")
    client = _imap_connect(full_account)
    try:
        status, _ = client.select(row["folder"], readonly=True)
        if status != "OK":
            raise ValueError("folder not selectable")
        status, msg_data = client.uid("fetch", str(row["imap_uid"]).encode("ascii"), "(RFC822)")
        if status != "OK" or not msg_data:
            raise ValueError("message fetch failed")
        _, raw = _extract_fetch_payload(msg_data)
        if not raw:
            raise ValueError("message unavailable")
        return raw
    finally:
        try:
            client.logout()
        except Exception:
            pass


def get_message(message_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row:
        raise ValueError("message not found")
    account = get_account(int(row["account_id"]), user=user)
    if not account or not account["mcp_read_enabled"]:
        raise ValueError("message read not allowed for account")
    result = dict(row)
    max_bytes = int(account["max_message_bytes"])
    body = result["text_body"]
    if not body:
        live_body, truncated, attachment_names, source = _live_message_body(account, result, max_bytes, user=user)
        result["text_body"] = live_body
        result["truncated"] = truncated
        result["body_source"] = source
        if attachment_names and not result.get("attachment_names"):
            result["attachment_names"] = attachment_names
    else:
        encoded = body.encode("utf-8")
        if len(encoded) > max_bytes:
            result["text_body"] = encoded[:max_bytes].decode("utf-8", errors="ignore")
            result["truncated"] = True
        else:
            result["truncated"] = False
        result["body_source"] = "local_index"
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="get_message", status="ok", account_id=int(row["account_id"]), target_resource=str(message_id))
    return result


def _message_row(message_id: int) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row:
        raise ValueError("message not found")
    return dict(row)


def _attachment_parts(msg: EmailMessage) -> list[dict[str, Any]]:
    parts = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        filename = part.get_filename()
        disposition = str(part.get_content_disposition() or "")
        if not filename and disposition != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        parts.append(
            {
                "index": len(parts),
                "filename": filename or f"attachment-{len(parts) + 1}",
                "content_type": part.get_content_type(),
                "content_id": str(part.get("content-id", "")).strip("<>"),
                "disposition": disposition or "attachment",
                "size_bytes": len(payload),
                "_payload": payload,
            }
        )
    return parts


def list_attachments(message_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    row = _message_row(message_id)
    account = get_account(int(row["account_id"]), user=user)
    if not account or not account["mcp_read_enabled"]:
        raise ValueError("message read not allowed for account")
    raw = _live_message_raw(account, row, user=user)
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    attachments = []
    for part in _attachment_parts(msg):
        item = dict(part)
        item.pop("_payload", None)
        attachments.append(item)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="list_attachments", status="ok", account_id=int(row["account_id"]), target_resource=str(message_id))
    return {"message_id": message_id, "account_id": int(row["account_id"]), "attachments": attachments, "count": len(attachments)}


def get_attachment(message_id: int, attachment_index: int = 0, filename: str = "", max_bytes: int = 1_000_000, user: dict[str, Any] | None = None) -> dict[str, Any]:
    row = _message_row(message_id)
    account = get_account(int(row["account_id"]), user=user)
    if not account or not account["mcp_read_enabled"]:
        raise ValueError("message read not allowed for account")
    raw = _live_message_raw(account, row, user=user)
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    attachments = _attachment_parts(msg)
    selected = None
    if filename.strip():
        for part in attachments:
            if str(part["filename"]).lower() == filename.strip().lower():
                selected = part
                break
    elif 0 <= int(attachment_index) < len(attachments):
        selected = attachments[int(attachment_index)]
    if not selected:
        raise ValueError("attachment not found")
    safe_max = max(1, min(int(max_bytes), 5_000_000))
    payload = selected["_payload"]
    truncated = len(payload) > safe_max
    payload = payload[:safe_max]
    metadata = dict(selected)
    metadata.pop("_payload", None)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="get_attachment", status="ok", account_id=int(row["account_id"]), target_resource=f"{message_id}:{metadata['index']}")
    return {
        "message_id": message_id,
        "account_id": int(row["account_id"]),
        "attachment": metadata,
        "content_base64": base64.b64encode(payload).decode("ascii"),
        "encoding": "base64",
        "truncated": truncated,
    }


def _select_message_attachments(
    message_id: int,
    *,
    attachment_indices: list[int] | None = None,
    attachment_filenames: list[str] | None = None,
    user: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    row = _message_row(message_id)
    account = get_account(int(row["account_id"]), user=user)
    if not account or not account["mcp_read_enabled"]:
        raise ValueError("message read not allowed for account")
    raw = _live_message_raw(account, row, user=user)
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    attachments = _attachment_parts(msg)
    wanted_indices = {int(index) for index in attachment_indices or []}
    wanted_filenames = {str(name).strip().lower() for name in attachment_filenames or [] if str(name).strip()}
    if not wanted_indices and not wanted_filenames:
        return attachments
    selected = []
    for part in attachments:
        if int(part["index"]) in wanted_indices or str(part["filename"]).lower() in wanted_filenames:
            selected.append(part)
    return selected


def move_messages(
    account_id: int,
    message_ids: list[int],
    target_folder: str,
    *,
    source_folder: str = "",
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    target_folder = target_folder.strip()
    if not target_folder:
        raise ValueError("target_folder is required")
    safe_ids = sorted({int(message_id) for message_id in message_ids if int(message_id) > 0})
    if not safe_ids:
        return {"ok": True, "account_id": account_id, "target_folder": target_folder, "moved": [], "skipped": [], "errors": []}
    placeholders = ",".join("?" for _ in safe_ids)
    params: list[Any] = [account_id, *safe_ids]
    where = f"account_id = ? AND id IN ({placeholders})"
    if source_folder.strip():
        where += " AND lower(folder) = ?"
        params.append(source_folder.strip().lower())
    with db() as conn:
        rows = conn.execute(f"SELECT id, folder, imap_uid, subject FROM messages WHERE {where}", params).fetchall()
    rows_by_id = {int(row["id"]): dict(row) for row in rows}
    skipped = [{"message_id": message_id, "reason": "not found or source folder mismatch"} for message_id in safe_ids if message_id not in rows_by_id]
    moved: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    by_folder: dict[str, list[dict[str, Any]]] = {}
    for row in rows_by_id.values():
        by_folder.setdefault(str(row["folder"]), []).append(row)
    client = _imap_connect(account)
    try:
        try:
            client.create(target_folder)
        except Exception:
            pass
        for folder, folder_rows in by_folder.items():
            status, _ = client.select(folder, readonly=False)
            if status != "OK":
                errors.extend({"message_id": int(row["id"]), "error": f"folder not selectable: {folder}"} for row in folder_rows)
                continue
            for row in folder_rows:
                uid = str(row["imap_uid"])
                message_id = int(row["id"])
                try:
                    status, _ = client.uid("MOVE", uid.encode("ascii"), target_folder)
                    if status != "OK":
                        status, _ = client.uid("COPY", uid.encode("ascii"), target_folder)
                        if status != "OK":
                            raise ValueError("IMAP copy failed")
                        status, _ = client.uid("STORE", uid.encode("ascii"), "+FLAGS.SILENT", r"(\Deleted)")
                        if status != "OK":
                            raise ValueError("IMAP delete flag failed after copy")
                        client.expunge()
                    with db() as conn:
                        conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
                    moved.append({"message_id": message_id, "from": folder, "to": target_folder, "subject": row.get("subject", "")})
                except Exception as exc:
                    errors.append({"message_id": message_id, "error": str(exc)})
    finally:
        try:
            client.logout()
        except Exception:
            pass
    status = "ok" if not errors else "partial"
    audit(
        actor_type="mcp_client",
        actor_id=str(user["id"] if user else "codex"),
        interface="mcp",
        action="move_messages",
        status=status,
        account_id=account_id,
        target_resource=",".join(str(item["message_id"]) for item in moved),
        error_message=json.dumps(errors)[:500] if errors else "",
    )
    return {
        "ok": not errors,
        "status": status,
        "account_id": account_id,
        "target_folder": target_folder,
        "moved": moved,
        "skipped": skipped,
        "errors": errors,
    }


def _local_message_rows(
    account_id: int,
    message_ids: list[int],
    *,
    source_folder: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    safe_ids = sorted({int(message_id) for message_id in message_ids if int(message_id) > 0})
    if not safe_ids:
        return [], []
    placeholders = ",".join("?" for _ in safe_ids)
    params: list[Any] = [account_id, *safe_ids]
    where = f"account_id = ? AND id IN ({placeholders})"
    if source_folder.strip():
        where += " AND lower(folder) = ?"
        params.append(source_folder.strip().lower())
    with db() as conn:
        rows = conn.execute(f"SELECT * FROM messages WHERE {where}", params).fetchall()
    found = [dict(row) for row in rows]
    found_ids = {int(row["id"]) for row in found}
    skipped = [{"message_id": message_id, "reason": "not found or source folder mismatch"} for message_id in safe_ids if message_id not in found_ids]
    return found, skipped


def _messages_by_folder(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_folder: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_folder.setdefault(str(row["folder"]), []).append(row)
    return by_folder


def mark_messages(
    account_id: int,
    message_ids: list[int],
    *,
    read: bool,
    source_folder: str = "",
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    rows, skipped = _local_message_rows(account_id, message_ids, source_folder=source_folder)
    changed: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    client = _imap_connect(account)
    try:
        for folder, folder_rows in _messages_by_folder(rows).items():
            status, _ = client.select(folder, readonly=False)
            if status != "OK":
                errors.extend({"message_id": int(row["id"]), "error": f"folder not selectable: {folder}"} for row in folder_rows)
                continue
            operation = "+FLAGS.SILENT" if read else "-FLAGS.SILENT"
            for row in folder_rows:
                message_id = int(row["id"])
                try:
                    status, _ = client.uid("STORE", str(row["imap_uid"]).encode("ascii"), operation, r"(\Seen)")
                    if status != "OK":
                        raise ValueError("IMAP flag update failed")
                    flags = str(row.get("flags") or "")
                    has_seen = "\\Seen" in flags or "Seen" in flags
                    if read and not has_seen:
                        flags = (flags + " \\Seen").strip()
                    elif not read:
                        flags = re.sub(r"\\?Seen", "", flags, flags=re.IGNORECASE).strip()
                    with db() as conn:
                        conn.execute("UPDATE messages SET flags = ?, indexed_at = CURRENT_TIMESTAMP WHERE id = ?", (flags, message_id))
                    changed.append({"message_id": message_id, "folder": folder, "read": read})
                except Exception as exc:
                    errors.append({"message_id": message_id, "error": str(exc)})
    finally:
        try:
            client.logout()
        except Exception:
            pass
    status = "ok" if not errors else "partial"
    audit(
        actor_type="mcp_client",
        actor_id=str(user["id"] if user else "codex"),
        interface="mcp",
        action="mark_messages",
        status=status,
        account_id=account_id,
        target_resource=",".join(str(item["message_id"]) for item in changed),
        policy_decision="read" if read else "unread",
        error_message=json.dumps(errors)[:500] if errors else "",
    )
    return {"ok": not errors, "status": status, "account_id": account_id, "read": read, "changed": changed, "skipped": skipped, "errors": errors}


def trash_messages(
    account_id: int,
    message_ids: list[int],
    *,
    trash_folder: str = "Trash",
    source_folder: str = "",
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return move_messages(account_id, message_ids, trash_folder or "Trash", source_folder=source_folder, user=user)


def add_label_to_messages(
    account_id: int,
    message_ids: list[int],
    label: str,
    *,
    source_folder: str = "",
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    label = label.strip()
    if not label:
        raise ValueError("label is required")
    rows, skipped = _local_message_rows(account_id, message_ids, source_folder=source_folder)
    copied: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    client = _imap_connect(account)
    try:
        try:
            client.create(label)
        except Exception:
            pass
        for folder, folder_rows in _messages_by_folder(rows).items():
            status, _ = client.select(folder, readonly=False)
            if status != "OK":
                errors.extend({"message_id": int(row["id"]), "error": f"folder not selectable: {folder}"} for row in folder_rows)
                continue
            for row in folder_rows:
                message_id = int(row["id"])
                try:
                    status, _ = client.uid("COPY", str(row["imap_uid"]).encode("ascii"), label)
                    if status != "OK":
                        raise ValueError("IMAP copy failed")
                    copied.append({"message_id": message_id, "from": folder, "label": label, "subject": row.get("subject", "")})
                except Exception as exc:
                    errors.append({"message_id": message_id, "error": str(exc)})
    finally:
        try:
            client.logout()
        except Exception:
            pass
    status = "ok" if not errors else "partial"
    audit(
        actor_type="mcp_client",
        actor_id=str(user["id"] if user else "codex"),
        interface="mcp",
        action="add_label",
        status=status,
        account_id=account_id,
        target_resource=label,
        error_message=json.dumps(errors)[:500] if errors else "",
    )
    return {"ok": not errors, "status": status, "account_id": account_id, "label": label, "copied": copied, "skipped": skipped, "errors": errors}


def remove_label_from_messages(
    account_id: int,
    message_ids: list[int],
    label: str,
    *,
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    label = label.strip()
    if not label:
        raise ValueError("label is required")
    rows, skipped = _local_message_rows(account_id, message_ids, source_folder=label)
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    removed: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    client = _imap_connect(account)
    try:
        status, _ = client.select(label, readonly=False)
        if status != "OK":
            errors.extend({"message_id": int(row["id"]), "error": f"folder not selectable: {label}"} for row in rows)
        else:
            for row in rows:
                message_id = int(row["id"])
                try:
                    status, _ = client.uid("STORE", str(row["imap_uid"]).encode("ascii"), "+FLAGS.SILENT", r"(\Deleted)")
                    if status != "OK":
                        raise ValueError("IMAP delete flag failed")
                    removed.append({"message_id": message_id, "label": label, "subject": row.get("subject", "")})
                except Exception as exc:
                    errors.append({"message_id": message_id, "error": str(exc)})
            if removed:
                client.expunge()
                with db() as conn:
                    conn.executemany("DELETE FROM messages WHERE id = ?", [(item["message_id"],) for item in removed])
    finally:
        try:
            client.logout()
        except Exception:
            pass
    status = "ok" if not errors else "partial"
    audit(
        actor_type="mcp_client",
        actor_id=str(user["id"] if user else "codex"),
        interface="mcp",
        action="remove_label",
        status=status,
        account_id=account_id,
        target_resource=label,
        error_message=json.dumps(errors)[:500] if errors else "",
    )
    return {"ok": not errors, "status": status, "account_id": account_id, "label": label, "removed": removed, "skipped": skipped, "errors": errors}


def create_draft(account_id: int, to_recipients: str, subject: str, body_text: str, cc_recipients: str = "", bcc_recipients: str = "", in_reply_to_message_id: int | None = None, user: dict[str, Any] | None = None) -> dict[str, Any]:
    account = get_account(account_id, user=user)
    if not account or not account["mcp_draft_enabled"]:
        raise ValueError("draft creation not allowed for account")
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO drafts (
                account_id, to_recipients, cc_recipients, bcc_recipients,
                subject, body_text, in_reply_to_message_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (account_id, to_recipients, cc_recipients, bcc_recipients, subject, body_text, in_reply_to_message_id),
        )
        draft_id = int(cur.lastrowid)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="create_draft", status="ok", account_id=account_id, target_resource=str(draft_id))
    return get_draft(draft_id, user=user)


def _add_draft_attachments(draft_id: int, source_message_id: int, attachments: list[dict[str, Any]]) -> int:
    if not attachments:
        return 0
    with db() as conn:
        for part in attachments:
            payload = part.get("_payload") or b""
            conn.execute(
                """
                INSERT INTO draft_attachments (
                    draft_id, source_message_id, source_attachment_index,
                    filename, content_type, content, size_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft_id,
                    source_message_id,
                    int(part["index"]),
                    str(part["filename"]),
                    str(part["content_type"] or "application/octet-stream"),
                    payload,
                    len(payload),
                ),
            )
    return len(attachments)


def create_forward_draft(
    message_id: int,
    to_recipients: str,
    note: str = "",
    cc_recipients: str = "",
    bcc_recipients: str = "",
    subject: str = "",
    attachment_indices: list[int] | None = None,
    attachment_filenames: list[str] | None = None,
    include_attachments: bool = False,
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    original = get_message(message_id, user=user)
    account_id = int(original["account_id"])
    original_subject = str(original.get("subject") or "")
    forward_subject = subject.strip() if subject.strip() else (original_subject if original_subject.lower().startswith("fwd:") else f"Fwd: {original_subject}")
    body_parts = []
    if note.strip():
        body_parts.append(note.strip())
        body_parts.append("")
    body_parts.extend(
        [
            "---------- Forwarded message ---------",
            f"From: {original.get('sender', '')}",
            f"Date: {original.get('sent_at', '')}",
            f"Subject: {original.get('subject', '')}",
            f"To: {original.get('recipients', '')}",
            "",
            str(original.get("text_body") or ""),
        ]
    )
    draft = create_draft(
        account_id,
        to_recipients,
        forward_subject,
        "\n".join(body_parts),
        cc_recipients=cc_recipients,
        bcc_recipients=bcc_recipients,
        in_reply_to_message_id=message_id,
        user=user,
    )
    attached_count = 0
    if include_attachments or attachment_indices or attachment_filenames:
        selected = _select_message_attachments(
            message_id,
            attachment_indices=attachment_indices,
            attachment_filenames=attachment_filenames,
            user=user,
        )
        attached_count = _add_draft_attachments(int(draft["id"]), message_id, selected)
        draft = get_draft(int(draft["id"]), user=user)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="create_forward_draft", status="ok", account_id=account_id, target_resource=str(draft["id"]))
    return draft | {"attached_count": attached_count}


def _draft_attachment_summaries(draft_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, source_message_id, source_attachment_index, filename, content_type, size_bytes, created_at
            FROM draft_attachments
            WHERE draft_id = ?
            ORDER BY id
            """,
            (draft_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _draft_attachment_rows(draft_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM draft_attachments WHERE draft_id = ? ORDER BY id",
            (draft_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_draft(draft_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db() as conn:
        if user and not user.get("is_admin"):
            row = conn.execute(
                "SELECT d.* FROM drafts d JOIN accounts a ON a.id = d.account_id WHERE d.id = ? AND a.owner_user_id = ?",
                (draft_id, user["id"]),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM drafts WHERE id = ?", (draft_id,)).fetchone()
    if not row:
        raise ValueError("draft not found")
    result = dict(row)
    result["attachments"] = _draft_attachment_summaries(draft_id)
    result["attachment_count"] = len(result["attachments"])
    return result


def list_drafts(user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    with db() as conn:
        if user and not user.get("is_admin"):
            rows = conn.execute(
                """
                SELECT d.*, a.name AS account_name, a.email_address AS account_email
                FROM drafts d
                JOIN accounts a ON a.id = d.account_id
                WHERE a.owner_user_id = ?
                ORDER BY d.created_at DESC
                LIMIT 100
                """,
                (user["id"],),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT d.*, a.name AS account_name, a.email_address AS account_email
                FROM drafts d
                JOIN accounts a ON a.id = d.account_id
                ORDER BY d.created_at DESC
                LIMIT 100
                """
            ).fetchall()
    return [dict(row) for row in rows]


def list_pending_drafts(user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    with db() as conn:
        if user and not user.get("is_admin"):
            rows = conn.execute(
                """
                SELECT d.*, a.name AS account_name, a.email_address AS account_email
                FROM drafts d
                JOIN accounts a ON a.id = d.account_id
                WHERE a.owner_user_id = ? AND d.status = 'pending_approval'
                ORDER BY d.created_at DESC
                LIMIT 100
                """,
                (user["id"],),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT d.*, a.name AS account_name, a.email_address AS account_email
                FROM drafts d
                JOIN accounts a ON a.id = d.account_id
                WHERE d.status = 'pending_approval'
                ORDER BY d.created_at DESC
                LIMIT 100
                """
            ).fetchall()
    return [dict(row) for row in rows]


def list_automation_consents(account_id: int | None = None, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = []
    if account_id is not None:
        if not get_account(int(account_id), user=user):
            raise ValueError("account not found")
        where.append("c.account_id = ?")
        params.append(int(account_id))
    if user and not user.get("is_admin"):
        where.append("a.owner_user_id = ?")
        params.append(user["id"])
    query = """
        SELECT c.*, a.name AS account_name, a.email_address AS account_email
        FROM automation_consents c
        JOIN accounts a ON a.id = c.account_id
    """
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY c.created_at DESC"
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def create_automation_consent(
    account_id: int,
    name: str,
    allowed_recipients: str = "",
    allowed_domains: str = "",
    max_sends_per_day: int = 0,
    expires_at: str = "",
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    account = get_account(account_id, user=user)
    if not account:
        raise ValueError("account not found")
    if not name.strip():
        raise ValueError("consent name is required")
    if not allowed_recipients.strip() and not allowed_domains.strip():
        raise ValueError("automation consent requires allowed_recipients or allowed_domains")
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO automation_consents (
                account_id, name, allowed_recipients, allowed_domains,
                max_sends_per_day, expires_at, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
            (
                account_id,
                name.strip(),
                allowed_recipients.strip(),
                allowed_domains.strip(),
                max(0, int(max_sends_per_day or 0)),
                expires_at.strip() or None,
            ),
        )
        consent_id = int(cur.lastrowid)
    audit(actor_type="mcp_client" if user else "human", actor_id=str(user["id"] if user else "admin"), interface="mcp" if user else "http", action="automation_consent_create", status="ok", account_id=account_id, target_resource=str(consent_id))
    return _get_automation_consent(consent_id, user=user)


def revoke_automation_consent(consent_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    consent = _get_automation_consent(consent_id, user=user)
    with db() as conn:
        conn.execute("UPDATE automation_consents SET enabled = 0 WHERE id = ?", (consent_id,))
    audit(actor_type="mcp_client" if user else "human", actor_id=str(user["id"] if user else "admin"), interface="mcp" if user else "http", action="automation_consent_revoke", status="ok", account_id=int(consent["account_id"]), target_resource=str(consent_id))
    return _get_automation_consent(consent_id, user=user)


def list_mail_history(user: dict[str, Any] | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 200))
    with db() as conn:
        if user and not user.get("is_admin"):
            rows = conn.execute(
                """
                SELECT d.id, d.account_id, a.name AS account_name, a.email_address AS account_email,
                       d.to_recipients, d.cc_recipients, d.bcc_recipients,
                       d.subject, d.body_text, d.sent_at, d.created_at, d.approved_by,
                       d.revision, d.created_by
                FROM drafts d
                JOIN accounts a ON a.id = d.account_id
                WHERE a.owner_user_id = ?
                  AND d.status = 'sent'
                ORDER BY d.sent_at DESC, d.id DESC
                LIMIT ?
                """,
                (user["id"], safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT d.id, d.account_id, a.name AS account_name, a.email_address AS account_email,
                       d.to_recipients, d.cc_recipients, d.bcc_recipients,
                       d.subject, d.body_text, d.sent_at, d.created_at, d.approved_by,
                       d.revision, d.created_by
                FROM drafts d
                JOIN accounts a ON a.id = d.account_id
                WHERE d.status = 'sent'
                ORDER BY d.sent_at DESC, d.id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def list_audit_events(user: dict[str, Any] | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 200))
    with db() as conn:
        if user and not user.get("is_admin"):
            rows = conn.execute(
                """
                SELECT al.*, a.name AS account_name, a.email_address AS account_email
                FROM audit_log al
                LEFT JOIN accounts a ON a.id = al.account_id
                WHERE a.owner_user_id = ?
                   OR (al.account_id IS NULL AND al.actor_id = ?)
                ORDER BY al.created_at DESC, al.id DESC
                LIMIT ?
                """,
                (user["id"], str(user["id"]), safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT al.*, a.name AS account_name, a.email_address AS account_email
                FROM audit_log al
                LEFT JOIN accounts a ON a.id = al.account_id
                ORDER BY al.created_at DESC, al.id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def list_security_audit_events(user: dict[str, Any] | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 200))
    with db() as conn:
        if user and not user.get("is_admin"):
            rows = conn.execute(
                """
                SELECT al.*, a.name AS account_name, a.email_address AS account_email, u.username
                FROM audit_log al
                LEFT JOIN accounts a ON a.id = al.account_id
                LEFT JOIN users u ON CAST(u.id AS TEXT) = al.actor_id
                WHERE al.interface IN ('mcp', 'system')
                  AND (
                    a.owner_user_id = ?
                    OR al.actor_id = ?
                  )
                ORDER BY al.created_at DESC, al.id DESC
                LIMIT ?
                """,
                (user["id"], str(user["id"]), safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT al.*, a.name AS account_name, a.email_address AS account_email, u.username
                FROM audit_log al
                LEFT JOIN accounts a ON a.id = al.account_id
                LEFT JOIN users u ON CAST(u.id AS TEXT) = al.actor_id
                WHERE al.interface IN ('mcp', 'system')
                ORDER BY al.created_at DESC, al.id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def bearer_security_summary(user: dict[str, Any] | None = None) -> dict[str, Any]:
    if not user:
        return {}
    rows = [row for row in list_security_audit_events(user=user, limit=100) if row.get("interface") == "mcp"][:20]
    latest = rows[0] if rows else None
    warning = ""
    status = "Normal"
    if latest:
        latest_ip = latest.get("remote_addr") or ""
        latest_client = latest.get("client_name") or latest.get("user_agent") or ""
        previous_ips = {row.get("remote_addr") for row in rows[1:] if row.get("remote_addr")}
        previous_clients = {(row.get("client_name") or row.get("user_agent")) for row in rows[1:] if row.get("client_name") or row.get("user_agent")}
        if latest_ip and previous_ips and latest_ip not in previous_ips:
            warning = "Token was used from a new IP address."
            status = "Review"
        elif latest_client and previous_clients and latest_client not in previous_clients:
            warning = "Token was used by a new client."
            status = "Review"
    return {
        "latest": latest,
        "status": status,
        "warning": warning,
    }


def search_contacts(account_id: int, query: str, limit: int = 20, user: dict[str, Any] | None = None) -> dict[str, Any]:
    account = get_account(account_id, user=user)
    if not account or not account["mcp_contacts_enabled"]:
        raise ValueError("contact lookup not allowed for account")
    safe_limit = max(1, min(limit, 100))
    needle = f"%{query.strip().lower()}%"
    with db() as conn:
        if query.strip():
            rows = conn.execute(
                """
                SELECT c.*, sp.provider, sp.name AS profile_name
                FROM contacts c
                LEFT JOIN sync_profiles sp ON sp.id = c.profile_id
                WHERE c.account_id = ?
                  AND (
                    lower(c.display_name) LIKE ?
                    OR lower(c.emails) LIKE ?
                    OR lower(c.phones) LIKE ?
                    OR lower(c.company) LIKE ?
                  )
                ORDER BY c.display_name, c.emails
                LIMIT ?
                """,
                (account_id, needle, needle, needle, needle, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT c.*, sp.provider, sp.name AS profile_name
                FROM contacts c
                LEFT JOIN sync_profiles sp ON sp.id = c.profile_id
                WHERE c.account_id = ?
                ORDER BY c.display_name, c.emails
                LIMIT ?
                """,
                (account_id, safe_limit),
            ).fetchall()
    contacts = _dedupe_contacts([dict(row) for row in rows])
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="search_contacts", status="ok", account_id=account_id)
    return {
        "account_id": account_id,
        "query": query,
        "limit": safe_limit,
        "contacts": contacts,
        "status": "ok",
    }


def _dedupe_contacts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        emails = str(row.get("emails") or "").lower().strip()
        name = str(row.get("display_name") or "").lower().strip()
        key = (emails, name)
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result


def list_calendar_events(account_id: int, start_at: str, end_at: str, limit: int = 50, user: dict[str, Any] | None = None) -> dict[str, Any]:
    account = get_account(account_id, user=user)
    if not account or not account["mcp_calendar_enabled"]:
        raise ValueError("calendar lookup not allowed for account")
    safe_limit = max(1, min(limit, 200))
    with db() as conn:
        rows = conn.execute(
            """
            SELECT e.*, sp.provider, sp.name AS profile_name
            FROM calendar_events e
            LEFT JOIN sync_profiles sp ON sp.id = e.profile_id
            WHERE e.account_id = ?
              AND (? = '' OR e.ends_at = '' OR e.ends_at >= ?)
              AND (? = '' OR e.starts_at = '' OR e.starts_at <= ?)
            ORDER BY e.starts_at, e.title
            LIMIT ?
            """,
            (account_id, start_at, start_at, end_at, end_at, safe_limit),
        ).fetchall()
    events = _dedupe_calendar_events([dict(row) for row in rows])
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="list_calendar_events", status="ok", account_id=account_id)
    return {
        "account_id": account_id,
        "start_at": start_at,
        "end_at": end_at,
        "limit": safe_limit,
        "events": events,
        "status": "ok",
    }


def _dedupe_calendar_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in rows:
        key = (
            str(row.get("provider_uid") or "").lower().strip(),
            str(row.get("title") or "").lower().strip(),
            str(row.get("starts_at") or "").strip(),
            str(row.get("ends_at") or "").strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result


def approve_draft(draft_id: int, approved_by: str = "admin", user: dict[str, Any] | None = None) -> dict[str, Any]:
    draft = get_draft(draft_id, user=user)
    with db() as conn:
        conn.execute(
            "UPDATE drafts SET status = 'approved', approved_at = CURRENT_TIMESTAMP, approved_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (approved_by, draft_id),
        )
    audit(
        actor_type="mcp_client" if user else "human",
        actor_id=approved_by,
        interface="mcp" if user else "http",
        action="draft_approve",
        status="ok",
        account_id=int(draft["account_id"]),
        target_resource=str(draft_id),
    )
    return get_draft(draft_id, user=user)


def reject_draft(draft_id: int, approved_by: str = "admin", user: dict[str, Any] | None = None) -> dict[str, Any]:
    draft = get_draft(draft_id, user=user)
    with db() as conn:
        conn.execute(
            "UPDATE drafts SET status = 'rejected', approved_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (approved_by, draft_id),
        )
    audit(
        actor_type="mcp_client" if user else "human",
        actor_id=approved_by,
        interface="mcp" if user else "http",
        action="draft_reject",
        status="ok",
        account_id=int(draft["account_id"]),
        target_resource=str(draft_id),
    )
    return get_draft(draft_id, user=user)


def delete_draft(draft_id: int, deleted_by: str = "mcp", user: dict[str, Any] | None = None) -> dict[str, Any]:
    draft = get_draft(draft_id, user=user)
    if draft["status"] == "sent":
        raise ValueError("sent drafts cannot be deleted")
    with db() as conn:
        conn.execute("DELETE FROM draft_attachments WHERE draft_id = ?", (draft_id,))
        conn.execute("DELETE FROM drafts WHERE id = ?", (draft_id,))
    audit(
        actor_type="mcp_client" if user else "human",
        actor_id=deleted_by,
        interface="mcp" if user else "http",
        action="draft_delete",
        status="ok",
        account_id=int(draft["account_id"]),
        target_resource=str(draft_id),
    )
    return {"deleted": True, "draft_id": draft_id, "previous_status": draft["status"]}


def _domain_allowed(account: dict[str, Any], recipients: list[str]) -> tuple[bool, str]:
    blocked = {d.strip().lower() for d in account["blocked_recipient_domains"].split(",") if d.strip()}
    allowed = {d.strip().lower() for d in account["allowed_recipient_domains"].split(",") if d.strip()}
    for recipient in recipients:
        domain = recipient.rsplit("@", 1)[-1].lower()
        if domain in blocked:
            return False, f"blocked recipient domain: {domain}"
        if allowed and domain not in allowed:
            return False, f"recipient domain not in allow list: {domain}"
    return True, "ok"


def _get_automation_consent(consent_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db() as conn:
        if user and not user.get("is_admin"):
            row = conn.execute(
                """
                SELECT c.*
                FROM automation_consents c
                JOIN accounts a ON a.id = c.account_id
                WHERE c.id = ? AND a.owner_user_id = ?
                """,
                (consent_id, user["id"]),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM automation_consents WHERE id = ?", (consent_id,)).fetchone()
    if not row:
        raise ValueError("automation consent not found")
    return dict(row)


def _split_csv(value: str) -> set[str]:
    return {item.strip().lower() for item in str(value or "").split(",") if item.strip()}


def _automation_consent_allowed(consent_id: int, account_id: int, recipients: list[str], user: dict[str, Any] | None = None) -> tuple[bool, str]:
    consent = _get_automation_consent(consent_id, user=user)
    if int(consent["account_id"]) != int(account_id):
        return False, "automation consent does not belong to draft account"
    if not int(consent["enabled"]):
        return False, "automation consent is disabled"
    expires_at = str(consent.get("expires_at") or "")
    if expires_at:
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires.astimezone(timezone.utc):
                return False, "automation consent has expired"
        except ValueError:
            return False, "automation consent has invalid expires_at"
    allowed_recipients = _split_csv(str(consent.get("allowed_recipients") or ""))
    allowed_domains = _split_csv(str(consent.get("allowed_domains") or ""))
    for recipient in recipients:
        normalized = recipient.lower()
        domain = normalized.rsplit("@", 1)[-1]
        if normalized not in allowed_recipients and domain not in allowed_domains:
            return False, f"recipient not covered by automation consent: {recipient}"
    max_sends = int(consent.get("max_sends_per_day") or 0)
    if max_sends > 0:
        with db() as conn:
            count = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM audit_log
                WHERE action = 'send_draft'
                  AND status = 'ok'
                  AND account_id = ?
                  AND policy_decision = ?
                  AND date(created_at) = date('now')
                """,
                (account_id, f"consent:{consent_id}"),
            ).fetchone()["count"]
        if int(count) >= max_sends:
            return False, "automation consent daily send limit reached"
    return True, "ok"


def _parse_recipients(*fields: str) -> list[str]:
    recipients: list[str] = []
    seen: set[str] = set()
    values = [field for field in fields if field and field.strip()]
    for _, addr in getaddresses(values):
        addr = addr.strip()
        if not addr or addr.lower() in seen:
            continue
        seen.add(addr.lower())
        recipients.append(addr)
    return recipients


def send_draft(draft_id: int, *, interactive_ok: bool = False, automation_consent_id: int | None = None, user: dict[str, Any] | None = None) -> dict[str, Any]:
    draft = get_draft(draft_id, user=user)
    account = get_account(int(draft["account_id"]), include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    if draft["status"] == "sent":
        raise ValueError("draft already sent")
    recipients = _parse_recipients(draft["to_recipients"], draft["cc_recipients"], draft["bcc_recipients"])
    if not recipients:
        raise ValueError("draft has no recipients")
    ok, reason = _domain_allowed(account, recipients)
    if not ok:
        raise ValueError(reason)
    mode = account["mcp_send_mode"]
    if mode == "disabled" or mode == "draft_only":
        raise ValueError("sending disabled by account policy")
    if mode in {"interactive_requires_ok", "interactive_or_approved_automation"} and not interactive_ok and automation_consent_id is None:
        return {
            "requires_ok": True,
            "draft_id": draft_id,
            "revision": draft["revision"],
            "from": account["email_address"],
            "to": draft["to_recipients"],
            "cc": draft["cc_recipients"],
            "bcc": draft["bcc_recipients"],
            "subject": draft["subject"],
            "body_text": draft["body_text"],
            "attachments": draft.get("attachments", []),
            "policy_decision": "interactive_ok_required",
            "instruction": "Show this payload to the user and call send_draft again with interactive_ok=true only after the user actively answers ok.",
        }
    if mode == "approved_automation_only" and automation_consent_id is None:
        raise ValueError("automation consent required")
    if automation_consent_id is not None:
        allowed_by_consent, consent_reason = _automation_consent_allowed(automation_consent_id, int(draft["account_id"]), recipients, user=user)
        if not allowed_by_consent:
            raise ValueError(consent_reason)
    if draft["status"] != "approved" and not interactive_ok and automation_consent_id is None:
        raise ValueError("draft is not approved")

    msg = EmailMessage()
    msg["From"] = f"{account['display_name']} <{account['email_address']}>" if account["display_name"] else account["email_address"]
    msg["To"] = draft["to_recipients"]
    if draft["cc_recipients"]:
        msg["Cc"] = draft["cc_recipients"]
    msg["Subject"] = draft["subject"]
    msg.set_content(draft["body_text"])
    for attachment in _draft_attachment_rows(draft_id):
        maintype, _, subtype = str(attachment["content_type"] or "application/octet-stream").partition("/")
        if not subtype:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(
            bytes(attachment["content"]),
            maintype=maintype,
            subtype=subtype,
            filename=str(attachment["filename"]),
        )

    if account["smtp_tls_mode"] == "ssl":
        client = smtplib.SMTP_SSL(account["smtp_host"], int(account["smtp_port"]), timeout=30)
    else:
        client = smtplib.SMTP(account["smtp_host"], int(account["smtp_port"]), timeout=30)
    try:
        client.ehlo()
        if account["smtp_tls_mode"] == "starttls":
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        client.login(account["smtp_username"], account["smtp_password"])
        client.send_message(msg, to_addrs=recipients)
        with db() as conn:
            conn.execute(
                "UPDATE drafts SET status = 'sent', sent_at = CURRENT_TIMESTAMP, send_error = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (draft_id,),
            )
        audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="send_draft", status="ok", account_id=int(draft["account_id"]), target_resource=str(draft_id), policy_decision="interactive_ok" if interactive_ok else f"consent:{automation_consent_id}")
        return {"ok": True, "draft_id": draft_id, "status": "sent"}
    except Exception as exc:
        with db() as conn:
            conn.execute("UPDATE drafts SET send_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (str(exc), draft_id))
        audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="send_draft", status="error", account_id=int(draft["account_id"]), target_resource=str(draft_id), error_message=str(exc))
        raise
    finally:
        try:
            client.quit()
        except Exception:
            pass
