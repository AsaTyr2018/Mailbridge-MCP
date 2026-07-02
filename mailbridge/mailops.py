from __future__ import annotations

import imaplib
import json
import re
import smtplib
import ssl
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

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
                sync_folders, sync_calendar_enabled, sync_contacts_enabled,
                mcp_read_enabled, mcp_search_enabled, mcp_calendar_enabled,
                mcp_contacts_enabled, mcp_draft_enabled, mcp_send_mode,
                max_search_results, max_message_bytes,
                allowed_recipient_domains, blocked_recipient_domains
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                sync_folders = ?, sync_calendar_enabled = ?, sync_contacts_enabled = ?,
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
    audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="account_update", status="ok", account_id=account_id)


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


def sync_account(account_id: int, *, limit: int = 100, user: dict[str, Any] | None = None) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    if not account["enabled"]:
        raise ValueError("account disabled")
    indexed = 0
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
            for uid in uids:
                status, msg_data = client.uid("fetch", uid, "(RFC822 FLAGS)")
                if status != "OK" or not msg_data:
                    continue
                raw = None
                flags_text = ""
                for item in msg_data:
                    if isinstance(item, tuple):
                        try:
                            flags_text = item[0].decode("utf-8", errors="ignore")
                        except Exception:
                            flags_text = str(item[0])
                        raw = item[1]
                        break
                if not raw:
                    continue
                msg = BytesParser(policy=policy.default).parsebytes(raw)
                text_body = _message_text(msg)
                subject = str(msg.get("subject", ""))
                sender = str(msg.get("from", ""))
                recipients = _address_header(msg, "to")
                cc = _address_header(msg, "cc")
                bcc = _address_header(msg, "bcc")
                delivered_to = _address_header(msg, "delivered-to")
                attachment_names = _attachment_names(msg)
                sent_at = ""
                if msg.get("date"):
                    try:
                        sent_at = parsedate_to_datetime(str(msg.get("date"))).isoformat()
                    except Exception:
                        sent_at = str(msg.get("date"))
                snippet = " ".join(text_body.split())[:500]
                headers = {k: str(v) for k, v in msg.items()}
                with db() as conn:
                    conn.execute(
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
                            len(raw),
                            json.dumps(headers),
                            flags_text,
                        ),
                    )
                indexed += 1
        with db() as conn:
            conn.execute(
                "UPDATE accounts SET last_sync_at = CURRENT_TIMESTAMP, last_sync_error = NULL WHERE id = ?",
                (account_id,),
            )
        audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="sync_account", status="ok", account_id=account_id)
        return {"ok": True, "indexed": indexed}
    except Exception as exc:
        with db() as conn:
            conn.execute(
                "UPDATE accounts SET last_sync_error = ? WHERE id = ?",
                (str(exc), account_id),
            )
        audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="sync_account", status="error", account_id=account_id, error_message=str(exc))
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
        lambda match: where.append("m.flags NOT LIKE '%\\\\Seen%'")
        if match.group(1).lower() == "unread"
        else where.append("m.flags LIKE '%\\\\Seen%'")
        if match.group(1).lower() == "read"
        else where.append("m.flags LIKE '%\\\\Flagged%'")
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
    encoded = body.encode("utf-8")
    if len(encoded) > max_bytes:
        result["text_body"] = encoded[:max_bytes].decode("utf-8", errors="ignore")
        result["truncated"] = True
    else:
        result["truncated"] = False
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="get_message", status="ok", account_id=int(row["account_id"]), target_resource=str(message_id))
    return result


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
    return dict(row)


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


def list_mail_history(user: dict[str, Any] | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 200))
    with db() as conn:
        if user and not user.get("is_admin"):
            rows = conn.execute(
                """
                SELECT m.id, m.account_id, a.name AS account_name, a.email_address AS account_email,
                       m.folder, m.subject, m.sender, m.recipients, m.sent_at,
                       m.attachment_names, m.size_bytes, m.indexed_at
                FROM messages m
                JOIN accounts a ON a.id = m.account_id
                WHERE a.owner_user_id = ?
                ORDER BY COALESCE(NULLIF(m.sent_at, ''), m.indexed_at) DESC, m.id DESC
                LIMIT ?
                """,
                (user["id"], safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT m.id, m.account_id, a.name AS account_name, a.email_address AS account_email,
                       m.folder, m.subject, m.sender, m.recipients, m.sent_at,
                       m.attachment_names, m.size_bytes, m.indexed_at
                FROM messages m
                JOIN accounts a ON a.id = m.account_id
                ORDER BY COALESCE(NULLIF(m.sent_at, ''), m.indexed_at) DESC, m.id DESC
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
                WHERE al.interface = 'mcp'
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
                WHERE al.interface = 'mcp'
                ORDER BY al.created_at DESC, al.id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def bearer_security_summary(user: dict[str, Any] | None = None) -> dict[str, Any]:
    if not user:
        return {}
    rows = list_security_audit_events(user=user, limit=20)
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


def approve_draft(draft_id: int, approved_by: str = "admin", user: dict[str, Any] | None = None) -> None:
    get_draft(draft_id, user=user)
    with db() as conn:
        conn.execute(
            "UPDATE drafts SET status = 'approved', approved_at = CURRENT_TIMESTAMP, approved_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (approved_by, draft_id),
        )
    audit(actor_type="human", actor_id=approved_by, interface="http", action="draft_approve", status="ok", target_resource=str(draft_id))


def reject_draft(draft_id: int, approved_by: str = "admin", user: dict[str, Any] | None = None) -> None:
    get_draft(draft_id, user=user)
    with db() as conn:
        conn.execute(
            "UPDATE drafts SET status = 'rejected', approved_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (approved_by, draft_id),
        )
    audit(actor_type="human", actor_id=approved_by, interface="http", action="draft_reject", status="ok", target_resource=str(draft_id))


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
            "policy_decision": "interactive_ok_required",
            "instruction": "Show this payload to the user and call send_draft again with interactive_ok=true only after the user actively answers ok.",
        }
    if mode == "approved_automation_only" and automation_consent_id is None:
        raise ValueError("automation consent required")
    if draft["status"] != "approved" and not interactive_ok and automation_consent_id is None:
        raise ValueError("draft is not approved")

    msg = EmailMessage()
    msg["From"] = f"{account['display_name']} <{account['email_address']}>" if account["display_name"] else account["email_address"]
    msg["To"] = draft["to_recipients"]
    if draft["cc_recipients"]:
        msg["Cc"] = draft["cc_recipients"]
    msg["Subject"] = draft["subject"]
    msg.set_content(draft["body_text"])

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
