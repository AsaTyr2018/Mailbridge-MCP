from __future__ import annotations

import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import settings


def generate_token_id() -> str:
    return f"tkn_{secrets.token_hex(3).upper()}"


def connect(path: Path | None = None) -> sqlite3.Connection:
    db_path = path or settings.database_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def migrate() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                email_address TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                imap_host TEXT NOT NULL,
                imap_port INTEGER NOT NULL DEFAULT 993,
                imap_tls_mode TEXT NOT NULL DEFAULT 'ssl',
                imap_username TEXT NOT NULL,
                imap_secret TEXT NOT NULL,
                smtp_host TEXT NOT NULL,
                smtp_port INTEGER NOT NULL DEFAULT 587,
                smtp_tls_mode TEXT NOT NULL DEFAULT 'starttls',
                smtp_username TEXT NOT NULL,
                smtp_secret TEXT NOT NULL,
                sync_folders TEXT NOT NULL DEFAULT 'INBOX',
                sync_calendar_enabled INTEGER NOT NULL DEFAULT 0,
                sync_contacts_enabled INTEGER NOT NULL DEFAULT 0,
                mail_index_mode TEXT NOT NULL DEFAULT 'metadata_only',
                sync_interval_seconds INTEGER NOT NULL DEFAULT 900,
                mcp_read_enabled INTEGER NOT NULL DEFAULT 1,
                mcp_search_enabled INTEGER NOT NULL DEFAULT 1,
                mcp_calendar_enabled INTEGER NOT NULL DEFAULT 0,
                mcp_contacts_enabled INTEGER NOT NULL DEFAULT 0,
                mcp_draft_enabled INTEGER NOT NULL DEFAULT 1,
                mcp_send_mode TEXT NOT NULL DEFAULT 'interactive_requires_ok',
                max_search_results INTEGER NOT NULL DEFAULT 20,
                max_message_bytes INTEGER NOT NULL DEFAULT 20000,
                allowed_recipient_domains TEXT NOT NULL DEFAULT '',
                blocked_recipient_domains TEXT NOT NULL DEFAULT '',
                last_sync_at TEXT,
                last_sync_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                folder TEXT NOT NULL,
                imap_uid TEXT NOT NULL,
                rfc822_message_id TEXT,
                thread_id TEXT,
                subject TEXT NOT NULL DEFAULT '',
                sender TEXT NOT NULL DEFAULT '',
                recipients TEXT NOT NULL DEFAULT '',
                cc TEXT NOT NULL DEFAULT '',
                bcc TEXT NOT NULL DEFAULT '',
                delivered_to TEXT NOT NULL DEFAULT '',
                sent_at TEXT,
                snippet TEXT NOT NULL DEFAULT '',
                text_body TEXT NOT NULL DEFAULT '',
                attachment_names TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                headers_json TEXT NOT NULL DEFAULT '{}',
                flags TEXT NOT NULL DEFAULT '',
                indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(account_id, folder, imap_uid)
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                subject,
                sender,
                recipients,
                snippet,
                text_body,
                content='messages',
                content_rowid='id'
            );

            CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(rowid, subject, sender, recipients, snippet, text_body)
                VALUES (new.id, new.subject, new.sender, new.recipients, new.snippet, new.text_body);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, subject, sender, recipients, snippet, text_body)
                VALUES ('delete', old.id, old.subject, old.sender, old.recipients, old.snippet, old.text_body);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, subject, sender, recipients, snippet, text_body)
                VALUES ('delete', old.id, old.subject, old.sender, old.recipients, old.snippet, old.text_body);
                INSERT INTO messages_fts(rowid, subject, sender, recipients, snippet, text_body)
                VALUES (new.id, new.subject, new.sender, new.recipients, new.snippet, new.text_body);
            END;

            CREATE TABLE IF NOT EXISTS drafts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                to_recipients TEXT NOT NULL,
                cc_recipients TEXT NOT NULL DEFAULT '',
                bcc_recipients TEXT NOT NULL DEFAULT '',
                subject TEXT NOT NULL,
                body_text TEXT NOT NULL,
                in_reply_to_message_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending_approval',
                revision INTEGER NOT NULL DEFAULT 1,
                approved_at TEXT,
                approved_by TEXT,
                sent_at TEXT,
                send_error TEXT,
                created_by TEXT NOT NULL DEFAULT 'mcp',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS automation_consents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                allowed_recipients TEXT NOT NULL DEFAULT '',
                allowed_domains TEXT NOT NULL DEFAULT '',
                max_sends_per_day INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sync_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                provider TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                base_url TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                secret TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                last_sync_at TEXT,
                last_sync_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                profile_id INTEGER REFERENCES sync_profiles(id) ON DELETE SET NULL,
                provider_uid TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                emails TEXT NOT NULL DEFAULT '',
                phones TEXT NOT NULL DEFAULT '',
                company TEXT NOT NULL DEFAULT '',
                raw_vcard TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(account_id, profile_id, provider_uid)
            );

            CREATE TABLE IF NOT EXISTS calendar_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                profile_id INTEGER REFERENCES sync_profiles(id) ON DELETE SET NULL,
                provider_uid TEXT NOT NULL,
                calendar_name TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                starts_at TEXT NOT NULL DEFAULT '',
                ends_at TEXT NOT NULL DEFAULT '',
                attendees TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                raw_ics TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(account_id, profile_id, provider_uid)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                account_id INTEGER,
                action TEXT NOT NULL,
                target_resource TEXT,
                policy_decision TEXT NOT NULL DEFAULT '',
                token_id TEXT NOT NULL DEFAULT '',
                client_name TEXT NOT NULL DEFAULT '',
                client_version TEXT NOT NULL DEFAULT '',
                mcp_version TEXT NOT NULL DEFAULT '',
                latency_ms INTEGER,
                remote_addr TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                intent TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                error_message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                mcp_token_hash TEXT NOT NULL UNIQUE,
                mcp_token_secret TEXT NOT NULL DEFAULT '',
                mcp_token_id TEXT NOT NULL DEFAULT '',
                mcp_token_preview TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO app_settings (key, value)
            VALUES ('registration_enabled', 'true');

            """
        )
        account_columns = {row["name"] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()}
        if "owner_user_id" not in account_columns:
            conn.execute("ALTER TABLE accounts ADD COLUMN owner_user_id INTEGER")
        if "mail_index_mode" not in account_columns:
            conn.execute("ALTER TABLE accounts ADD COLUMN mail_index_mode TEXT NOT NULL DEFAULT 'full_text'")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS accounts_owner_name_idx ON accounts(owner_user_id, name)")
        existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        for column_name, column_def in {
            "bcc": "TEXT NOT NULL DEFAULT ''",
            "delivered_to": "TEXT NOT NULL DEFAULT ''",
            "attachment_names": "TEXT NOT NULL DEFAULT ''",
            "size_bytes": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            if column_name not in existing_columns:
                conn.execute(f"ALTER TABLE messages ADD COLUMN {column_name} {column_def}")
        user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "mcp_token_secret" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN mcp_token_secret TEXT NOT NULL DEFAULT ''")
        if "mcp_token_id" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN mcp_token_id TEXT NOT NULL DEFAULT ''")
        for row in conn.execute("SELECT id FROM users WHERE mcp_token_id = '' OR mcp_token_id IS NULL").fetchall():
            conn.execute("UPDATE users SET mcp_token_id = ? WHERE id = ?", (generate_token_id(), row["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_mcp_token_id_idx ON users(mcp_token_id)")
        audit_columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        for column_name, column_def in {
            "token_id": "TEXT NOT NULL DEFAULT ''",
            "client_name": "TEXT NOT NULL DEFAULT ''",
            "client_version": "TEXT NOT NULL DEFAULT ''",
            "mcp_version": "TEXT NOT NULL DEFAULT ''",
            "latency_ms": "INTEGER",
            "remote_addr": "TEXT NOT NULL DEFAULT ''",
            "user_agent": "TEXT NOT NULL DEFAULT ''",
            "intent": "TEXT NOT NULL DEFAULT ''",
        }.items():
            if column_name not in audit_columns:
                conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column_name} {column_def}")
        conn.execute("CREATE INDEX IF NOT EXISTS sync_profiles_account_idx ON sync_profiles(account_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS contacts_account_name_idx ON contacts(account_id, display_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS calendar_events_account_time_idx ON calendar_events(account_id, starts_at, ends_at)")
