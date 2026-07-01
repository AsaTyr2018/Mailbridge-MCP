from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any

from .config import ensure_secret_file, settings
from .db import db
from .security import secret_box


SESSION_COOKIE = "mailbridge_session"
CSRF_COOKIE = "mailbridge_csrf"


def _session_secret() -> str:
    return ensure_secret_file(settings.session_secret_file, token_bytes=48)


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_urlsafe(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 260_000)
    return f"pbkdf2_sha256${salt}${base64.b64encode(digest).decode('ascii')}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, encoded = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    expected = hash_password(password, salt)
    return hmac.compare_digest(expected, stored)


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def token_preview(token: str) -> str:
    return f"{token[:6]}...{token[-6:]}"


def user_count() -> int:
    with db() as conn:
        return int(conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"])


def registration_enabled() -> bool:
    with db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = 'registration_enabled'").fetchone()
    return not row or row["value"] == "true"


def set_registration_enabled(enabled: bool) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES ('registration_enabled', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("true" if enabled else "false",),
        )


def create_user(username: str, password: str) -> tuple[dict[str, Any], str]:
    username = username.strip()
    if not username:
        raise ValueError("username is required")
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    is_admin = user_count() == 0
    token = generate_token()
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO users (
                username, password_hash, is_admin, is_active,
                mcp_token_hash, mcp_token_secret, mcp_token_preview
            ) VALUES (?, ?, ?, 1, ?, ?, ?)
            """,
            (username, hash_password(password), int(is_admin), _hash_secret(token), secret_box.encrypt(token), token_preview(token)),
        )
        user_id = int(cur.lastrowid)
    return get_user(user_id), token


def get_user(user_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT id, username, is_admin, is_active, mcp_token_secret, mcp_token_preview, created_at, updated_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    result["mcp_token"] = secret_box.decrypt(result.pop("mcp_token_secret"))
    return result


def get_user_for_login(username: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, is_admin, is_active, mcp_token_preview, created_at, updated_at FROM users ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    user = get_user_for_login(username)
    if not user or not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return get_user(int(user["id"]))


def make_session_token(user_id: int) -> str:
    nonce = secrets.token_urlsafe(24)
    issued_at = str(int(time.time()))
    payload = f"{user_id}:{issued_at}:{nonce}"
    signature = hmac.new(_session_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def user_id_from_session(value: str | None) -> int | None:
    if not value:
        return None
    parts = value.split(":")
    if len(parts) != 4:
        return None
    user_id, issued_at, nonce, signature = parts
    payload = f"{user_id}:{issued_at}:{nonce}"
    expected = hmac.new(_session_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        return int(user_id)
    except ValueError:
        return None


def make_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def find_user_by_mcp_token(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    token_hash = _hash_secret(token)
    with db() as conn:
        row = conn.execute(
            "SELECT id, username, is_admin, is_active, mcp_token_preview FROM users WHERE mcp_token_hash = ?",
            (token_hash,),
        ).fetchone()
    if not row or not row["is_active"]:
        return None
    return dict(row)


def revoke_user_token(user_id: int) -> str:
    token = generate_token()
    with db() as conn:
        conn.execute(
            "UPDATE users SET mcp_token_hash = ?, mcp_token_secret = ?, mcp_token_preview = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (_hash_secret(token), secret_box.encrypt(token), token_preview(token), user_id),
        )
    return token


def set_user_active(user_id: int, active: bool) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (int(active), user_id),
        )


def delete_user(user_id: int) -> None:
    with db() as conn:
        conn.execute("UPDATE accounts SET owner_user_id = NULL WHERE owner_user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
