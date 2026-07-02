from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from .db import db, generate_token_id
from .security import secret_box
from . import users


DEFAULT_PERMISSIONS = ["list_accounts", "sync", "search", "read", "move", "trash", "mark_read"]


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_permissions(value: str) -> set[str]:
    try:
        data = json.loads(value or "[]")
    except json.JSONDecodeError:
        return set()
    return {str(item) for item in data if str(item).strip()}


def _row_to_token(row: Any, account_ids: list[int] | None = None) -> dict[str, Any]:
    result = dict(row)
    result["enabled"] = bool(result["enabled"])
    result["permissions"] = sorted(_load_permissions(result.get("permissions", "[]")))
    result["allowed_account_ids"] = account_ids if account_ids is not None else []
    result.pop("token_hash", None)
    result.pop("token_secret", None)
    return result


def _resolve_owned_account_ids(owner_user_id: int, account_names: list[str] | None, account_ids: list[int] | None) -> list[int]:
    ids: set[int] = set()
    with db() as conn:
        for account_id in account_ids or []:
            row = conn.execute(
                "SELECT id FROM accounts WHERE id = ? AND owner_user_id = ?",
                (int(account_id), owner_user_id),
            ).fetchone()
            if not row:
                raise ValueError(f"account id {account_id} is not owned by this user")
            ids.add(int(row["id"]))
        for name in account_names or []:
            row = conn.execute(
                "SELECT id FROM accounts WHERE name = ? AND owner_user_id = ?",
                (name.strip(), owner_user_id),
            ).fetchone()
            if not row:
                raise ValueError(f"account '{name}' is not owned by this user")
            ids.add(int(row["id"]))
    return sorted(ids)


def create_automation_token(
    user: dict[str, Any],
    *,
    name: str,
    account_names: list[str] | None = None,
    account_ids: list[int] | None = None,
    permissions: list[str] | None = None,
) -> tuple[dict[str, Any], str]:
    if not user:
        raise ValueError("user required")
    clean_name = name.strip() or "MASH automation"
    owner_user_id = int(user["id"])
    allowed_account_ids = _resolve_owned_account_ids(owner_user_id, account_names, account_ids)
    if not allowed_account_ids:
        raise ValueError("at least one owned account must be allowed")
    clean_permissions = sorted({item.strip() for item in (permissions or DEFAULT_PERMISSIONS) if item.strip()})
    token = secrets.token_urlsafe(40)
    token_id = generate_token_id()
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO automation_tokens (
                owner_user_id, name, token_hash, token_secret, token_id,
                token_preview, permissions, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                owner_user_id,
                clean_name,
                _hash_secret(token),
                secret_box.encrypt(token),
                token_id,
                users.token_preview(token),
                json.dumps(clean_permissions),
            ),
        )
        automation_token_id = int(cur.lastrowid)
        conn.executemany(
            "INSERT INTO automation_token_accounts (token_id, account_id) VALUES (?, ?)",
            [(automation_token_id, account_id) for account_id in allowed_account_ids],
        )
    return get_automation_token(automation_token_id, user=user), token


def get_automation_token(token_pk: int, user: dict[str, Any]) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute(
            """
            SELECT * FROM automation_tokens
            WHERE id = ? AND owner_user_id = ?
            """,
            (token_pk, int(user["id"])),
        ).fetchone()
        if not row:
            raise ValueError("automation token not found")
        account_rows = conn.execute(
            "SELECT account_id FROM automation_token_accounts WHERE token_id = ? ORDER BY account_id",
            (token_pk,),
        ).fetchall()
    return _row_to_token(row, [int(item["account_id"]) for item in account_rows])


def list_automation_tokens(user: dict[str, Any]) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM automation_tokens WHERE owner_user_id = ? ORDER BY id DESC",
            (int(user["id"]),),
        ).fetchall()
        account_rows = conn.execute(
            """
            SELECT ata.token_id, ata.account_id
            FROM automation_token_accounts ata
            JOIN automation_tokens at ON at.id = ata.token_id
            WHERE at.owner_user_id = ?
            ORDER BY ata.token_id, ata.account_id
            """,
            (int(user["id"]),),
        ).fetchall()
    account_map: dict[int, list[int]] = {}
    for row in account_rows:
        account_map.setdefault(int(row["token_id"]), []).append(int(row["account_id"]))
    return [_row_to_token(row, account_map.get(int(row["id"]), [])) for row in rows]


def revoke_automation_token(token_pk: int, user: dict[str, Any]) -> dict[str, Any]:
    with db() as conn:
        cur = conn.execute(
            "UPDATE automation_tokens SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND owner_user_id = ?",
            (token_pk, int(user["id"])),
        )
    if cur.rowcount == 0:
        raise ValueError("automation token not found")
    return {"revoked": True, "id": token_pk}


def find_user_by_automation_token(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not token:
        return None
    token_hash = _hash_secret(token)
    with db() as conn:
        row = conn.execute(
            """
            SELECT * FROM automation_tokens
            WHERE token_hash = ? AND enabled = 1
            """,
            (token_hash,),
        ).fetchone()
        if not row:
            return None
        account_rows = conn.execute(
            "SELECT account_id FROM automation_token_accounts WHERE token_id = ? ORDER BY account_id",
            (int(row["id"]),),
        ).fetchall()
    user = users.get_user(int(row["owner_user_id"]))
    if not user or not user["is_active"]:
        return None
    return user, _row_to_token(row, [int(item["account_id"]) for item in account_rows])


def token_allows(token: dict[str, Any] | None, permission: str, account_id: int | None = None) -> bool:
    if not token:
        return True
    if permission not in set(token.get("permissions") or []):
        return False
    if account_id is not None and int(account_id) not in set(token.get("allowed_account_ids") or []):
        return False
    return True


def require_allowed(token: dict[str, Any] | None, permission: str, account_id: int | None = None) -> None:
    if not token_allows(token, permission, account_id):
        raise PermissionError(f"automation token does not allow {permission} for this account")
