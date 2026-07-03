from __future__ import annotations

import threading
import time
from typing import Any

from .config import settings
from .db import db
from . import __version__
from . import mailops
from . import users


_stop_event = threading.Event()
_worker_thread: threading.Thread | None = None


def _row_to_job(row: Any) -> dict[str, Any]:
    return dict(row)


def enqueue_sync_job(
    account_id: int,
    *,
    limit: int = 50,
    mode: str = "manual_recent",
    user: dict[str, Any] | None = None,
    requested_by: str = "http",
) -> dict[str, Any]:
    account = mailops.get_account(account_id, user=user)
    if not account:
        raise ValueError("account not found")
    owner_user_id = int(account["owner_user_id"]) if account.get("owner_user_id") is not None else None
    safe_limit = max(1, min(int(limit), 100000))
    with db() as conn:
        existing = conn.execute(
            """
            SELECT *
            FROM sync_jobs
            WHERE account_id = ? AND status IN ('queued', 'running')
            ORDER BY id DESC
            LIMIT 1
            """,
            (account_id,),
        ).fetchone()
        if existing:
            return _row_to_job(existing) | {"already_running": True}
        cur = conn.execute(
            """
            INSERT INTO sync_jobs (owner_user_id, account_id, mode, status, requested_by, limit_count)
            VALUES (?, ?, ?, 'queued', ?, ?)
            """,
            (owner_user_id, account_id, mode, requested_by, safe_limit),
        )
        job_id = int(cur.lastrowid)
        row = conn.execute("SELECT * FROM sync_jobs WHERE id = ?", (job_id,)).fetchone()
    return _row_to_job(row) | {"already_running": False}


def get_sync_job(job_id: int, *, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db() as conn:
        if user and not user.get("is_admin"):
            row = conn.execute(
                "SELECT * FROM sync_jobs WHERE id = ? AND owner_user_id = ?",
                (int(job_id), int(user["id"])),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM sync_jobs WHERE id = ?", (int(job_id),)).fetchone()
    if not row:
        raise ValueError("sync job not found")
    return _row_to_job(row)


def list_sync_jobs(
    *,
    user: dict[str, Any] | None = None,
    account_id: int | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 100))
    params: list[Any] = []
    where: list[str] = []
    if user and not user.get("is_admin"):
        where.append("owner_user_id = ?")
        params.append(int(user["id"]))
    if account_id is not None:
        where.append("account_id = ?")
        params.append(int(account_id))
    sql = "SELECT * FROM sync_jobs"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(safe_limit)
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_job(row) for row in rows]


def cancel_sync_job(job_id: int, *, user: dict[str, Any] | None = None) -> dict[str, Any]:
    job = get_sync_job(job_id, user=user)
    if job["status"] == "queued":
        with db() as conn:
            conn.execute(
                """
                UPDATE sync_jobs
                SET status = 'cancelled', cancel_requested = 1, finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (int(job_id),),
            )
    elif job["status"] == "running":
        with db() as conn:
            conn.execute(
                "UPDATE sync_jobs SET cancel_requested = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (int(job_id),),
            )
    return get_sync_job(job_id, user=user)


def _claim_next_job() -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM sync_jobs
            WHERE status = 'queued'
            ORDER BY id
            LIMIT 1
            """
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """
            UPDATE sync_jobs
            SET status = 'running', started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (int(row["id"]),),
        )
        claimed = conn.execute("SELECT * FROM sync_jobs WHERE id = ?", (int(row["id"]),)).fetchone()
    return _row_to_job(claimed)


def _progress(job_id: int, payload: dict[str, Any]) -> None:
    with db() as conn:
        conn.execute(
            """
            UPDATE sync_jobs
            SET current_folder = ?, processed = ?, indexed = ?, updated_flags = ?,
                total_estimate = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                str(payload.get("folder") or ""),
                int(payload.get("processed") or 0),
                int(payload.get("indexed") or 0),
                int(payload.get("updated_flags") or 0),
                int(payload.get("total_estimate") or 0),
                job_id,
            ),
        )


def _job_cancelled(job_id: int) -> bool:
    with db() as conn:
        row = conn.execute("SELECT cancel_requested FROM sync_jobs WHERE id = ?", (job_id,)).fetchone()
    return bool(row and row["cancel_requested"])


def _run_job(job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    account_id = int(job["account_id"])
    owner = users.get_user(int(job["owner_user_id"])) if job.get("owner_user_id") else None

    def progress(payload: dict[str, Any]) -> None:
        _progress(job_id, payload)
        if _job_cancelled(job_id):
            raise RuntimeError("sync job cancelled")

    try:
        result = mailops.sync_account(
            account_id,
            limit=int(job["limit_count"]),
            user=owner,
            progress=progress,
            reconcile_flags=True,
            flag_reconcile_limit=None,
            audit_actor_type="system",
            audit_actor_id="mailbridge-sync-worker",
            audit_interface="system",
            audit_token_id=f"system:{job['requested_by'] or 'worker'}",
            audit_client_name="mailbridge-sync-worker",
            audit_client_version=__version__,
            audit_remote_addr="local",
            audit_user_agent=f"Mailbridge/{__version__} background-sync",
            audit_intent=str(job["mode"] or "sync_account"),
            audit_target_resource=f"sync_job:{job_id}",
        )
        with db() as conn:
            conn.execute(
                """
                UPDATE sync_jobs
                SET status = 'done', processed = ?, indexed = ?, updated_flags = ?,
                    finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    int(result.get("indexed") or 0),
                    int(result.get("indexed") or 0),
                    int(result.get("updated_flags") or 0),
                    job_id,
                ),
            )
    except Exception as exc:
        status = "cancelled" if "cancelled" in str(exc).lower() else "failed"
        with db() as conn:
            conn.execute(
                """
                UPDATE sync_jobs
                SET status = ?, error_message = ?, finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status, str(exc), job_id),
            )


def _enqueue_auto_jobs() -> None:
    with db() as conn:
        rows = conn.execute("SELECT id FROM accounts WHERE enabled = 1 ORDER BY id").fetchall()
    for row in rows:
        try:
            enqueue_sync_job(
                int(row["id"]),
                limit=settings.auto_sync_limit,
                mode="auto_recent",
                user=None,
                requested_by="auto",
            )
        except Exception:
            continue


def _worker_loop() -> None:
    with db() as conn:
        conn.execute(
            """
            UPDATE sync_jobs
            SET status = 'failed', error_message = 'worker restarted while job was running',
                finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE status = 'running'
            """
        )
    last_auto = 0.0
    while not _stop_event.is_set():
        now = time.monotonic()
        if now - last_auto >= settings.auto_sync_interval_seconds:
            _enqueue_auto_jobs()
            last_auto = now
        job = _claim_next_job()
        if job:
            _run_job(job)
            continue
        _stop_event.wait(1.0)


def start_worker() -> None:
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return
    _stop_event.clear()
    _worker_thread = threading.Thread(target=_worker_loop, name="mailbridge-sync-worker", daemon=True)
    _worker_thread.start()


def stop_worker() -> None:
    _stop_event.set()
    if _worker_thread and _worker_thread.is_alive():
        _worker_thread.join(timeout=5)
