from __future__ import annotations

from .db import db


def audit(
    *,
    actor_type: str,
    actor_id: str,
    interface: str,
    action: str,
    status: str,
    account_id: int | None = None,
    target_resource: str | None = None,
    policy_decision: str = "",
    error_message: str = "",
) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit_log (
                actor_type, actor_id, interface, account_id, action,
                target_resource, policy_decision, status, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor_type,
                actor_id,
                interface,
                account_id,
                action,
                target_resource,
                policy_decision,
                status,
                error_message,
            ),
        )

