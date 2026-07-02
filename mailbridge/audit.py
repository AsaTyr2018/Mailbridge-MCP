from __future__ import annotations

import time

from .auth_context import get_mcp_request
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
    token_id: str = "",
    client_name: str = "",
    client_version: str = "",
    mcp_version: str = "",
    latency_ms: int | None = None,
    remote_addr: str = "",
    user_agent: str = "",
    intent: str = "",
    error_message: str = "",
) -> None:
    request_meta = get_mcp_request() if interface == "mcp" else {}
    started_at = request_meta.get("started_at")
    if latency_ms is None and isinstance(started_at, float):
        latency_ms = max(0, int((time.perf_counter() - started_at) * 1000))
    token_id = token_id or str(request_meta.get("token_id", ""))
    client_name = client_name or str(request_meta.get("client_name", ""))
    client_version = client_version or str(request_meta.get("client_version", ""))
    mcp_version = mcp_version or str(request_meta.get("mcp_version", ""))
    remote_addr = remote_addr or str(request_meta.get("remote_addr", ""))
    user_agent = user_agent or str(request_meta.get("user_agent", ""))
    intent = intent or action or str(request_meta.get("intent", ""))
    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit_log (
                actor_type, actor_id, interface, account_id, action,
                target_resource, policy_decision, token_id, client_name,
                client_version, mcp_version, latency_ms, remote_addr,
                user_agent, intent, status, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor_type,
                actor_id,
                interface,
                account_id,
                action,
                target_resource,
                policy_decision,
                token_id,
                client_name,
                client_version,
                mcp_version,
                latency_ms,
                remote_addr,
                user_agent,
                intent,
                status,
                error_message,
            ),
        )
