from __future__ import annotations

from contextvars import ContextVar
from typing import Any


_mcp_user: ContextVar[dict[str, Any] | None] = ContextVar("mcp_user", default=None)


def set_mcp_user(user: dict[str, Any] | None):
    return _mcp_user.set(user)


def reset_mcp_user(token) -> None:
    _mcp_user.reset(token)


def get_mcp_user() -> dict[str, Any] | None:
    return _mcp_user.get()

