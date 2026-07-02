from __future__ import annotations

from contextvars import ContextVar
from typing import Any


_mcp_user: ContextVar[dict[str, Any] | None] = ContextVar("mcp_user", default=None)
_mcp_request: ContextVar[dict[str, Any]] = ContextVar("mcp_request", default={})


def set_mcp_user(user: dict[str, Any] | None):
    return _mcp_user.set(user)


def reset_mcp_user(token) -> None:
    _mcp_user.reset(token)


def get_mcp_user() -> dict[str, Any] | None:
    return _mcp_user.get()


def set_mcp_request(meta: dict[str, Any]):
    return _mcp_request.set(meta)


def reset_mcp_request(token) -> None:
    _mcp_request.reset(token)


def get_mcp_request() -> dict[str, Any]:
    return _mcp_request.get()
