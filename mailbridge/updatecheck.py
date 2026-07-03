from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__
from .config import settings


_CACHE: dict[str, Any] = {"checked_at_monotonic": 0.0, "result": None}
_CACHE_TTL_SECONDS = 300


def _short_sha(value: str) -> str:
    return value[:12] if value and value != "unknown" else value


def current_commit() -> str:
    if settings.git_commit:
        return settings.git_commit
    repo_root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return "unknown"
    return result.stdout.strip() or "unknown"


def _latest_github_commit() -> dict[str, Any]:
    url = f"{settings.github_api_url}/repos/{settings.update_check_repo}/commits/{settings.update_check_branch}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"Mailbridge-MCP/{__version__}",
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    commit = payload.get("commit") if isinstance(payload.get("commit"), dict) else {}
    author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
    return {
        "sha": str(payload.get("sha", "")),
        "url": str(payload.get("html_url", "")),
        "committed_at": str(author.get("date", "")),
        "message": str(commit.get("message", "")).splitlines()[0] if commit.get("message") else "",
    }


def check_for_updates(*, force: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    if not force and _CACHE["result"] and now - float(_CACHE["checked_at_monotonic"]) < _CACHE_TTL_SECONDS:
        return dict(_CACHE["result"])

    local_sha = current_commit()
    result: dict[str, Any] = {
        "status": "unknown",
        "message": "Update status could not be checked.",
        "update_available": None,
        "current_commit": local_sha,
        "current_commit_short": _short_sha(local_sha),
        "repo": settings.update_check_repo,
        "branch": settings.update_check_branch,
        "version": __version__,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }
    try:
        latest = _latest_github_commit()
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        result["error"] = str(exc)
    else:
        latest_sha = latest["sha"]
        result.update(
            {
                "latest_commit": latest_sha,
                "latest_commit_short": _short_sha(latest_sha),
                "latest_url": latest["url"],
                "latest_committed_at": latest["committed_at"],
                "latest_message": latest["message"],
            }
        )
        if local_sha == "unknown":
            result["message"] = "Current commit is unknown; set MAILBRIDGE_GIT_COMMIT for exact update checks."
        elif latest_sha and latest_sha != local_sha:
            result["status"] = "update_available"
            result["update_available"] = True
            result["message"] = "Hey, da gibt es was Neues."
        else:
            result["status"] = "current"
            result["update_available"] = False
            result["message"] = "Mailbridge is up to date."

    _CACHE["checked_at_monotonic"] = now
    _CACHE["result"] = dict(result)
    return result
