from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    master_key_file: Path
    public_url: str
    session_secret_file: Path
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    secure_cookies: bool
    auto_sync_interval_seconds: int
    auto_sync_limit: int

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.getenv("MAILBRIDGE_DATA_DIR", "./data")).resolve()
        public_url = os.getenv("MAILBRIDGE_PUBLIC_URL", "http://127.0.0.1:8080")
        allowed_hosts = tuple(
            item.strip()
            for item in os.getenv("MAILBRIDGE_ALLOWED_HOSTS", "127.0.0.1,127.0.0.1:8080,localhost,localhost:8080").split(",")
            if item.strip()
        )
        allowed_origins = tuple(
            item.strip()
            for item in os.getenv("MAILBRIDGE_ALLOWED_ORIGINS", public_url).split(",")
            if item.strip()
        )
        return cls(
            data_dir=data_dir,
            database_path=Path(os.getenv("MAILBRIDGE_DATABASE_PATH", str(data_dir / "mailbridge.db"))).resolve(),
            master_key_file=Path(os.getenv("MAILBRIDGE_MASTER_KEY_FILE", str(data_dir / "master.key"))).resolve(),
            session_secret_file=Path(os.getenv("MAILBRIDGE_SESSION_SECRET_FILE", str(data_dir / "session.key"))).resolve(),
            public_url=public_url,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            secure_cookies=os.getenv("MAILBRIDGE_SECURE_COOKIES", "false").lower() in {"1", "true", "yes", "on"},
            auto_sync_interval_seconds=max(30, int(os.getenv("MAILBRIDGE_AUTO_SYNC_INTERVAL_SECONDS", "300"))),
            auto_sync_limit=max(1, int(os.getenv("MAILBRIDGE_AUTO_SYNC_LIMIT", "50"))),
        )


def ensure_secret_file(path: Path, *, token_bytes: int = 32) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(token_bytes)
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)
    return value


settings = Settings.from_env()
