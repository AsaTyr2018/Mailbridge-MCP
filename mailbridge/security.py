from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.fernet import Fernet

from .config import ensure_secret_file, settings


def _fernet_key_from_secret(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class SecretBox:
    def __init__(self, key_file: Path):
        raw = ensure_secret_file(key_file, token_bytes=48)
        self._fernet = Fernet(_fernet_key_from_secret(raw))

    def encrypt(self, value: str) -> str:
        if value == "":
            return ""
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str | None) -> str:
        if not value:
            return ""
        return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")


secret_box = SecretBox(settings.master_key_file)

