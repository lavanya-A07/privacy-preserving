"""Central configuration loaded from environment variables.

NEVER hardcode secrets here. All sensitive material is loaded from .env.
"""
from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root (one level above backend/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _require(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(
            f"Required environment variable '{name}' is missing. "
            f"Copy .env.example to .env and configure it."
        )
    return value


def _decode_key(name: str, *, required: bool = True) -> bytes | None:
    raw = os.getenv(name, "")
    if not raw:
        if required:
            raise RuntimeError(
                f"Environment variable '{name}' is missing. "
                f"Generate one with: "
                f"python -c \"import os,base64;print(base64.b64encode(os.urandom(32)).decode())\""
            )
        return None
    try:
        key = base64.b64decode(raw)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"'{name}' is not valid base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"'{name}' must decode to exactly 32 bytes (got {len(key)})")
    return key


class Settings:
    """Runtime settings container."""

    def __init__(self) -> None:
        # Non-secret
        self.mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        self.database_name: str = os.getenv("DATABASE_NAME", "flyyy_privacy_platform")

        self.smtp_host: str = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port: int = int(os.getenv("SMTP_PORT", "1025"))
        self.smtp_from: str = os.getenv("SMTP_FROM", "privacy-shield@local")

        self.app_env: str = os.getenv("APP_ENV", "development")
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO")

        # Data paths
        self.data_dir: Path = PROJECT_ROOT / "data"
        self.customers_csv: Path = self.data_dir / "customers.csv"

        # Secrets — lazy-loaded so the app can boot without them in dev
        self._vault_key_b64: str | None = os.getenv("VAULT_AES_KEY_BASE64")
        self._fpe_key_b64: str | None = os.getenv("FPE_KEY_BASE64")
        self._token_secret_b64: str | None = os.getenv("TOKEN_SECRET_BASE64")

    # ----- lazy secret accessors -----
    @property
    def vault_key(self) -> bytes:
        if not self._vault_key_b64:
            raise RuntimeError("VAULT_AES_KEY_BASE64 is not set. See .env.example")
        return _decode_key_from_b64(self._vault_key_b64, "VAULT_AES_KEY_BASE64")

    @property
    def fpe_key(self) -> bytes:
        if not self._fpe_key_b64:
            raise RuntimeError("FPE_KEY_BASE64 is not set. See .env.example")
        return _decode_key_from_b64(self._fpe_key_b64, "FPE_KEY_BASE64")

    @property
    def token_secret(self) -> bytes:
        if not self._token_secret_b64:
            raise RuntimeError("TOKEN_SECRET_BASE64 is not set. See .env.example")
        return _decode_key_from_b64(self._token_secret_b64, "TOKEN_SECRET_BASE64")

    @property
    def is_dev(self) -> bool:
        return self.app_env.lower() in ("dev", "development", "local")


def _decode_key_from_b64(b64: str, name: str) -> bytes:
    try:
        key = base64.b64decode(b64)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"'{name}' is not valid base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"'{name}' must decode to 32 bytes (got {len(key)})")
    return key


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
