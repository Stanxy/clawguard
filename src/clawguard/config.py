from __future__ import annotations

import shutil
from pathlib import Path

from pydantic_settings import BaseSettings

_DATA_DIR = Path.home() / ".config" / "clawwall"

# The bundled default policy shipped with the package
_BUNDLED_POLICY = Path(__file__).resolve().parent / "default_policy.yaml"

# Legacy location (repo checkout)
_REPO_POLICY = Path(__file__).resolve().parent.parent.parent / "config" / "default_policy.yaml"


def _ensure_data_dir() -> Path:
    """Create the data directory and seed the default policy if missing."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    target = _DATA_DIR / "policy.yaml"
    if not target.exists():
        # Prefer bundled copy; fall back to repo checkout path
        source = _BUNDLED_POLICY if _BUNDLED_POLICY.exists() else _REPO_POLICY
        if source.exists():
            shutil.copy2(source, target)
    return _DATA_DIR


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8642
    debug: bool = False

    database_url: str = f"sqlite+aiosqlite:///{_DATA_DIR / 'clawwall.db'}"

    policy_path: str = str(_DATA_DIR / "policy.yaml")

    log_level: str = "INFO"

    model_config = {"env_prefix": "CLAWGUARD_"}


def get_settings() -> Settings:
    _ensure_data_dir()
    return Settings()
