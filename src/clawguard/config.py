from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8642
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///clawguard.db"

    policy_path: str = str(
        Path(__file__).resolve().parent.parent.parent / "config" / "default_policy.yaml"
    )

    log_level: str = "INFO"

    model_config = {"env_prefix": "CLAWGUARD_"}


def get_settings() -> Settings:
    return Settings()
