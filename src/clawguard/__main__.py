"""CLI entry point: python -m clawguard"""
from __future__ import annotations

import uvicorn

from clawguard.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "clawguard.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
