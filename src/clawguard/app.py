from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from clawguard.api.router import api_router
from clawguard.config import Settings, get_settings
from clawguard.dashboard import router as dashboard_router
from clawguard.db.session import close_db, init_db
from clawguard.dependencies import get_container, init_container


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = init_container(settings)
        await init_db(container.engine)
        yield
        await close_db(container.engine)

    app = FastAPI(
        title="ClawGuard",
        description="DLP Surveillance Layer for OpenClaw",
        version="0.2.0",
        lifespan=lifespan,
    )
    app.include_router(api_router)
    app.include_router(dashboard_router)
    return app
