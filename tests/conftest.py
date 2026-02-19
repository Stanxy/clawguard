from __future__ import annotations

import os
import shutil

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clawguard.app import create_app
from clawguard.config import Settings
from clawguard.db.models import Base
from clawguard.db.session import init_db, close_db, reset_globals
from clawguard.dependencies import init_container
import clawguard.dependencies as deps


@pytest.fixture
def settings(tmp_path):
    """Settings using a temp SQLite DB and the default policy."""
    db_path = tmp_path / "test.db"
    src_policy = os.path.join(
        os.path.dirname(__file__), "..", "config", "default_policy.yaml"
    )
    policy_path = str(tmp_path / "policy.yaml")
    shutil.copy2(src_policy, policy_path)
    return Settings(
        database_url=f"sqlite+aiosqlite:///{db_path}",
        policy_path=policy_path,
        host="127.0.0.1",
        port=0,
    )


@pytest_asyncio.fixture
async def engine(settings):
    eng = create_async_engine(settings.database_url, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()
    reset_globals()


@pytest_asyncio.fixture
async def session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def client(settings):
    """HTTPX async test client for the FastAPI app with lifespan."""
    reset_globals()
    deps._container = None

    # Initialize the container and DB before running tests
    container = init_container(settings)
    await init_db(container.engine)

    app = create_app(settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    await close_db(container.engine)
    deps._container = None
    reset_globals()
