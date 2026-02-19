from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from clawguard.db.models import Base


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine(database_url: str) -> AsyncEngine:
    global _engine
    if _engine is None or str(_engine.url) != database_url:
        _engine = create_async_engine(database_url, echo=False)
    return _engine


def get_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory


async def init_db(engine: AsyncEngine) -> None:
    """Create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db(engine: AsyncEngine) -> None:
    """Dispose of engine connections."""
    await engine.dispose()


def reset_globals() -> None:
    """Reset module-level state (for testing)."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
