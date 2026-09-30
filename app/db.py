from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    pass


# asyncpg connections are bound to the event loop that opened them. The web
# app runs one loop, but each RQ job runs its own (asyncio.run), so engines are
# kept per loop.
_engines: dict[int, tuple[AsyncEngine, async_sessionmaker[AsyncSession]]] = {}


def _current() -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    try:
        key = id(asyncio.get_running_loop())
    except RuntimeError:
        key = 0
    pair = _engines.get(key)
    if pair is None:
        # Idle connections are recycled rather than held open indefinitely (the
        # idle monitor also closes them all when nobody is using the app).
        engine = create_async_engine(get_settings().database_url, pool_pre_ping=True, pool_recycle=300)
        pair = _engines[key] = (engine, async_sessionmaker(engine, expire_on_commit=False))
    return pair


def get_engine() -> AsyncEngine:
    return _current()[0]


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    return _current()[1]


async def dispose_engine() -> None:
    """Dispose the current loop's engine."""
    try:
        key = id(asyncio.get_running_loop())
    except RuntimeError:
        key = 0
    pair = _engines.pop(key, None)
    if pair is not None:
        await pair[0].dispose()


async def get_session() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as session:
        yield session
