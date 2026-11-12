"""Async database engine/session + initialization."""

from __future__ import annotations

from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from .config import get_settings

_settings = get_settings()
_engine = create_async_engine(_settings.db_url, echo=False, future=True)
_SessionLocal = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    # Import models so metadata is populated before create_all.
    from . import models  # noqa: F401
    async with _engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


@asynccontextmanager
async def session_scope():
    async with _SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_engine():
    return _engine
