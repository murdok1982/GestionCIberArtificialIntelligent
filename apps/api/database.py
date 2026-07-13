from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from typing import AsyncGenerator
import logging
import os
from apps.api.config import settings


engine = create_async_engine(
    settings.DATABASE_URL.get_secret_value(),
    echo=settings.DEBUG,
    pool_size=20,
    max_overflow=0,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Apply schema migrations via Alembic.

    Using Alembic as the single source of truth avoids the drift that occurs
    when `metadata.create_all` and `alembic upgrade head` run against the same
    database (the second would fail with "already exists").
    """
    try:
        _run_alembic_upgrade()
    except Exception as exc:  # pragma: no cover - safety net for dev/test environments
        logging.getLogger(__name__).warning(
            "Alembic migration failed (%s); falling back to create_all. "
            "This should never happen in production.",
            exc,
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


def _run_alembic_upgrade() -> None:
    from alembic import command
    from alembic.config import Config

    here = os.path.dirname(os.path.abspath(__file__))
    ini_path = os.path.join(here, "alembic.ini")
    cfg = Config(ini_path)
    cfg.set_main_option("script_location", os.path.join(here, "alembic"))
    database_url = settings.DATABASE_URL.get_secret_value().replace(
        "postgresql+asyncpg", "postgresql"
    )
    cfg.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(cfg, "head")