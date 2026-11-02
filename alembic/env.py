import asyncio

from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context
from quetrust.config import get_settings


async def _run() -> None:
    engine = create_async_engine(get_settings().migration_database_url)
    async with engine.connect() as conn:
        await conn.run_sync(lambda c: (context.configure(connection=c), context.run_migrations()))
        await conn.commit()
    await engine.dispose()


asyncio.run(_run())
