"""The Que Trust API (`/api/v2`) with an in-process worker: signed event delivery and approval expiry.

No CORS layer: browsers reach Trust through nginx, which answers CORS for the console's origins."""

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from quetrust import db, events, keys, service
from quetrust.api import console, flags, owner
from quetrust.config import get_settings
from quetrust.errors import Problem, problem_handler

log = logging.getLogger("quetrust")


async def _worker() -> None:
    while True:
        try:
            await events.deliver_pending()
            await service.expire_due()
        except Exception:
            log.exception("worker pass failed")
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    keys.signing_key()  # fail at start, not at the first decision, when production has no key
    task = asyncio.create_task(_worker()) if get_settings().deliver_events else None
    yield
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    await db.dispose()


def create_app() -> FastAPI:
    production = get_settings().production
    app = FastAPI(
        title="Que Trust API",
        version="2.0.0-draft",
        lifespan=lifespan,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )
    app.add_exception_handler(Problem, problem_handler)
    app.include_router(owner.wellknown)
    app.include_router(owner.wellknown, prefix="/api/v2")
    for module in (owner, console, flags):
        app.include_router(module.router, prefix="/api/v2")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
