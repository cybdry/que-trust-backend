"""application/problem+json errors (Technical Docs 2 "Shared contracts and error handling")."""

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse


class Problem(Exception):
    def __init__(self, status: int, code: str, detail: str = "", **extra: Any) -> None:
        super().__init__(detail or code)
        self.status, self.code, self.detail, self.extra = status, code, detail, extra


async def problem_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, Problem)
    body = {
        "type": f"urn:que:problem:{exc.code.replace('_', '-')}",
        "title": exc.code.replace("_", " ").capitalize(),
        "status": exc.status,
        "detail": exc.detail,
        "instance": request.url.path,
        "code": exc.code,
        "correlation_id": request.headers.get("X-Correlation-Id"),
        "retryable": exc.status in (409, 429, 503) and exc.code != "idempotency_conflict",
        **exc.extra,
    }
    return JSONResponse(body, status_code=exc.status, media_type="application/problem+json")
