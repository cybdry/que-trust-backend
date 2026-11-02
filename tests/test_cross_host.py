"""Cross-host operation (DEC-199): in production every address of another product is https://, and Trust names
itself on its outbound calls (WAFs such as Que.IS's Cloudflare refuse Python's default user agents)."""

import uuid

import httpx
import pytest

from quetrust import auth
from quetrust.config import Settings

HTTPS = {
    "env": "production",
    "jwks_url": "https://nhiam.example/.well-known/jwks.json",
    "qct_jwks_url": "https://api.que.example/.well-known/jwks.json",
    "nhiam_url": "https://nhiam.example/api/v2",
    "issuer": "https://trust.example",
    "public_base_url": "https://trust.example",
    "event_subscribers": ["https://nexus.example/api/v2/events/inbound"],
    "connect_inbound": ["https://connect.example/api/v2/events/inbound"],
    "amphi_inbound": ["https://amphi.example/api/v2/events/inbound"],
    "opa_url": "http://trust-opa:8181",  # Trust's own engine, deployed with it: plain http is fine
}


def test_production_addresses_must_be_https() -> None:
    assert Settings(**HTTPS).env == "production"
    for name, value in (
        ("jwks_url", "http://devstack:8230/nhiam/api/v2/.well-known/jwks.json"),
        ("nhiam_url", "http://devstack:8230/nhiam/api/v2"),
        ("issuer", "http://trust.example"),
        ("connect_inbound", ["http://connect:8210/api/v2/events/inbound"]),
        ("amphi_inbound", ["http://amphi:8220/api/v2/events/inbound"]),
    ):
        with pytest.raises(ValueError, match=name):
            Settings(**{**HTTPS, name: value})


def test_development_keeps_plain_http() -> None:
    assert Settings(jwks_url="http://127.0.0.1:8230/jwks.json").env == "dev"


async def test_jwks_fetch_names_trust(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"keys": []})

    real = httpx.AsyncClient
    monkeypatch.setattr(
        auth.httpx, "AsyncClient", lambda **kw: real(**{**kw, "transport": httpx.MockTransport(handler)})
    )
    await auth.jwks_at(f"https://nhiam.example/{uuid.uuid4()}/.well-known/jwks.json", None)
    assert seen and seen[0].headers["User-Agent"].startswith("que-trust/")
