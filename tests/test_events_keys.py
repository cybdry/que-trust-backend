"""Signed event delivery (03 §D.2) — approval events to Nexus, resource-policy events to Connect, a feature flag's
event to its product (DEC-198), retried until
accepted — and the decision-token key: production never makes one up."""

import hashlib
import hmac
import json

import httpx
import pytest

from quetrust import events, keys
from quetrust.config import Settings, get_settings
from tests.conftest import Tenant


async def test_events_are_signed_and_routed(t: Tenant, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUST_DELIVER_EVENTS", "true")
    monkeypatch.setenv("TRUST_EVENT_SUBSCRIBERS", '["https://nexus.test/api/v2/events/inbound"]')
    monkeypatch.setenv("TRUST_CONNECT_INBOUND", '["https://connect.test/api/v2/events/inbound"]')
    monkeypatch.setenv("TRUST_AMPHI_INBOUND", '["https://amphi.test/api/v2/events/inbound"]')
    get_settings.cache_clear()
    seen: list[httpx.Request] = []
    nexus_up = False

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "nexus.test" and not nexus_up:
            return httpx.Response(503)
        return httpx.Response(202)

    try:
        a = await t.approval(t.body())
        await t.vote(a, "default", t.person("amy", "approver"))
        await t.req("PUT", "/resource-policies/que-connect/model/m-1", t.admin, {"rules": []}, expect=200)
        await t.req("PUT", "/feature-flags/que-amphi/budgets", t.admin, {"enabled": False}, expect=200)
        await events.deliver_pending(limit=100_000, transport=httpx.MockTransport(handler))
        mine = [r for r in seen if json.loads(r.content)["quetenant"] == str(t.id)]
        assert {(r.url.host, json.loads(r.content)["type"]) for r in mine} == {
            ("nexus.test", "que.trust.approval.decided.v2"),
            ("connect.test", "que.trust.resource_policy.changed.v2"),
            ("amphi.test", "que.trust.feature_flag.changed.v2"),
        }
        signed = mine[0]
        sig = dict(p.strip().split("=", 1) for p in signed.headers["Que-Signature"].split(","))
        mac = hmac.new(b"dev-event-signing-secret", f"{sig['t']}.".encode() + signed.content, hashlib.sha256)
        assert sig["v1"] == mac.hexdigest() and json.loads(signed.content)["source"] == "que-trust"
        assert all(r.headers["User-Agent"].startswith("que-trust/") for r in mine)  # named (DEC-199)

        pending = {e["id"] for e in await t.outbox()}
        nexus_up = True
        seen.clear()
        await events.deliver_pending(limit=100_000, transport=httpx.MockTransport(handler))
        retried = [json.loads(r.content)["id"] for r in seen if json.loads(r.content)["quetenant"] == str(t.id)]
        assert retried and set(retried) <= pending  # the same event id, retried
    finally:
        get_settings.cache_clear()


# Production refuses plain-http addresses (DEC-199): the production-mode tests use these.
HTTPS_ENV = {
    "TRUST_JWKS_URL": "https://nhiam.example/.well-known/jwks.json",
    "TRUST_ISSUER": "https://trust.example",
    "TRUST_PUBLIC_BASE_URL": "https://trust.example",
    "TRUST_EVENT_SUBSCRIBERS": '["https://nexus.example/api/v2/events/inbound"]',
    "TRUST_CONNECT_INBOUND": '["https://connect.example/api/v2/events/inbound"]',
    "TRUST_AMPHI_INBOUND": '["https://amphi.example/api/v2/events/inbound"]',
}


def _production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUST_ENV", "production")
    for k, v in HTTPS_ENV.items():
        monkeypatch.setenv(k, v)


def test_production_needs_a_signing_key(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    _production(monkeypatch)
    monkeypatch.setenv("TRUST_SIGNING_KEY", "")
    monkeypatch.setenv("TRUST_SIGNING_KEY_FILE", f"{tmp_path}/missing.pem")
    get_settings.cache_clear()
    keys.signing_key.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="required in production"):
            keys.signing_key()
        pem = Settings().model_dump()  # sanity: settings load in production without the key set
        assert pem["env"] == "production"
    finally:
        get_settings.cache_clear()
        keys.signing_key.cache_clear()


def test_the_key_can_come_from_a_mounted_file(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    pem = get_settings().signing_key
    path = f"{tmp_path}/trust.pem"
    with open(path, "w") as f:
        f.write(pem)
    _production(monkeypatch)
    monkeypatch.setenv("TRUST_SIGNING_KEY", "")
    monkeypatch.setenv("TRUST_SIGNING_KEY_FILE", path)
    get_settings.cache_clear()
    keys.signing_key.cache_clear()
    try:
        assert keys.jwks()["keys"][0]["kid"] == "trust-1"
    finally:
        get_settings.cache_clear()
        keys.signing_key.cache_clear()
