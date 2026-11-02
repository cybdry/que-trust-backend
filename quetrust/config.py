"""Settings (TRUST_*). Dev defaults point at the local stack: Postgres :55432, OPA :58181, que-devstack :8230,
Nexus :8200, Connect :8210."""

from functools import lru_cache
from typing import Any

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRUST_", extra="ignore")

    env: str = "dev"
    database_url: str = "postgresql+asyncpg://trust_app:trust_app_dev@localhost:55432/trust"
    # Event delivery and approval expiry only: BYPASSRLS, granted just the outbox and approvals.
    worker_database_url: str = "postgresql+asyncpg://trust_worker:trust_worker_dev@localhost:55432/trust"
    migration_database_url: str = "postgresql+asyncpg://trust_owner:trust_owner_dev@localhost:55432/trust"
    # The decision engine (DEC-144). Trust keeps every module in its database and reloads OPA when it lost them.
    opa_url: str = "http://127.0.0.1:58181"

    # Callers are verified offline: NHIAM's JWKS (services, workloads, AI approvers) and the dev people issuer.
    jwks_url: str = "http://127.0.0.1:8230/nhiam/api/v2/.well-known/jwks.json"
    jwks: dict[str, Any] | None = None  # a static JWKS (tests) instead of jwks_url
    issuers: list[str] = ["https://dev.que.local/nhiam", "https://dev.que.local/issuer"]
    audience: str = "que-trust"
    clock_skew_seconds: int = 60
    # Que.IS QCTs (people signed in through Que.IS): RS256, aud "queis", tenant in customerTenantId. Empty: off.
    qct_issuer: str = ""
    qct_jwks_url: str = ""
    qct_jwks: dict[str, Any] | None = None  # static JWKS (tests)
    qct_audience: str = "queis"
    # Que.IS base AAA for people (Technical Docs 2). Empty: off.
    que_is_url: str = ""

    # Decision tokens (03 §C.8 (6)): RS256 with this PEM key (the secret store in production; outside
    # production a key file is made on first use).
    issuer: str = "https://dev.que.local/trust"
    signing_key: str = ""
    signing_key_file: str = ".data/trust-signing-key.pem"
    signing_kid: str = "trust-1"
    decision_ttl_seconds: int = 300

    # NHIAM: an AI approver's approval mandate is checked there when it decides. Empty: AI approvers are refused.
    nhiam_url: str = ""
    nhiam_token: str = ""  # Trust's bearer for NHIAM

    # Signed events (03 §D): approvals → Nexus; resource policies and Connect's feature flags → Connect; AMPHI's
    # feature flags → AMPHI (DEC-198).
    event_subscribers: list[str] = ["http://127.0.0.1:8200/api/v2/events/inbound"]
    connect_inbound: list[str] = ["http://127.0.0.1:8210/api/v2/events/inbound"]
    amphi_inbound: list[str] = ["http://127.0.0.1:8220/api/v2/events/inbound"]
    event_signing_kid: str = "dev-1"
    event_signing_secret: str = "dev-event-signing-secret"  # noqa: S105 - dev default; production sets TRUST_EVENT_SIGNING_SECRET
    deliver_events: bool = True
    public_base_url: str = "http://localhost:8240"

    @model_validator(mode="after")
    def _https_in_production(self) -> "Settings":
        """In production the products may run on different hosts and reach each other only over HTTPS (DEC-199):
        every address of another product, its own public address and issuer must be https://. Empty means "off";
        the database URLs and Trust's own OPA (deployed with it) are not addresses of another product."""
        if self.env != "production":
            return self
        named = {
            "jwks_url": self.jwks_url,
            "qct_jwks_url": self.qct_jwks_url,
            "nhiam_url": self.nhiam_url,
            "public_base_url": self.public_base_url,
            "issuer": self.issuer,
            **{f"event_subscribers[{i}]": u for i, u in enumerate(self.event_subscribers)},
            **{f"connect_inbound[{i}]": u for i, u in enumerate(self.connect_inbound)},
            **{f"amphi_inbound[{i}]": u for i, u in enumerate(self.amphi_inbound)},
        }
        plain = [name for name, url in named.items() if url and not url.startswith("https://")]
        if plain:
            raise ValueError(f"production: these addresses must be https:// (DEC-199): {', '.join(plain)}")
        return self

    @property
    def production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
