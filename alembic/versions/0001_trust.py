"""Que Trust schema: tenant policies (rules + Rego), approval policies, groups, agent profiles, decisions,
approvals, evidence, resource policies, idempotency, outbox (DEC-197).

Revision ID: 0001
Every table is tenant-scoped with forced row security (app.tenant_id). The API role sees only the verified
caller's tenant. Only the worker role (BYPASSRLS, granted just the outbox and approvals) scans across
tenants, to deliver events and expire approvals.
"""

from alembic import op

revision = "0001"
down_revision = None

TENANT_TABLES = (
    "tenant_policy",
    "approval_config",
    "tenant_group",
    "agent_profile",
    "decision",
    "approval",
    "evidence_package",
    "resource_policy",
    "idempotency_record",
    "outbox_event",
)

SQL = """
CREATE SCHEMA IF NOT EXISTS trust;
SET search_path = trust, public;

CREATE TABLE tenant_policy (
  tenant_id uuid NOT NULL PRIMARY KEY, rego text NOT NULL, rules jsonb, digest text NOT NULL,
  saved_by text NOT NULL, saved_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE approval_config (
  tenant_id uuid NOT NULL PRIMARY KEY, config jsonb NOT NULL, revision int NOT NULL DEFAULT 1,
  updated_by text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_group (
  tenant_id uuid NOT NULL, grp text NOT NULL, member text NOT NULL,
  added_by text NOT NULL, added_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, grp, member)
);

CREATE TABLE agent_profile (
  tenant_id uuid NOT NULL, version_key text NOT NULL, asset_id text, profile jsonb NOT NULL,
  digest text NOT NULL, registered_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, version_key)
);

CREATE TABLE decision (
  tenant_id uuid NOT NULL, id text NOT NULL, action jsonb NOT NULL, action_digest text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('allow', 'deny', 'approval_required')),
  reasons jsonb NOT NULL DEFAULT '[]', obligations jsonb NOT NULL DEFAULT '[]', policy_ref text NOT NULL,
  input jsonb NOT NULL DEFAULT '{}', approval_ref text, expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX decision_recent ON decision (tenant_id, created_at DESC);

CREATE TABLE approval (
  tenant_id uuid NOT NULL, id text NOT NULL, idempotency_key text NOT NULL, decision_ref text NOT NULL,
  action jsonb NOT NULL, action_digest text NOT NULL, business_reason text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected', 'changes_requested', 'expired', 'voided')),
  stages jsonb NOT NULL, void_reason text, revision int NOT NULL DEFAULT 1, next_expiry timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX approval_due ON approval (next_expiry) WHERE status = 'pending' AND next_expiry IS NOT NULL;

CREATE TABLE evidence_package (
  tenant_id uuid NOT NULL, id text NOT NULL, manifest_digest text, package jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE resource_policy (
  tenant_id uuid NOT NULL, product text NOT NULL, kind text NOT NULL, ref text NOT NULL, policy_id text NOT NULL,
  rules jsonb, tool_rules jsonb NOT NULL DEFAULT '[]', version int NOT NULL,
  assigned_by text NOT NULL, assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, product, kind, ref)
);

CREATE TABLE idempotency_record (
  tenant_id uuid NOT NULL, scope text NOT NULL, key text NOT NULL, request_digest text NOT NULL,
  status int, response jsonb, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, scope, key)
);

CREATE TABLE outbox_event (
  tenant_id uuid NOT NULL, id text NOT NULL, type text NOT NULL, target text NOT NULL
    CHECK (target IN ('nexus', 'connect')),
  data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz, attempts int NOT NULL DEFAULT 0, last_error text,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX outbox_pending ON outbox_event (created_at) WHERE delivered_at IS NULL
"""


def upgrade() -> None:
    for statement in (x.strip() for x in SQL.split(";\n")):  # asyncpg runs one statement per call
        if statement:
            op.execute(statement)
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE trust.{t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE trust.{t} FORCE ROW LEVEL SECURITY")
        using = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"
        op.execute(f"CREATE POLICY tenant_isolation ON trust.{t} USING ({using}) WITH CHECK ({using})")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON trust.{t} TO trust_app")
    op.execute("GRANT USAGE ON SCHEMA trust TO trust_app, trust_worker")
    op.execute("GRANT SELECT, UPDATE ON trust.outbox_event, trust.approval TO trust_worker")
    op.execute("GRANT INSERT ON trust.outbox_event TO trust_worker")


def downgrade() -> None:
    op.execute("DROP SCHEMA trust CASCADE")
