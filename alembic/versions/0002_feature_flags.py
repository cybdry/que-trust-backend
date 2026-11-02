"""Feature flags and the person behind a service's call (DEC-198).

Revision ID: 0002
- feature_flag: whether the tenant lets Nexus use a product's feature (Connect's knowledge, tools, models, skills,
  A2A agents; AMPHI's registry, releases, deployments, budgets). A feature without a row is on (default true).
- decision.on_behalf_of, approval.on_behalf_of: the person (their verified Que.IS token, `Que-Subject-Token`) a
  service called for.
- Events can go to AMPHI too (feature flags of AMPHI's features).
"""

from alembic import op

revision = "0002"
down_revision = "0001"

SQL = """
CREATE TABLE trust.feature_flag (
  tenant_id uuid NOT NULL, product text NOT NULL, feature text NOT NULL, enabled boolean NOT NULL,
  version int NOT NULL DEFAULT 1, updated_by text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, product, feature)
);
ALTER TABLE trust.decision ADD COLUMN on_behalf_of text;
ALTER TABLE trust.approval ADD COLUMN on_behalf_of text;
ALTER TABLE trust.outbox_event DROP CONSTRAINT IF EXISTS outbox_event_target_check;
ALTER TABLE trust.outbox_event ADD CONSTRAINT outbox_event_target_check CHECK (target IN ('nexus', 'connect', 'amphi'))
"""


def upgrade() -> None:
    for statement in (x.strip() for x in SQL.split(";\n")):
        if statement:
            op.execute(statement)
    using = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    op.execute("ALTER TABLE trust.feature_flag ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE trust.feature_flag FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON trust.feature_flag USING ({using}) WITH CHECK ({using})")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON trust.feature_flag TO trust_app")


def downgrade() -> None:
    op.execute("ALTER TABLE trust.outbox_event DROP CONSTRAINT IF EXISTS outbox_event_target_check")
    op.execute(
        "ALTER TABLE trust.outbox_event ADD CONSTRAINT outbox_event_target_check CHECK (target IN ('nexus', 'connect'))"
    )
    op.execute("ALTER TABLE trust.approval DROP COLUMN on_behalf_of")
    op.execute("ALTER TABLE trust.decision DROP COLUMN on_behalf_of")
    op.execute("DROP TABLE trust.feature_flag")
