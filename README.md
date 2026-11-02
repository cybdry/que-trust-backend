# Que Trust — backend

The Que Trust API (`/api/v2`): rules, approval policies and approvals, decisions (Rego, evaluated in OPA), feature
flags, resource policies, agent profiles and the platform policy, with signed event delivery to Que Nexus and Que
Connect and approval expiry in an in-process worker.

- Python 3.12, FastAPI, PostgreSQL (Alembic migrations), OPA for decisions.
- Install: `uv sync`. Migrate: `uv run alembic upgrade head`. Run: `uv run uvicorn quetrust.app:app`.
- Settings come from `TRUST_*` environment variables (`quetrust/config.py`); secrets are never committed.
- Tests: `uv run pytest -q` (needs PostgreSQL and OPA running locally).

Its console is [que-trust-frontend](https://github.com/Creacubedusa/que-trust-frontend).
