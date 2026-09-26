# unmask

**Self-hosted OSINT orchestration platform.** unmask runs open-source intelligence tools as
repeatable, audited investigations: automated pivot chains, case management with a full
audit trail, time-aware diffing between scans, and an open tool-adapter architecture.

> Use unmask only for investigations you are authorized to perform and have a lawful basis
> for. Every case records a written authorization note and a lawful-basis confirmation
> before a single lookup runs.

---

## Contents

- [Features](#features)
- [Status](#status)
- [Architecture](#architecture)
- [Local development](#local-development)
- [Deploying to Railway](#deploying-to-railway)
- [Key management](#key-management)
- [Writing a tool adapter](#writing-a-tool-adapter)
- [Operational footprint & ethics](#operational-footprint--ethics)

## Features

| | |
|---|---|
| **Case gate** | Cases cannot be created without an authorization note and lawful-basis confirmation — enforced in the UI, the service layer *and* a database `CHECK` constraint. |
| **Encryption at rest** | Entity values, attributes and target values are encrypted (Fernet) before they reach Postgres. Lookups use an HMAC blind index. Keys never live with the database. |
| **Honest failures** | Adapters must prove an empty result is genuinely empty. Bot walls, proxy blocks and soft-200 pages raise `SignatureMismatch` and are shown as failures — never as "0 results". |
| **Failure isolation** | One broken tool never fails a scan. Every failure is written to `scan_runs.tools_failed` / `failure_details` and shown on the case. |
| **Circuit breaker** | Three consecutive failures auto-disable a tool and raise a banner. A passing health check (against a known-good target, validated by content signature) re-enables it. |
| **Reliability ≠ confidence** | Every entity carries a source-reliability rating (Admiralty A–F: trust in the *source class*) separately from confidence (is this the *same person*). |
| **Audit trail** | Logins, case views, scans, confirmations and health checks are written to `access_log`, which survives case deletion. |

## Status

Built phase by phase; each phase is verified before the next starts.

| Phase | Scope | State |
|---|---|---|
| 0 | Scaffold, full schema + migrations, auth, Railway deploy config | ✅ |
| 1 | `ToolAdapter` interface, Sherlock adapter, Dashboard, Case Creation, Entities tab | ✅ |
| 2 | Maigret, Holehe, h8mail, theHarvester, Amass, crt.sh, SpiderFoot; RQ workers; rate limiting | ⏳ |
| 3 | Two-pass correlation (fuzzy + embeddings), confidence scoring, merge/split | ⏳ |
| 4 | Pivot rule engine + Pivot Log | ⏳ |
| 5 | Graph tab (Cytoscape) | ⏳ |
| 6 | Timeline diffing + watch mode | ⏳ |
| 7 | DuckDuckGo + Brave adapters, search-link buttons | ⏳ |
| 8 | Reporting / export | ⏳ |
| 9 | GHunt, PhoneInfoga, ExifTool (disabled by default), multi-user sharing | ⏳ |
| 10 | AI synthesis layer | ⏳ |

The circuit breaker and manual tool health checks are already live, since the schema and
orchestrator needed them anyway.

## Architecture

```
FastAPI (async) ── Jinja2 + htmx ── Cytoscape.js (graph tab only)
   │
   ├── app/adapters/     ToolAdapter contract + one module per tool (subprocess / API only)
   ├── app/services/     cases, scan orchestration, entities, tool health
   ├── app/models.py     full schema (SQLAlchemy 2.0), encrypted column types
   ├── app/crypto.py     Fernet encryption + HMAC blind index, key rotation
   └── migrations/       Alembic
PostgreSQL ── case data          Redis ── login rate limiting (RQ queue from Phase 2)
```

**Scan flow.** Creating a case writes the investigation, its targets (plus a seed entity per
target) and scan run #1, then dispatches one job per *(target, enabled tool accepting that
target type)*. Jobs run concurrently within each tool's `max_concurrent` /
`delay_between_requests_ms` limits. Results are upserted by blind index, every sighting is
recorded in `entity_observations` (which powers diffing), and each discovery is linked to its
target with a `relation` carrying a plain-language `match_explanation`.

In Phases 0–1 scans run in-process, so the web service runs a single Uvicorn worker. Phase 2
moves them to RQ worker services with priority queues (manual scans preempt watch-mode).

### Schema

The complete schema ships in migration `0001` so later phases never partially migrate
existing case data: `users`, `investigations`, `targets`, `entities`, `entity_observations`,
`relations`, `scan_runs`, `pivot_log`, `tool_config`, `access_log`.

## Local development

Requirements: Python 3.11+, PostgreSQL 14+, Redis (optional locally — login rate limiting
falls back to memory).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pip install -r requirements-tools.txt      # sherlock etc. (or install into a separate venv
                                           # and point UNMASK_TOOLS_BIN at its bin/)
cp .env.example .env
python -m app.cli gen-keys                 # paste the output into .env
# set DATABASE_URL and UNMASK_ADMIN_EMAIL / UNMASK_ADMIN_PASSWORD in .env
alembic upgrade head
uvicorn app.main:app --reload
```

Open http://localhost:8000 and sign in with the bootstrap admin. Additional users:
`python -m app.cli create-user someone@example.com`.

### Tests

```bash
createdb unmask_test
TEST_DATABASE_URL=postgresql://localhost/unmask_test pytest
ruff check . && ruff format --check .
```

Integration tests rebuild the schema from the migrations and use fake adapters, so they need
no network access. They cover the case gate, CSRF, login rate limiting, failure isolation,
soft-failure detection, the circuit breaker, per-owner access control, audit logging and
encryption at rest.

### Tool health

```bash
python -m app.cli health-check            # every tool
python -m app.cli health-check sherlock
```

Health checks run each tool against a known-good target and validate a content signature
(e.g. Sherlock must find the known account on GitHub *and* GitLab) — an HTTP 200 alone proves
nothing.

## Deploying to Railway

1. **Create a project** and add the **PostgreSQL** and **Redis** plugins.
2. **Add a service from this GitHub repo.** Railway picks up `railway.toml` and builds the
   `Dockerfile`; each push to the default branch redeploys. Migrations run on start and
   `/healthz` is the health check.
3. **Set variables on the web service** (not on the database):

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` (reference variable) |
   | `REDIS_URL` | `${{Redis.REDIS_URL}}` |
   | `SECRET_KEY`, `UNMASK_DATA_KEYS`, `UNMASK_INDEX_KEY` | from `python -m app.cli gen-keys` — see [Key management](#key-management) |
   | `UNMASK_ADMIN_EMAIL`, `UNMASK_ADMIN_PASSWORD` | bootstrap admin; remove after first login |
   | `PUBLIC_BASE_URL` | your public URL, e.g. `https://unmask.example.com` (canonical URLs, sitemap, Open Graph) |

4. **Generate a domain** under the service's networking settings.
5. **Backups.** The database holds irreplaceable case data. Enable Railway's Postgres
   backups (or a scheduled `pg_dump` to object storage) and test a restore before relying on it.

`UNMASK_ENV=production` (set in the image) refuses to start with a weak `SECRET_KEY`, missing
encryption keys, or a secret key that reuses encryption key material, and turns on secure
cookies and HSTS.

## Key management

- `UNMASK_DATA_KEYS` — comma-separated Fernet keys. The first encrypts; all decrypt. To
  rotate, prepend a new key, re-encrypt, then drop the old one.
- `UNMASK_INDEX_KEY` — HMAC key for the blind index. Changing it requires re-indexing.
- Keys must live in a secret store **separate from the database**: a dedicated secret manager
  (Doppler, Infisical, 1Password, Vault) synced into the web service's variables, or at minimum
  set only on the web service — never on the Postgres service. A database backup alone must
  never be enough to read case data.
- Losing the data keys makes encrypted fields unrecoverable. Keep an offline copy.

## Writing a tool adapter

```python
from app.adapters.base import EntityCandidate, RawResult, SignatureMismatch, ToolAdapter, run_tool_subprocess


class ExampleAdapter(ToolAdapter):
    name = "example"
    label = "Example"
    input_types = ["email"]
    health_check_target = "known-good@example.com"

    async def run(self, target_value, context_tags):
        proc = await run_tool_subprocess(["example-cli", "--json", "--", target_value])
        if '"status": "complete"' not in proc.stdout:
            raise SignatureMismatch("no completion marker — possible bot wall or partial run")
        return [RawResult(self.name, target_value, proc.stdout)]

    def parse(self, raw):
        return [EntityCandidate(type="domain", value="example.com", source_reliability="B", confidence=0.6)]
```

Register it in `app/adapters/registry.py`. Rules:

- Call tools only via `run_tool_subprocess` or an HTTP API — never import third-party tool
  code. The subprocess gets a scrubbed environment (no database URL, keys or secrets), a
  throwaway working directory, no shell, and a timeout.
- Put user-supplied values after `--` and validate them, so a target can never become a flag.
- Raise `SignatureMismatch` whenever the output doesn't prove the run completed. Returning
  `[]` means "verified: nothing found".
- Set `source_reliability` for the source class and keep `confidence` about identity.

## Operational footprint & ethics

- **Authorization first.** Cases require a written authorization note and lawful-basis
  confirmation, stored with the case.
- **Your footprint is visible.** Repeated automated lookups against one person are
  themselves a detectable pattern — to the platforms queried and potentially to the subject.
  Scan only as often as the investigation needs; watch mode (Phase 6) will stagger runs.
- **Retention.** Each case has `retention_days` (default 90). Enforced purging ships with
  watch mode; until then, delete cases you no longer need.
- **Humans conclude.** Report export (Phase 8) will require a human-written analyst
  assessment. The platform presents correlated evidence; it does not decide who someone is.
- **Search engines.** Only the public landing page is indexable. Everything behind the login
  sends `X-Robots-Tag: noindex` and `Cache-Control: no-store`, and `robots.txt` disallows it.
  Set `UNMASK_ALLOW_INDEXING=false` to hide the deployment from crawlers entirely.
