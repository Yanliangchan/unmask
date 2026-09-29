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

Built phase by phase; each phase is verified before the next starts. **Phases 0–8 are the MVP.**
Phase 9's case sharing already works (owner-only, from Case Settings); its extra adapters remain.

| Phase | Scope | State |
|---|---|---|
| 0 | Scaffold, full schema + migrations, auth, Railway deploy config | ✅ |
| 1 | `ToolAdapter` interface, Sherlock adapter, Dashboard, Case Creation, Entities tab | ✅ |
| 2 | Maigret, Holehe, h8mail, theHarvester, Amass, crt.sh, SpiderFoot; RQ workers; rate limiting | ✅ |
| 3 | Two-pass correlation (fuzzy + embeddings), confidence scoring, merge/split | ✅ |
| 4 | Pivot rule engine + Pivot Log (depth/budget limits, skipped pivots logged) | ✅ |
| 5 | Graph tab (Cytoscape, PageRank centrality, self-hosted) | ✅ |
| 6 | Timeline diffs, watch mode (jittered, staggered), retention purges, scheduled health checks, alerts | ✅ |
| 7 | DuckDuckGo (Instant Answers) + Brave Search adapters, search-link and reverse-image buttons | ✅ |
| 8 | Case Settings screen, report export (Markdown + print-ready PDF) gated on a written analyst assessment | ✅ |
| 9 | GHunt, PhoneInfoga, ExifTool (disabled by default), multi-user sharing | ⏳ |
| 10 | AI synthesis layer | ⏳ |

## Correlation

Correlation runs after every scan (and on demand from the Entities tab).

**Pass 1 — string rules (rapidfuzz).**
- *Merges* values that are the same identifier written differently: case, `http`/`https`/`www`
  and trailing slashes on profile URLs, Gmail dots and `+tags`, name order and punctuation
  (`Chan, Yan-Liang` = `Yan Liang Chan`), phone formatting, IPv6 notation. This is
  de-duplication, not an identity judgement.
- *Links* entities that corroborate each other across types: an email whose handle matches a
  username, a profile's display name matching a name, an address at a target domain.
- *Suggests* near-misses for review: `j.doe`/`j_doe`, `Jon Smith`/`John Smith`,
  `Yan Chan`/`Yan Liang Chan`.

**Pass 2 — local embeddings** (`all-MiniLM-L6-v2`, CPU, baked into the image) *suggests*
semantically similar names and usernames the rules miss, noting whether initials line up.
If the model isn't available, pass 2 is reported as skipped rather than quietly replaced.

**Only identical identifiers merge automatically.** Everything that is a judgement about
identity is a suggestion with a written explanation that an analyst accepts ("Same — merge")
or dismisses ("Different — keep separate"). Analysts can also merge any two values of the same
type and split merged values apart. Every decision is audited, and the engine never
re-merges a pair an analyst separated or re-suggests one they dismissed. Merged values pool
their details and sources, so no evidence is lost.

**Confidence** (does this belong to the subject?) combines, with diminishing returns:
the adapter's prior, weighted by source reliability; each additional independent tool;
cross-field corroboration; and the share of case context tags found in the entity's own
details. Targets and analyst-confirmed entities are 1.0. Each entity shows a plain-language
breakdown of its score, and `field_confidence` stores the components.

Explanations quote the values they compare, so `relations.match_explanation` is encrypted
at rest like the values themselves.

## Pivots

After each scan is correlated, pivot rules decide which findings get followed up
automatically:

| Finding | Rule | Tool |
|---|---|---|
| username (conf > 0.6) | guess `username@` gmail / outlook / yahoo / proton | Holehe |
| username (conf > 0.6) | the username itself | Maigret |
| email (conf > 0.6) | the address | h8mail |
| email (conf > 0.6) | its domain, unless a shared provider | theHarvester |
| domain | the domain, unless a shared provider or big platform | Amass, crt.sh, SpiderFoot |

Each trigger is written to the pivot log (Pivot Log screen), and the pivots from one
evaluation run together as a `pivot_chain` scan. The platform never runs a tool twice on the same input in a case, never pivots onto shared
domains such as gmail.com, and caps chains by depth (`UNMASK_PIVOT_MAX_DEPTH`, default 2)
and by pivots per evaluation (`UNMASK_PIVOT_BUDGET`, default 20). Pivots that hit a limit, or
whose tool is disabled, unconfigured or excluded from the case, are logged as **skipped with
the reason**. A guessed address only becomes an entity if a tool confirms it is registered.
Auto-pivot can be switched off per case. Rules live in `app/pivots/rules.py`.

## Timeline, watch mode and retention

**Timeline** compares any two scan runs (by default the latest two analyst or watch-mode
runs): *new*, *changed* (a tool reported different details) and *no longer found*. A value
that "disappeared" because its tool failed or didn't run is labelled *not a real
disappearance*, with the reason, instead of being reported as gone.

**Watch mode** re-scans a case weekly or monthly. Each case's next run is jittered (±10%,
at most 12 hours) and each scheduler tick starts at most `UNMASK_WATCH_MAX_PER_TICK` scans,
chosen at random, so watched cases never hit the tools in one synchronized burst. Watch scans
use the lowest-priority queue.

**Retention** is enforced, not just stored: a case with no new scans for `retention_days`
is deleted with everything in it, unless it is marked permanently active. Viewing a case
does not extend its retention. The dashboard warns during the last week. Audit rows about a
purged case keep its id.

**Scheduler.** One loop handles watch scans, purges and daily tool health checks
(`UNMASK_HEALTHCHECK_HOURS`). With RQ it runs inside the worker behind a Redis lock, so extra
workers never double-run it, and no separate cron service is needed. Set
`UNMASK_ALERT_WEBHOOK_URL` (Slack/Discord/Teams-compatible) to be alerted when a circuit
breaker trips or cases are purged. Alerts contain tool names and counts only, never case data.

## Reports and case settings

**Case Settings** (from the case header) holds watch mode, automatic pivots, retention,
sharing, the analyst assessment, report export and deletion. Sharing and deletion are
owner-only. Deletion needs the case name typed out, and every change is audited.

**Reports** can't be exported until the case has a human-written **analyst assessment**. The
report presents evidence; the assessment is the conclusion. A report contains:
- the assessment and the authorization note
- the targets
- entities grouped by confidence tier, with source reliability, sources and merges
- the number of unreviewed suggestions
- contradictions between sources (e.g. accounts reporting different locations)
- the scan timeline with the latest diff
- pivot counts
- coverage gaps (tools whose latest run failed)
- a method section

Export is a Markdown download or a print-ready view ("Save as PDF" in the browser), which
renders names in any script correctly. Every export is audited. Reports are generated on
demand and never stored.

## Tools

Every tool runs as a subprocess (or HTTP API) from its own virtualenv, and every adapter
carries a completion check for the way that tool fails silently.

| Tool | Input | Licence | Source reliability | How a silent failure is caught |
|---|---|---|---|---|
| Sherlock | username | MIT | C | start/completion banner, result count, >50% of sites erroring; health check needs a known account on GitHub *and* GitLab |
| Maigret | username | MIT | C | completion line, ndjson count must match, >50% of sites erroring |
| Holehe | email | GPL-3.0 | B | "N websites checked" footer, >50% rate-limited. Always run with `--no-password-recovery` so the subject is never sent a reset flow |
| h8mail | email | BSD-3 | B (HIBP) – D (dump aggregators) | refuses to run without a breach API key; source errors with no findings = failure. Stores only that a credential leaked plus a fingerprint, never the password or hash |
| theHarvester | domain | GPL-2.0 | C | compares sources searched with exceptions logged (it writes a clean empty report even when every source failed) |
| crt.sh | domain | API | B | non-JSON 200 responses (error and bot-check pages) are failures |
| Amass | domain | Apache-2.0 | C | completion message, >50% of queried data sources failing |
| Brave Search | username, email, name, domain, phone | API (key) | D | non-search JSON (rate-limit/error bodies) is a failure; shown as "Not configured" without `UNMASK_BRAVE_API_KEY` |
| DuckDuckGo | username, email, name, domain, phone | API | C/D | official Instant Answer API only (summaries, not full web results); a non-JSON body is a failure |
| SpiderFoot | domain, IP | MIT | C/D | final "Scan completed with status FINISHED" (it exits 0 and prints `[]` on failed scans) |

Every entity also has a **Search ↗** menu: Google, Google Images, Bing, DuckDuckGo and
`site:` searches on LinkedIn, Reddit and Pastebin, pre-filled with the value and the
case's context tags. Image targets get reverse-image search (Google Lens, Yandex, Bing
Visual Search, TinEye). The analyst opens these links, not the platform, in a new tab
with no referrer.

Tools are pinned in `scripts/install-tools.sh`, which is also the tool manifest. Health checks
run each tool against a known-good target (or a reserved address that proves the run's
structure without probing a real person).

## Architecture

```
FastAPI (async) ── Jinja2 + htmx ── Cytoscape.js (graph tab only; both self-hosted, no CDN)
   │
   ├── app/adapters/     ToolAdapter contract + one module per tool (subprocess / API only)
   ├── app/services/     cases, scan orchestration, entities, tool health
   ├── app/models.py     full schema (SQLAlchemy 2.0), encrypted column types
   ├── app/crypto.py     Fernet encryption + HMAC blind index, key rotation
   └── migrations/       Alembic
   ├── app/jobs.py       dispatch: inline asyncio tasks (dev) or RQ priority queues
   ├── app/worker.py     RQ worker entrypoint
   └── app/throttle.py   per-tool concurrency limits shared by all workers (Redis leases)
PostgreSQL ── case data     Redis ── scan queues, tool slots, login rate limiting
```

**Scan flow.** Creating a case writes the investigation, its targets (plus a seed entity per
target) and scan run #1, then dispatches one job per *(target, enabled tool accepting that
target type)*. Jobs run concurrently within each tool's `max_concurrent` /
`delay_between_requests_ms` limits. Results are upserted by blind index, every sighting is
recorded in `entity_observations` (which powers diffing), and each discovery is linked to its
target with a `relation` carrying a plain-language `match_explanation`.

**Queues.** With `UNMASK_QUEUE=rq` (the Docker default) scans go to Redis and run on worker
services. Workers drain `unmask-high` (manual scans) before `unmask-default` (pivot chains)
and `unmask-low` (watch mode, health checks), so an analyst's scan never waits behind
background work. `tool_config.max_concurrent` is enforced across all workers with expiring
Redis leases. A run that dies with its worker is marked failed, never left "running". If no
worker is up, the dashboard and case page say so. `UNMASK_QUEUE=inline` runs scans inside
the web process for simple local development.

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
TOOLS_DIR=$PWD/.tools sh scripts/install-tools.sh   # one venv per tool, binaries in .tools/bin
export UNMASK_TOOLS_BIN=$PWD/.tools/bin
cp .env.example .env
python -m app.cli gen-keys                 # paste the output into .env
# set DATABASE_URL and UNMASK_ADMIN_EMAIL / UNMASK_ADMIN_PASSWORD in .env
alembic upgrade head
uvicorn app.main:app --reload
```

Scans run inline by default. To use the queue locally, set `UNMASK_QUEUE=rq` and start a
worker alongside the web app with `python -m app.worker`.

Open http://localhost:8000 and sign in with the bootstrap admin. Additional users:
`python -m app.cli create-user someone@example.com`.

### Tests

```bash
createdb unmask_test
TEST_DATABASE_URL=postgresql://localhost/unmask_test \
TEST_REDIS_URL=redis://localhost:6379/15 pytest      # Redis optional: skips queue tests
# Optional, for correlation pass 2 locally (CPU-only torch):
# pip install torch --index-url https://download.pytorch.org/whl/cpu && pip install -r requirements-ml.txt
ruff check . && ruff format --check .
```

Integration tests rebuild the schema from the migrations and use fake adapters, so they need
no network access. They cover the case gate, CSRF, login rate limiting, failure isolation,
soft-failure detection, the circuit breaker, per-owner access control, audit logging,
encryption at rest, correlation (synthetic near-duplicate fixtures that pin down what
may and may not merge, scoring, idempotence, analyst overrides), every adapter's parser and completion checks (from real captured output,
including fully blocked runs), the subprocess sandbox, and the RQ path with a real worker
process (priority order, crash handling, no-worker warning).

### Tool health

```bash
python -m app.cli health-check            # every tool
python -m app.cli health-check sherlock
```

Health checks run each tool against a known-good target and validate a content signature
(e.g. Sherlock must find the known account on GitHub *and* GitLab) — an HTTP 200 alone proves
nothing.

### Measuring accuracy

```bash
python -m app.cli eval identities.json --json results.json
```

Runs the username tools and web search against people whose accounts you know (your own, or
volunteers who agreed; the file must record that authorization) and reports each tool's
precision, recall and run time, before and after the profile-page check. Rerun it after any
change to tools, site lists or scoring. The file format is documented in `app/evaluation.py`.

Inside the app, every Confirm and "Not them" (with its reason) is counted per site. The Tools
page shows how often each score band, tool and site was right, and sites with a poor record count
for less in future scores. Username tools check a focused list of ~120 reliable sites by
default (`UNMASK_USERNAME_SITES=all` for everything they know).

## Deploying to Railway

1. **Create a project** and add the **PostgreSQL** and **Redis** plugins.
2. **Add a web service from this GitHub repo.** Railway picks up `railway.toml` and builds
   the `Dockerfile`; each push to the default branch redeploys. Migrations run on start and
   `/healthz` is the health check.
3. **Add a worker service from the same repo.** In its settings set the config-as-code path
   to `railway.worker.toml` (no HTTP health check) and add `UNMASK_ROLE=worker`. Give it the
   same variables as the web service. Start with one worker: each runs several tools at once,
   and tool limits are shared, so add workers only when queued scans wait too long for your
   plan's CPU and memory.
4. **Set variables on both app services** (not on the database):

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` (reference variable) |
   | `REDIS_URL` | `${{Redis.REDIS_URL}}` |
   | `SECRET_KEY`, `UNMASK_DATA_KEYS`, `UNMASK_INDEX_KEY` | from `python -m app.cli gen-keys` — see [Key management](#key-management) |
   | `UNMASK_ADMIN_EMAIL`, `UNMASK_ADMIN_PASSWORD` | bootstrap admin; remove after first login |
   | `PUBLIC_BASE_URL` | your public URL, e.g. `https://unmask.example.com` (canonical URLs, sitemap, Open Graph) |
   | `UNMASK_H8MAIL_KEYS` | optional breach API keys, e.g. `hibp=…` — h8mail stays "Not configured" without one |
   | `UNMASK_SERPER_KEY` (or `UNMASK_SERPAPI_KEY`, `UNMASK_GOOGLE_API_KEY` + `UNMASK_GOOGLE_CX`, `UNMASK_BRAVE_API_KEY`) | web search provider for the targeted searches and the Web tab; without one, web search stays "Not configured" |

5. **Generate a domain** for the web service.
6. **Backups.** The database holds irreplaceable case data. Enable Railway's Postgres
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
