# UNMASK overhaul — Phase 1 audit and baseline (October 2026)

This is the independent audit that drove the overhaul. Each finding was verified
against the code (file:line references are to the pre-overhaul tree, commit `422d44b`).
Specialist reviews ran in parallel: principal engineer (A), OSINT / identity
resolution (B), graph and visualisation (C), product design (D), positioning and
business (E+F), security and production readiness (G).

## Baseline

| Check | Result |
|---|---|
| Test suite | **304 passed** (114 s) against Postgres 16 + Redis |
| Lint | `ruff check .` clean |
| Migrations | `alembic check` — no drift between models and head (0009) |
| App | runs locally (`UNMASK_QUEUE=inline`); every screen renders; one 404 for an `/entities` sub-resource during navigation |
| Graph | Cytoscape 3.30.4, two layouts (radial preset, cose), 400-node trim, no edge inspector, no path finding, no multi-select |

Baseline screenshots (1440×900 and 390×844) were captured for every screen and
reviewed before any change.

## The ten most serious weaknesses

1. **A stuck run can block a case forever, including its retention purge** (A).
   Runs are committed then enqueued with no rollback on enqueue failure
   (`routes/cases.py:291-297`, `services/scans.py:510`); dead runs are reaped only at
   process start (`main.py:79-86`), never in the scheduler tick. While a run sits in
   `queued`/`running`, new scans return the stale run, watch mode skips the case and
   **retention purge skips it** (`scheduler.py:343-347`) — a compliance failure.
2. **SSRF in profile verification** (A, G). `verify.py:334-349` fetches URLs taken from
   tool output with `follow_redirects=True` and never calls `safefetch.check_url`, unlike
   snapshots, which are properly guarded.
3. **"Verified" can mean a soft-404 that echoes the username** (B). The not-found body
   check runs after the title/description/**canonical** match (`verify.py:252-274`), and
   `verified` adds a large weight to the score (`scoring.py:89-91`).
4. **Correlation is presented as identity** (B). The score measures existence plus
   coincidence: a handle like `john` on two username tools with a matching display name
   scores 0.72 → "Likely", which feeds the headline "Likely the same person on N sites".
   Rarity only damps the base prior; boosts compound afterwards; evidence *against*
   (name mismatch, "common username") is shown in the UI but never lowers the score.
5. **Coherence counts as attribution** (B). Corroboration counts any corroborating
   relation equally regardless of the other endpoint's confidence (`engine.py:476-485`),
   so two decoy accounts that link to each other lift each other; h8mail's own
   `breach_associated` edge "corroborates" the record it came from.
6. **Optimistic merges** (B). On merge `confirmed_flag` is OR'd and reliability takes
   the best letter (`engine.py:147-150`); phone canonicalisation strips leading zeros
   without a country code, so national numbers from different countries auto-merge
   (`normalize.py:51`); name canonicalisation sorts tokens, so "Chan Yan" = "Yan Chan".
7. **Relations have no direction, no uniqueness, no temporal or evidence record** (A, B).
   Pairs are UUID-sorted (`engine.py:82`), STIX exports everything as `related-to`,
   relations carry only `created_at`, and nothing links an edge to the observation,
   page or rule that produced it. This blocks path analysis and provenance.
8. **Unbounded fan-out and full-case correlation under the case lock after every job**
   (A, `scans.py:413-452`); DB pool exhaustion is counted against tools' circuit
   breakers (`scans.py:423-426`).
9. **Races** (A): duplicate scan runs from concurrent POSTs (`routes/cases.py:459`),
   `cancel_scan_run` overwrites concurrent job outcomes, `accept_suggestion` does not
   check `merged_into_id` and can corrupt the merge tree (`routes/correlation.py:215`).
10. **The graph is a picture, not a workspace** (C, D). No edge/evidence inspector, no
    path analysis, no multi-select or bulk actions, no isolate/collapse/undo, filters
    limited to four toggles, six saturated colours with eleven shapes and no
    legend-by-default, and the case header pushes the canvas below the fold (on phones
    it is entirely off-screen).

## The ten highest-value improvements

1. Reap stuck runs in the scheduler with a heartbeat; never let an active run block a purge.
2. SSRF-guard every outbound fetch (one checked transport).
3. Fix the verification order and stop matching on `canonical`.
4. Make the score evidence-aware: negative evidence lowers it; corroboration is
   weighted by the other endpoint; common handles are capped without an anchor.
5. Relation provenance: first/last seen, seen count, evidence basis
   (observed / rule / similarity / analyst), and per-relation observations.
6. **Evidence-weighted path analysis** between any two entities, explaining the weakest
   link and separating observed from inferred hops.
7. **Graph workspace**: inspector for nodes *and* edges, filters by type / source /
   confidence / relation / basis, multi-select, isolate, expand, hide, undo, layouts that
   don't reshuffle on every filter, path highlighting, subgraph export.
8. **Identity Resolution Lab**: an offline, labelled synthetic benchmark with precision,
   recall, false-merge gate and calibration (Brier, ECE), run in CI.
9. A cohesive design system and a compact case header so the work surface leads.
10. A versioned, read-only JSON API with scoped, hashed API keys and audit logging.

## Works well — must not regress

- Encryption at rest (Fernet, MultiFernet rotation) with HMAC blind-index lookups.
- The case gate: authorisation note and lawful basis, enforced in UI, service and a DB `CHECK`.
- Terms gate, CSRF on every POST, strict CSP with self-hosted scripts, `no-store` and
  `X-Robots-Tag` on private pages, gzip on static only (BREACH).
- Case isolation through `get_case_for_user` on every case route; share links store a
  token hash and expire; snapshots are SSRF-checked, SHA-256 re-verified, never rendered.
- Honest failures: `SignatureMismatch`, per-job isolation, circuit breaker that a human
  override beats, "not a real disappearance" in diffs.
- Only canonical-identical values auto-merge; analyst `same`/`not same` is never overridden.
- Pivot depth and budget caps, no duplicate inputs, logged skip reasons.
- Memory controls (subprocess caps, process slots, idle wind-down).
- The access log survives case deletion; retention purges are enforced.

## Incomplete or misleading

- The `image` target type is accepted but no adapter takes it (runs end with zero jobs).
- `last_verified` is bumped on any sighting and exported as `last_seen`.
- Similarity ratios and cosine scores are stored and shown as relation "confidence".
- Skipped pivots (budget/depth/disabled tool) are suppressed forever, never retried.
- Domain pivots fire at confidence 0.0, so an employer domain from an email triggers
  infrastructure enumeration.
- README phases 9–10 (GHunt, PhoneInfoga, AI synthesis) are not built.
- `evaluation.py` is a live, network-dependent smoke test of tools only; it never
  exercises correlation, scoring or thresholds.

## Design review (D)

- The visual language is calm but generic (pastel mint, filled grey inputs, emerald
  plus sky gradient); it does not read as a professional intelligence tool.
- Information hierarchy on the case page: breadcrumb, title, target tags, sample banner,
  run strip and tabs take ~300 px before any content.
- The graph uses saturated hues on eleven shapes; type is double-encoded but strength
  and confirmation fight for the same border channel; labels only at zoom ≥ 1.25.
- Two display faces (Sora + Inter) add weight without adding hierarchy.
- Mobile: the graph canvas starts below the first screen.

## Positioning (E+F)

- **Primary audience:** corporate security and investigations teams (insider risk,
  fraud, trust and safety, brand impersonation, executive protection), 2–15 analysts,
  who answer to legal, HR and a DPO. The gate, audit log, retention and
  assessment-gated reports are exactly what they must show; enterprise CTI suites price
  them out; self-hosting keeps subject data off third-party SaaS.
- **Secondary:** due-diligence / vendor-vetting firms (the report and method are the
  product) and pentest / red-team external recon (the domain chain plus STIX).
- **Not targeted:** consumer people-search (excluded by the AUP) and journalists
  (price-sensitive, served free elsewhere).
- **Value proposition:** *Investigations you can defend* — every finding explained,
  every step on the record, every byte on your infrastructure.
- **Gaps for paid adoption:** SSO/MFA and roles, an approver workflow, audit-log export,
  a source-health view, and a chain-of-custody evidence bundle.
- Competitor prices gathered from third-party sources disagree; none are quoted in the
  product.

## Roadmap (as executed)

| Phase | Scope |
|---|---|
| 1 | This audit; baseline; screenshots |
| 1b | Release-blocking fixes: SSRF in verification, stuck-run reaping, races, verification order |
| 2 | Design system: tokens, type, components, compact case header |
| 3 | Graph workspace (inspector, filters, paths, selection, isolate, undo, export, perf) |
| 4 | Relation provenance and temporal fields; path analysis; scoring fixes; Identity Lab; source health |
| 5 | Every screen in the new system; landing page and onboarding |
| 6 | Public API v1 with scoped keys |
| 7 | QA: tests, lint, security checks, performance, docs |

The security (G) and graph (C) appendices follow.

## Appendix G — security and production readiness

`pip-audit -r requirements.txt`: no known vulnerabilities. `ruff --select S`: 12 hits,
all `assert` type-narrowing or the benchmark script. No Critical findings.

| Sev | Finding | Where | Fix (status at end of overhaul in the changelog) |
|---|---|---|---|
| High | No cap on targets per case, nor on cases/scans per user: one request can profile thousands of people | `routes/cases.py:228`, `services/cases.py:84`, `identifiers.py:35` | Per-case target cap; per-user daily target and scan quotas; audited `quota_exceeded` |
| Med | `--forwarded-allow-ips *` makes `X-Forwarded-For` client-controlled (login limiter bypass, forged audit IPs) | `scripts/start.sh:22` | Default to the platform proxy; preflight refuses `*` in production unless explicitly acknowledged |
| Med | Cookie sessions can't be revoked and slide forever | `main.py:116`, `routes/auth.py:262` | Absolute lifetime (issued-at) and a per-user session version bumped on logout and "sign out everywhere" |
| Med | Profile verification follows redirects without the SSRF guard | `verify.py:334-351` | Check every hop with `safefetch.check_url` |
| Med | CSV / JSON / STIX exports skip the assessment gate | `routes/evidence.py:132` | Same gate as reports |
| Med | Collaborators can change retention (incl. `permanently_active`), watch, pivots and the assessment | `routes/settings.py:343-417`, `watch.py:66`, `pivots.py:79` | Owner-only |
| Low | Alert webhook URL (a secret) logged in exceptions | `alerts.py:31` | Log class and status only |
| Low | Non-admins can trigger tool health checks and view the integrations page | `routes/cases.py:151`, `routes/integrations.py:62` | Admin-only |
| Low | Tool-supplied URLs rendered as `href` without a scheme check | `_entity_row.html:16` and others | `safe_url` filter (http/https only) |
| Low | Authorisation note accepts "x" | `services/cases.py:80` | Minimum length |
| Low | Per-email lockout lets anyone lock a known user out; limiter never re-probes Redis | `security.py:72-87` | Re-probe periodically |
| Low | Snapshot size per case unbounded; global search decrypts every entity per keystroke | `services/search.py:45` | Limits and debounce |
| Low | Base image not pinned by digest; some requirements unpinned | `Dockerfile`, `requirements.txt` | Pin |

Done well and preserved: case isolation on every route (all handlers checked),
CSRF on all 50+ POSTs, argon2 with dummy-hash timing, safe `next` redirects, SSRF-safe
snapshot fetcher, subprocesses without a shell and with scrubbed env and `--` separators,
autoescaping with no `|safe`, sandboxed raw snapshot downloads, strict CSP, 256-bit
hashed share-link tokens, CSV formula neutralisation, startup refusal of weak keys.
