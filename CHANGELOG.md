# Changelog

## 2026-10 — easier to use, open source

- **Open source** under the MIT licence (`LICENSE`).
- **Three domain sources**, which run only on a domain (a domain target, or one a scan finds),
  never on shared mail or platform domains:
  - **Subfinder**: passive subdomain discovery. A run where most of its sources failed is refused
    rather than read as "no subdomains". `scripts/install-tools.sh` installs a checksummed release.
  - **DNS records** (DNS-over-HTTPS): addresses, mail and name servers, SPF and DMARC, and the
    services the records name (mail providers, verified tools).
  - **urlscan.io**: hostnames and hosting seen in public scans. Works without a key;
    `UNMASK_URLSCAN_KEY` raises the limits.
- **The analyst assessment is encrypted at rest**, like the rest of a case's content. Migration
  0017 encrypts existing assessments (it needs `UNMASK_DATA_KEYS`, as the app does).
- **Case navigation:** four sections (Findings, Graph, Log, Report) with their pages as sub-tabs,
  and Settings behind a gear. Every existing URL still works.
- **Report tab:** the assessment, downloads and share links in one place. "Prepare to send" makes
  a read-only link, the PDF and a message to paste into an email in one step.
- **Reasons in words** on every finding row, with the main reason against when there is one.
- **Review:** a "Review N undecided" button in Findings; each card shows progress and the finding's
  reason in one line; on a phone the decisions sit in a fixed bar of thumb-sized buttons.
- **Landing page rebuilt:** a responsible-use band at the top, the method as five steps, reports and
  outputs, measured accuracy, the authorisation record, and fresh screenshots that follow the light
  and dark themes. Motion is subtle, only below the fold, and off for anyone who prefers reduced motion.

## 2026-10 — investigation workflow

Schema: migrations 0014–0016 (webhooks; working log notes; imported findings).

- **Reports in every format.** Settings › Download the report: PDF, Word, HTML, Markdown, raw data
  (text) and the evidence bundle; pick several to get one ZIP with a SHA-256 list. Laid out for
  decision makers (summary), investigators (findings, connections) and legal/audit (method,
  authorisation, evidence), with TLP:AMBER and a reference on every page and a Brief option.
  Also `GET /api/v1/cases/{id}/report`.
- **Evidence bundle** (ZIP) with a verifiable manifest; **signed webhooks** for `scan.finished` and
  `watch.changes`; **audit log export** (CSV, JSONL, API).
- **Faster scans:** bounded parallel jobs, coalesced rescoring; platform errors no longer count
  against a tool.
- **Case timeline:** "since you last looked" strip, `?since=` on findings, new findings marked in the
  graph, and an "As of" slider that replays the case scan by scan.
- **Lab:** offline replay of page verification; pivots ranked by expected value; skipped pivots can
  be retried from the Pivot Log.
- **Working log:** case-level entries, pinned findings and links, and a draft assessment laid out
  from them.
- **Import** from STIX 2.1 or an UNMASK export: checked before anything is written, marked
  imported and never observed, links that never raise a score.
- **Workspace:** score breakdown on hover, compact tables, graph full screen, copy a finding as a
  citation.

## 2026-10 — overhaul

Driven by the audit in [docs/audit/2026-10-overhaul-audit.md](docs/audit/2026-10-overhaul-audit.md).
Schema: migrations 0010–0013 (see README › Upgrading and rolling back).

### Security and correctness
- Profile verification checks every redirect hop against the SSRF guard.
- Misuse limits: 25 targets per case; daily per-account target and scan quotas, audited when hit;
  authorisation notes must say who, why and a reference.
- Stuck runs are reaped by the scheduler, and a run that can't be queued fails with the reason,
  so neither blocks a case's next scan or its retention purge.
- No duplicate scan runs from concurrent requests; accepting a stale suggestion can't corrupt the merge tree.
- Sessions have an absolute lifetime and a per-user epoch: signing out ends every session.
- The client address comes from the trusted proxy hop, not the spoofable left of `X-Forwarded-For`.
- Retention, watch mode and auto-pivot are owner-only; health checks are admin-only; data exports
  need the analyst assessment; tool-supplied links are http(s)/mailto only; the alert webhook URL
  is no longer logged.

### Identity resolution (measured by the new Identity Resolution Lab)
- Corroboration is weighted by how much the other end is believed; another person's accounts no
  longer vouch for each other. A page naming someone else lowers the score; an unanchored common
  handle is capped at 0.50; a finding's own discovery edge no longer corroborates it.
- National phone numbers keep their leading zero; name order is kept (reordered names are suggestions).
- Verification ignores the canonical link and rejects pages whose body says the profile doesn't exist.
- Result on 271 labelled findings: precision at "Likely" 0.835 → 0.992, false merges 10 → 0.

### Evidence and provenance
- Relations record their basis (observed, rule, similarity, analyst), direction, first/last seen and count.
- Observations record what the tool reported, the source page, the finding searched from and the source grade.
- Findings show a provenance chain; hand-added findings say who added them.

### Graph workspace
- Rings, force (fCoSE), tree and groups layouts; filters by strength, link kind, type, source, score
  and date that never re-run the layout; multi-select, expand, isolate, hide, collapse, bulk decisions;
  search with `type:`/`tool:`/`site:`/`is:`; undo/redo; remembered view; inspector for findings, links
  and selections; minimap; PNG and JSON export; keyboard navigation.
- Evidence-weighted path analysis between two findings, with weakest links and warnings.
- 1,500-finding graphs are interactive in about 3 s (previous force layout: ~9 s at 500).

### Product
- Design system: paper and ink, IBM Plex, one highlighter accent, square corners; light and dark.
- Compact case header; Home that starts from templates; landing page rewritten as a case file with
  real screenshots and measured, reproducible claims.
- Tools page: how each source behaved over 30 days.
- Larger, more realistic sample case.
- API v1 with scoped, hashed, expiring keys; Python client in `clients/python/`.

### Tooling
- `python -m app.cli lab` (Identity Lab), `scripts/graphbench.py` (graph performance).
- Tests: 304 → 345.
