# Changelog

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
