# Graph workspace

The Graph tab is an investigation surface, not a picture. Everything in it changes the
**view** only (hide, isolate, collapse, filters, layout) and can be undone; decisions
(*Same person*, *Not them*) go through the same audited endpoints as the Entities tab.

## Reading it

| Mark | Meaning |
|---|---|
| Filled ink circle | A target |
| Glyph and ring colour | Entity type (the glyph means colour is never the only cue) |
| Green ring | Confirmed by an analyst |
| Dashed ring / dotted ring, faded | Possible / weak or page not checked |
| Solid line, arrow | **Observed**: a tool reported it, or a fetched page shows it (arrow: found from) |
| Darker solid line | **Rule match**: same handle, address at a domain. Links values, not people |
| Dashed line | **Similarity**: values look alike above a threshold. Suggests, never establishes |
| Heavy ink line | **Analyst**: a person decided it |
| Dotted amber line | Possible duplicate nobody has reviewed |
| Yellow halo | Selected, or a search match |

Click a link to see every relation behind it: which tool or rule produced it, the
explanation, confidence (called *similarity* where it is one), first and last seen and
how often. Inferred links carry an explicit caveat.

## Working it

- **Layouts**: Rings (targets centre, stronger findings closer), Force (fCoSE), Tree
  (each finding under what it was found from), Groups (blocks by type). Filters never
  re-run the layout; *Re-layout* does, on what is shown.
- **Select** with click, Shift-click, Shift-drag. **Expand** (E) shows hidden links,
  **Isolate** (I) keeps the selection and its direct links, **Hide** (H), **Collapse**
  folds findings that hang only off one node.
- **Find**: free text, or `type:email`, `tool:sherlock`, `site:github`, `is:confirmed`.
  Enter steps through matches.
- **Paths** (P, with two selected): the strongest evidence paths between them.
- **Undo/redo**: Ctrl+Z / Ctrl+Shift+Z for every view change. The view (layout,
  positions, hides, filters) is remembered per case in this browser only.
- **Keyboard**: arrows move between linked findings, Enter opens one, Esc clears.
- **Export**: PNG of the view or of everything shown; JSON of the visible subgraph with
  its evidence. Full case exports (CSV, JSON, STIX) are in Settings.

## Path ranking

`app/services/paths.py`. Each link's weight comes from how it was established
(analyst 1.0, observed 0.9, rule 0.75, similarity 0.45; ×0.6 for an unreviewed
duplicate) times `0.5 + 0.5 × confidence`. Each intermediate finding is discounted by
`√belief × log₂4 / log₂(2 + degree)`, so shared providers and common names cannot carry a
strong path; targets are exempt (they connect to everything by construction). Every
extra hop costs ×0.85. Yen's algorithm returns the top five paths for this score, each
with its weakest link, observed vs inferred counts, and warnings (long chain, hub,
similarity, unreviewed duplicate). The score is association strength through the
evidence, never identity, and the UI says so.

## Performance

Measured with `scripts/graphbench.py` (synthetic cases: 3 targets, 4 hubs, ~1.4 links per
finding, mixed link kinds) in headless Chromium on a 4-vCPU container without a GPU.
"Ready" is navigation to an interactive graph, including the request.

| Findings / links | graph.json | Ready | Force | Rings | Filter | Select 5 | Paths |
|---|---|---|---|---|---|---|---|
| 200 / 276 | 105 ms | 0.8 s | 0.56 s* | 0.44 s* | 6 ms | 79 ms | 72 ms |
| 600 / 837 | 244 ms | 1.6 s | 0.30 s | 0.13 s | 12 ms | 97 ms | 153 ms |
| 1500 / 2096 | 0.5–0.8 s | 2.9–3.3 s | 0.47 s | 0.12 s | 28 ms | 248 ms | 410 ms |

\* animated below 400 findings; the time is mostly the animation.

Before the rewrite the force layout (CoSE, 1,500 iterations) took about 9 s at 500
findings and 154 s at 2,000 (headless measurement), and every filter re-ran it.
Above 600 findings the canvas switches to straight edges, textured panning and no hover
fading; above 2,500 it renders at device pixel ratio 1. Graphs over 1,500 findings open
with the weakest left out (the status line offers to load them).
