# Identity Resolution Lab

`python -m app.cli lab [--cases ground-truth.json] [-n 40] [--json out.json] [--baseline docs/lab/baseline.json]`

The lab measures what UNMASK *concludes* from tool output: which findings it scores as the
subject's, what it merges, and whether a score means what it says. It runs the real
pipeline (persist, correlate, rescore) inside a transaction that is rolled back, so it needs
no network and leaves nothing behind. `tests/test_lab.py` runs it on every test run.

Cases come from a deterministic generator (`app/lab.py`) built around the ways identity
resolution goes wrong, or from a JSON file of **consented** ground truth in the same shape.

| Trap | What it is |
|---|---|
| namesake_handle | the same handle on a site, held by someone else |
| soft404 | a page that echoes any username and names nobody |
| mutual_decoys | two accounts of another person that link to each other |
| common_handle | a common handle: most sites holding it belong to other people |
| namesake_name | a web page about someone with the same name |
| phone_country | a foreign number that matched only once its country code was ignored |
| name_order | a different person whose name has the same words in another order |

## October 2026: before and after

Same 40 synthetic cases, 271 labelled findings (74% the subject's).
`baseline-before.json` is the engine as audited; `baseline.json` is after the fixes.

| Metric | Before | After |
|---|---|---|
| Precision at *Likely* (≥ 0.70) | 0.835 (24 false positives) | **0.992** (1) |
| Recall at *Likely* | 0.602 | 0.602 |
| Precision at *Possible* (≥ 0.45) | 0.716 | 0.861 |
| **False merges** | **10** | **0** |
| Brier score | 0.236 | 0.175 |
| Expected calibration error | 0.302 | 0.323 |

| Trap (wrong side of *Likely*) | Before | After |
|---|---|---|
| mutual_decoys | 12 / 12 | 0 / 12 |
| phone_country (false merges) | 5 / 5 | 0 / 5 |
| name_order (false merges) | 5 / 5 | 0 / 5 |
| namesake_handle | 1 / 6 | 0 / 6 |
| soft404 | 1 / 6 | 1 / 6 * |

What changed, and why:

1. **Corroboration is weighted by the other end.** A link to a target or a confirmed
   finding counts fully; a link to another unconfirmed finding counts only as much as that
   finding is believed on its own (two-pass rescoring). Decoys no longer vouch for each other.
2. **Evidence against lowers the score.** A checked page that names somebody else keeps
   35% of its prior. A common handle with nothing tying it to the subject is capped at 0.50.
3. **A finding's own discovery edge is not corroboration** (h8mail's breach record no longer
   "corroborates" itself).
4. **Canonical forms only merge what is certainly the same identifier.** National phone
   numbers keep their leading zero (London `020…` ≠ Cairo `+20…`); name order is kept,
   except the unambiguous "Last, First". Same-words-different-order names are *suggested*.
5. **Verification** no longer accepts the canonical link as proof, and a page whose body says
   the profile does not exist is rejected even if its title echoes the username
   (`tests/test_verify.py`).

\* The lab hands the scorer pre-verified pages, so it cannot see fix 5; the remaining soft-404
false positive is caught by the verifier, which has its own tests.

## Reading the numbers honestly

- Recall at *Likely* stays at 0.60 on purpose: the subject's login-walled accounts (40 of 201
  subject findings) score about 0.24 because nothing on them could be checked, and their
  email registrations sit at the adapter's prior. Raising those would mean claiming evidence
  the platform does not have.
- Calibration error is high because the score is deliberately conservative where evidence
  is missing. No calibration map is fitted to synthetic data: that would make the numbers
  look better without making them truer. Fit one only against consented real ground truth
  (`--cases`), and version it.
- Synthetic cases test the logic, not the world. A score is evidence about attribution,
  never proof of identity.
