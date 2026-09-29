"""Identity confidence scoring.

Confidence answers "does this belong to the subject?". It is built from:

* the adapter's **prior** for this kind of finding,
* **source reliability** (Admiralty A–F), which scales how far the prior is trusted,
* **independent sources**: each additional tool that saw the value,
* **cross-field corroboration**: links to other entities in the case
  (an email whose handle matches the username, a profile name matching the
  target's name, ...),
* **context-tag match**: how many of the case's context tags appear in the
  entity's own details,
* **page verification** (accounts only): a profile page that names the
  username counts as evidence; one that could not be checked (bot wall,
  login wall) weakens the prior instead.

Evidence is combined with a noisy-OR, so each piece raises confidence with
diminishing returns and no single weak signal can push a finding to certainty.
Analyst-supplied targets and analyst-confirmed entities are 1.0: a human
decision always outranks the score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

RELIABILITY_WEIGHT = {"A": 1.0, "B": 0.85, "C": 0.7, "D": 0.5, "E": 0.3, "F": 0.4}

EXTRA_SOURCE_WEIGHT = 0.2
CORROBORATION_WEIGHT = 0.25
MAX_CORROBORATIONS = 3
TAG_MATCH_WEIGHT = 0.3
VERIFIED_WEIGHT = 0.35
UNVERIFIED_FACTOR = 0.55


@dataclass
class Evidence:
    prior: float
    reliability: str
    sources: int
    corroborations: list[str] = field(default_factory=list)
    tag_match: float | None = None
    is_seed: bool = False
    confirmed: bool = False
    verification: str | None = None
    # Account hits: how distinctive the username is (None = not a username match).
    rarity: float | None = None
    rarity_note: str = ""
    # Account hits: this site's track record in past analyst decisions.
    site_factor: float = 1.0
    site_note: str | None = None


@dataclass
class Score:
    overall: float
    components: dict[str, float]
    explanation: list[str]


def score(ev: Evidence) -> Score:
    if ev.is_seed:
        return Score(1.0, {"evidence.override": 1.0}, ["analyst-supplied target"])
    model = _model_score(ev)
    if ev.confirmed:
        # The model's own estimate is kept so decisions can check the scores later.
        components = {**model.components, "evidence.override": 1.0, "evidence.model_score": model.overall}
        return Score(1.0, components, ["confirmed by analyst", *model.explanation])
    return model


def _model_score(ev: Evidence) -> Score:
    w = RELIABILITY_WEIGHT.get(ev.reliability, 0.4)
    # Reliability scales the prior between 60% and 100% of its value.
    base = max(0.0, min(1.0, ev.prior)) * (0.6 + 0.4 * w)
    explanation = [f"prior {ev.prior:.2f} from the source, weighted by reliability {ev.reliability} → {base:.2f}"]
    if ev.rarity is not None and ev.rarity < 1.0:
        base *= 0.5 + 0.5 * ev.rarity
        if ev.rarity_note:
            explanation.append(f"{ev.rarity_note} → {base:.2f}")
    if ev.site_factor != 1.0:
        base = min(0.95, base * ev.site_factor)
        explanation.append(f"{ev.site_note} → {base:.2f}")
    if ev.verification == "unverified":
        base *= UNVERIFIED_FACTOR
        explanation.append(f"profile page could not be checked, so the prior is reduced to {base:.2f}")
    residual = 1.0 - base
    if ev.verification == "verified":
        residual *= 1.0 - VERIFIED_WEIGHT
        explanation.append("profile page checked: it exists and names the username")

    extra = max(0, ev.sources - 1)
    for _ in range(extra):
        residual *= 1.0 - EXTRA_SOURCE_WEIGHT * w
    if extra:
        explanation.append(f"seen by {ev.sources} independent tools")

    corroborations = ev.corroborations[:MAX_CORROBORATIONS]
    for _ in corroborations:
        residual *= 1.0 - CORROBORATION_WEIGHT
    explanation.extend(f"corroborated: {c}" for c in corroborations)

    if ev.tag_match:
        residual *= 1.0 - TAG_MATCH_WEIGHT * ev.tag_match
        explanation.append(f"{ev.tag_match:.0%} of case context tags found in its details")

    overall = round(max(0.0, min(0.99, 1.0 - residual)), 4)
    components = {
        "evidence.prior": round(ev.prior, 4),
        "evidence.reliability_weight": w,
        "evidence.sources": float(ev.sources),
        "evidence.corroborations": float(len(corroborations)),
    }
    if ev.tag_match is not None:
        components["evidence.tag_match"] = round(ev.tag_match, 4)
    if ev.verification:
        components["evidence.verified"] = 1.0 if ev.verification == "verified" else 0.0
    if ev.rarity is not None:
        components["evidence.username_rarity"] = round(ev.rarity, 3)
    if ev.site_factor != 1.0:
        components["evidence.site_factor"] = round(ev.site_factor, 3)
    components["evidence.model_score"] = overall
    return Score(overall, components, explanation)


def tag_match_score(tags: list[str], text: str) -> float | None:
    """Share of context tags that appear (fuzzily) in an entity's own text."""
    from rapidfuzz import fuzz

    usable = [t.casefold().strip() for t in tags if len(t.strip()) >= 3]
    if not usable:
        return None
    haystack = text.casefold()
    if not haystack.strip():
        return 0.0
    hits = sum(1 for t in usable if t in haystack or fuzz.partial_ratio(t, haystack) >= 90)
    return hits / len(usable)
