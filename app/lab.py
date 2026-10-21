"""Identity Resolution Lab: measure correlation and scoring against labelled ground truth.

``app/evaluation.py`` measures the *tools* against live sites. The lab measures what the
platform itself concludes from what the tools return: which findings it scores as
belonging to the subject, what it merges, and whether its scores mean what they say.

It runs the real pipeline (persist findings, correlate, rescore) inside a transaction
that is rolled back, so it leaves nothing behind and needs no network. Cases come from a
deterministic synthetic generator built around the ways identity resolution goes wrong
(``TRAPS``), or from a JSON file of consented ground truth in the same shape.

Metrics, for findings labelled "subject" (positive) or not:

* precision and recall at the *Likely* and *Possible* thresholds,
* false merges: two values the engine merged that belong to different people (must be 0),
* calibration: Brier score and expected calibration error (10 equal-width bins),
* a per-trap breakdown, so a regression names the failure it reintroduced.

A score is evidence about attribution, never proof; the lab exists to keep it honest.
"""

from __future__ import annotations

import json
import random
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.adapters.base import EntityCandidate

TRAPS = {
    "baseline": "the subject's own accounts and records",
    "namesake_handle": "the same handle on a site, held by someone else",
    "soft404": "a page that echoes any username and names nobody",
    "mutual_decoys": "two accounts of another person that link to each other",
    "common_handle": "a common handle: most sites holding it belong to other people",
    "namesake_name": "a web page about someone with the same name",
    "phone_country": "a foreign number that only matches without its country code",
    "name_order": "a different person whose name has the same words in another order",
}

CITIES = ["Lisbon", "Leeds", "Osaka", "Tucson", "Ghent", "Perth", "Cork", "Bergen", "Quito", "Brno"]
JOBS = ["nurse", "architect", "welder", "teacher", "chemist", "pilot", "baker", "editor", "surveyor", "luthier"]
FIRST = ["Mara", "Tomas", "Ines", "Kofi", "Hana", "Ravi", "Lena", "Owen", "Sana", "Pavel", "Noor", "Ezra"]
LAST = ["Okafor", "Lindqvist", "Moreau", "Tanaka", "Haddad", "Novak", "Quist", "Varga", "Ibarra", "Coelho"]
COMMON = ["alex", "john", "maria", "sam"]


@dataclass
class Finding:
    key: str
    tool: str
    parent: str  # a seed type ("username", "email", "name", "phone")
    type: str
    value: str
    attributes: dict
    reliability: str
    prior: float
    relation_type: str
    why: str
    truth: str  # "subject" | "other"
    trap: str = "baseline"


@dataclass
class LabCase:
    name: str
    seeds: dict[str, str]
    tags: list[str]
    findings: list[Finding] = field(default_factory=list)


def _account(
    case: LabCase, rng, key, site, handle, title, about, truth, trap, *, verified=True, links=None, prior=None
):
    url = f"https://{site}.lab.example/{handle}"
    reason = "profile page names the username in its title" if verified else "login wall"
    attrs = {"site": f"{site} (lab)", "url": url, "username": handle,
             "verification": "verified" if verified else "unverified", "verification_reason": reason}  # fmt: skip
    if verified:
        attrs["preview"] = {"title": title, "username": handle, "description": about, "matched_in": ["title"]}
        if links:
            attrs["preview"]["links"] = links
    tool = rng.choice(["sherlock", "maigret"])
    p = rng.uniform(0.45, 0.65)
    case.findings.append(Finding(key, tool, "username", "account", url, attrs, "C", round(p, 2), "has_account",
                                 "same username", truth, trap))  # fmt: skip
    return url


def generate(n: int = 40, seed: int = 20261021) -> list[LabCase]:
    """Deterministic synthetic investigations, each built around one or two traps."""
    rng = random.Random(seed)  # noqa: S311 — reproducible test data, not security
    cases = []
    for i in range(n):
        first, last = FIRST[i % len(FIRST)], LAST[(i * 7) % len(LAST)]
        city, job = CITIES[i % len(CITIES)], JOBS[(i * 3) % len(JOBS)]
        trap = list(TRAPS)[1 + i % (len(TRAPS) - 1)]
        handle = rng.choice(COMMON) if trap == "common_handle" else f"{first.lower()}{last.lower()}{i}"
        name = f"{first} {last}"
        seeds = {"username": handle, "email": f"{first.lower()}.{last.lower()}{i}@mail.lab.example", "name": name}
        case = LabCase(f"lab-{i:03d}-{trap}", seeds, [city.lower(), job])
        # The subject: two to four checked profiles that name them and their context.
        for k in range(rng.randint(2, 4)):
            _account(case, rng, f"s{k}", f"site{k}", handle, f"{name} ({handle})", f"{job.title()} in {city}.",
                     "subject", "baseline")  # fmt: skip
        _account(case, rng, "s-wall", "wall", handle, "", "", "subject", "baseline", verified=False)
        case.findings.append(Finding("s-reg", "holehe", "email", "registration", f"Forum {i} (lab)",
                                     {"site": f"Forum {i} (lab)", "email": seeds["email"]}, "B", 0.7,
                                     "registered_on", "email is registered", "subject"))  # fmt: skip
        other_first, other_last = FIRST[(i + 5) % len(FIRST)], LAST[(i + 3) % len(LAST)]
        other_city = CITIES[(i + 4) % len(CITIES)]
        if trap == "namesake_handle":
            _account(case, rng, "t-namesake", "trapsite", handle, f"{other_first} {other_last} ({handle})",
                     f"Gardener in {other_city}.", "other", trap)  # fmt: skip
        elif trap == "soft404":
            _account(case, rng, "t-echo", "echo", handle, handle, "", "other", trap)
        elif trap == "mutual_decoys":
            a = f"https://decoya.lab.example/{handle}"
            b = f"https://decoyb.lab.example/{handle}"
            _account(case, rng, "t-decoy-a", "decoya", handle, f"{other_first} {other_last} ({handle})",
                     f"Cyclist in {other_city}.", "other", trap, links=[b])  # fmt: skip
            _account(case, rng, "t-decoy-b", "decoyb", handle, f"{other_first} {other_last} ({handle})",
                     f"Cyclist in {other_city}.", "other", trap, links=[a])  # fmt: skip
        elif trap == "common_handle":
            for k in range(5):
                nf, nl = FIRST[(i + k + 2) % len(FIRST)], LAST[(i + k + 6) % len(LAST)]
                _account(case, rng, f"t-common-{k}", f"popular{k}", handle, f"{nf} {nl} ({handle})",
                         f"{JOBS[k].title()} in {CITIES[(i + k + 1) % len(CITIES)]}.", "other", trap)  # fmt: skip
        elif trap == "namesake_name":
            case.findings.append(Finding("t-page", "websearch", "name", "web_mention",
                                         f"https://news.lab.example/{i}/{last.lower()}",
                                         {"url": f"https://news.lab.example/{i}/{last.lower()}",
                                          "title": f"{name}, {other_city} councillor",
                                          "snippet": f"{name} has served {other_city} since 2009…"},
                                         "D", 0.5, "mentioned_in", "search result names the subject",
                                         "other", trap))  # fmt: skip
        elif trap == "phone_country":
            seeds["phone"] = "020 7946 0" + f"{i:03d}"
            case.findings.append(Finding("t-phone", "numverify", "phone", "phone", "+20 7946 0" + f"{i:03d}",
                                         {"country": "EG"}, "C", 0.5, "related_number", "carrier lookup",
                                         "other", trap))  # fmt: skip
        elif trap == "name_order":
            case.findings.append(Finding("t-order", "websearch", "name", "name", f"{last} {first}",
                                         {"source": "directory listing"}, "D", 0.45, "mentioned_as",
                                         "a directory lists this name", "other", trap))  # fmt: skip
        cases.append(case)
    return cases


def load(path: str | Path) -> list[LabCase]:
    """Ground truth in the generator's shape: [{"name", "seeds", "tags", "findings": [...]}]."""
    raw = json.loads(Path(path).read_text())
    return [LabCase(c["name"], c["seeds"], c.get("tags", []), [Finding(**f) for f in c["findings"]]) for c in raw]


# --- Running ------------------------------------------------------------------------------------


@dataclass
class Outcome:
    case: str
    key: str
    trap: str
    truth: str
    score: float
    merged_with: str | None = None


async def run(session: AsyncSession, cases: list[LabCase]) -> list[Outcome]:
    """Run the real pipeline on each case and read back the scores. Rolls everything back."""
    from datetime import UTC, datetime

    from app.correlation.engine import correlate_case
    from app.models import Entity, ScanRun, User
    from app.services.cases import TargetInput, create_case
    from app.services.scans import persist_candidates

    outcomes: list[Outcome] = []
    owner = User(email=f"lab-{uuid.uuid4().hex[:8]}@lab.invalid", password_hash="!", is_admin=False)  # noqa: S106 — not a credential; no password can match "!"
    session.add(owner)
    await session.flush()
    try:
        for c in cases:
            case = await create_case(
                session, owner=owner, name=c.name, lawful_basis_confirmed=True, disabled_tools=[],
                authorization_note="Identity Resolution Lab: synthetic data, rolled back after measuring.",
                targets=[TargetInput(v, t, list(c.tags)) for t, v in c.seeds.items()],
            )  # fmt: skip
            now = datetime.now(UTC)
            run_ = ScanRun(case_id=case.id, run_number=1, status="completed", triggered_by="manual",
                           started_at=now, completed_at=now)  # fmt: skip
            session.add(run_)
            await session.flush()
            seeds = {
                e.type: e
                for e in (await session.scalars(select(Entity).where(Entity.case_id == case.id, Entity.is_seed))).all()
            }
            by_tool: dict[tuple[str, str], list[EntityCandidate]] = defaultdict(list)
            for f in c.findings:
                by_tool[(f.tool, f.parent)].append(
                    EntityCandidate(
                        f.type,
                        f.value,
                        dict(f.attributes),
                        f.reliability,
                        f.prior,
                        {"value": f.prior},
                        f.relation_type,
                        f.why,
                    )  # fmt: skip
                )
            for (tool, parent), cands in by_tool.items():
                await persist_candidates(session, run=run_, parent=seeds[parent], tool=tool, candidates=cands)
            await session.flush()
            await correlate_case(session, case.id, semantic=False)
            await session.flush()
            entities = (await session.scalars(select(Entity).where(Entity.case_id == case.id))).all()
            by_digest = {(e.type, e.value_digest): e for e in entities}
            by_id = {e.id: e for e in entities}
            seed_ids = {e.id: t for t, e in seeds.items()}
            for f in c.findings:
                e = by_digest.get((f.type, crypto.digest(f.type, f.value)))
                if e is None:
                    continue
                survivor = by_id.get(e.merged_into_id) if e.merged_into_id else e
                merged = None
                if e.merged_into_id:
                    merged = seed_ids.get(e.merged_into_id) or str(e.merged_into_id)
                outcomes.append(Outcome(c.name, f.key, f.trap, f.truth, round(survivor.confidence, 4), merged))
    finally:
        await session.rollback()
    return outcomes


# --- Metrics ------------------------------------------------------------------------------------


def _pr(outcomes: list[Outcome], threshold: float) -> dict:
    tp = sum(1 for o in outcomes if o.score >= threshold and o.truth == "subject")
    fp = sum(1 for o in outcomes if o.score >= threshold and o.truth != "subject")
    fn = sum(1 for o in outcomes if o.score < threshold and o.truth == "subject")
    return {"precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None, "tp": tp, "fp": fp, "fn": fn}  # fmt: skip


def calibration(outcomes: list[Outcome], bins: int = 10) -> dict:
    if not outcomes:
        return {"brier": None, "ece": None, "bins": []}
    brier = sum((o.score - (o.truth == "subject")) ** 2 for o in outcomes) / len(outcomes)
    table, ece = [], 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        inside = [o for o in outcomes if lo <= o.score < hi or (b == bins - 1 and o.score == 1.0)]
        if not inside:
            continue
        mean = sum(o.score for o in inside) / len(inside)
        rate = sum(o.truth == "subject" for o in inside) / len(inside)
        ece += len(inside) / len(outcomes) * abs(mean - rate)
        table.append({"range": f"{lo:.1f}-{hi:.1f}", "n": len(inside), "mean_score": round(mean, 3),
                      "subject_rate": round(rate, 3)})  # fmt: skip
    return {"brier": round(brier, 4), "ece": round(ece, 4), "bins": table}


def report(outcomes: list[Outcome]) -> dict:
    from app.services.entities import LIKELY, POSSIBLE

    false_merges = [asdict(o) for o in outcomes if o.merged_with and o.truth != "subject"]
    traps = {}
    for trap in TRAPS:
        sub = [o for o in outcomes if o.trap == trap]
        if not sub:
            continue
        wrong = sum(1 for o in sub if (o.score >= LIKELY) != (o.truth == "subject"))
        traps[trap] = {"n": len(sub), "mean_score": round(sum(o.score for o in sub) / len(sub), 3),
                       "wrong_at_likely": wrong, "about": TRAPS[trap]}  # fmt: skip
    return {
        "findings": len(outcomes),
        "subject_share": round(sum(o.truth == "subject" for o in outcomes) / max(1, len(outcomes)), 3),
        "likely": _pr(outcomes, LIKELY),
        "possible": _pr(outcomes, POSSIBLE),
        "false_merges": len(false_merges),
        "false_merge_examples": false_merges[:5],
        "calibration": calibration(outcomes),
        "traps": traps,
    }


def regressions(current: dict, baseline: dict) -> list[str]:
    """What got worse than a saved baseline; the CLI exits non-zero when this is not empty."""
    problems = []
    if current["false_merges"] > 0:
        problems.append(f"{current['false_merges']} false merge(s): values of different people were merged")
    cp, bp = current["likely"]["precision"] or 0, baseline["likely"]["precision"] or 0
    if cp < bp - 0.005:
        problems.append(f"precision at Likely fell from {bp:.3f} to {cp:.3f}")
    ce, be = current["calibration"]["ece"] or 0, baseline["calibration"]["ece"] or 0
    if ce > be + 0.02:
        problems.append(f"calibration error rose from {be:.3f} to {ce:.3f}")
    return problems


def summary_lines(r: dict) -> list[str]:
    lk, ps, cal = r["likely"], r["possible"], r["calibration"]
    out = [
        f"{r['findings']} labelled findings ({r['subject_share']:.0%} belong to the subject)",
        f"Likely:   precision {lk['precision']}, recall {lk['recall']}  (tp {lk['tp']}, fp {lk['fp']}, fn {lk['fn']})",
        f"Possible: precision {ps['precision']}, recall {ps['recall']}",
        f"False merges: {r['false_merges']}",
        f"Calibration: Brier {cal['brier']}, ECE {cal['ece']}",
        "Traps (findings scored on the wrong side of Likely):",
    ]
    out += [f"  {k:16} {v['wrong_at_likely']:>3}/{v['n']:<3} mean {v['mean_score']:.2f}  {v['about']}"
            for k, v in r["traps"].items()]  # fmt: skip
    return out
