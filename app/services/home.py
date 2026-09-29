"""The home inbox: what needs the analyst now, the getting-started checklist, and the sample case."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import and_, func, not_, or_, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import EntityCandidate
from app.models import AccessLog, Entity, Investigation, ScanRun, User
from app.services.cases import TargetInput, create_case, visible_case_ids
from app.services.entities import WEAK_CONFIDENCE

SAMPLE_NAME = "Sample case: Alex Rivera (made-up data)"


# --- What needs you --------------------------------------------------------------------------


@dataclass
class AttentionItem:
    kind: str  # review | running | failed
    case: Investigation
    count: int
    text: str
    url: str


async def attention(session: AsyncSession, user: User, limit: int = 8) -> list[AttentionItem]:
    """Cases with findings waiting for a decision, scans running now, and scans that failed."""
    ids = await visible_case_ids(session, user)
    if not ids:
        return []
    cases = {c.id: c for c in (await session.scalars(select(Investigation).where(Investigation.id.in_(ids)))).all()}
    # Same rule as the review queue: undecided, not a web result, not hidden from the default view.
    to_review = (
        await session.execute(
            select(Entity.case_id, func.count())
            .where(
                Entity.case_id.in_(ids),
                Entity.merged_into_id.is_(None),
                Entity.is_seed.is_(False),
                Entity.confirmed_flag.is_(False),
                Entity.dismissed_flag.is_(False),
                Entity.type != "web_mention",
                Entity.confidence >= WEAK_CONFIDENCE,
                not_(and_(Entity.type == "account", Entity.verification == "unverified")),
            )
            .group_by(Entity.case_id)
        )
    ).all()
    items: list[AttentionItem] = []
    for case_id, count in sorted(to_review, key=lambda r: -r[1]):
        case = cases[case_id]
        items.append(AttentionItem("review", case, count, f"{count} finding{'s' if count != 1 else ''} to review",
                                   f"/cases/{case_id}/review"))  # fmt: skip
    latest = (
        await session.scalars(
            select(ScanRun)
            .where(ScanRun.case_id.in_(ids), ScanRun.triggered_by != "health_check")
            .order_by(ScanRun.case_id, ScanRun.run_number.desc())
            .ext(distinct_on(ScanRun.case_id))
        )
    ).all()
    for run in latest:
        case = cases[run.case_id]
        if run.status in ("queued", "running"):
            done = f"{run.jobs_done} of {run.jobs_total} tools" if run.jobs_total else "starting"
            items.append(AttentionItem("running", case, run.jobs_done, f"Scan {run.run_number} running · {done}",
                                       f"/cases/{case.id}"))  # fmt: skip
        elif run.status == "failed" or (run.status == "partial" and run.tools_failed):
            n = len(run.tools_failed or [])
            text = f"Scan {run.run_number}: {n} tool{'s' if n != 1 else ''} failed"
            items.append(AttentionItem("failed", case, n, text, f"/cases/{case.id}"))
    order = {"running": 0, "review": 1, "failed": 2}
    items.sort(key=lambda i: order[i.kind])
    return items[:limit]


# --- Getting started ---------------------------------------------------------------------------


@dataclass
class Step:
    key: str
    label: str
    hint: str
    done: bool
    url: str | None = None


async def checklist(session: AsyncSession, user: User) -> list[Step]:
    ids = await visible_case_ids(session, user)
    real_q = select(Investigation.id).where(Investigation.id.in_(ids), Investigation.is_sample.is_(False))
    real = list((await session.scalars(real_q.order_by(Investigation.created_at))).all()) if ids else []
    scanned = bool(real) and bool(await session.scalar(select(ScanRun.id).where(ScanRun.case_id.in_(real)).limit(1)))
    decided = bool(ids) and bool(
        await session.scalar(
            select(Entity.id)
            .where(
                Entity.case_id.in_(ids),
                Entity.is_seed.is_(False),
                or_(Entity.confirmed_flag.is_(True), Entity.dismissed_flag.is_(True)),
            )
            .limit(1)
        )
    )
    shared = bool(
        await session.scalar(
            select(AccessLog.id).where(AccessLog.user_id == user.id, AccessLog.action == "share_case").limit(1)
        )
    )
    prefs = (user.preferences or {}).get("notify") or {}
    notified = bool(prefs.get("email") or user.slack_webhook)
    first_real = f"/cases/{real[0]}" if real else None
    return [
        Step("case", "Create your first case", "Start from a template, or paste what you know about the subject.",
             bool(real), "/cases/new"),
        Step("scan", "Run a scan", "Every new case scans straight away; Run scan repeats it later.", scanned,
             first_real),
        Step("decide", "Decide on a finding", "Confirm what belongs to the subject and rule out the rest. "
             "Your decisions train each site's accuracy.", decided, (first_real + "/review") if first_real else None),
        Step("notify", "Choose how you hear about results", "Email or Slack when a scan finishes or watch mode "
             "finds something new.", notified, "/account"),
        Step("share", "Share a case with a colleague", "From a case's Settings tab.", shared,
             first_real and first_real + "/settings"),
    ]  # fmt: skip


def show_checklist(user: User, steps: list[Step]) -> bool:
    return not (user.preferences or {}).get("onboarding_dismissed") and not all(s.done for s in steps)


# --- Sample case -------------------------------------------------------------------------------


# Invented person, reserved example domains only: nothing here points at a real account.
def _account(host: str, path: str, site: str, reliability: str, prior: float, check: str, note: str, title: str = ""):
    url = f"https://{host}/{path}"
    attrs = {"site": site, "url": url, "username": "alexrivera", "verification": check, "verification_reason": note}
    if title:
        attrs["title"] = title
    return EntityCandidate("account", url, attrs, reliability, prior, {"value": prior}, "has_account", "same username")


def _mention(url: str, title: str, snippet: str, reliability: str, prior: float, note: str):
    attrs = {"url": url, "title": title, "snippet": snippet}
    return EntityCandidate("web_mention", url, attrs, reliability, prior, {"value": prior}, "mentioned_in", note)


_SAMPLE_FINDINGS: dict[str, list[EntityCandidate]] = {
    "sherlock": [
        _account("code.example", "alexrivera", "CodeHub (example)", "C", 0.62, "verified",
                 "Profile page names Alex Rivera, Portland", "Alex Rivera · Portland · product designer"),
        _account("photos.example", "alexrivera", "Photoshare (example)", "C", 0.55, "verified",
                 "Profile page found", "alexrivera: photos from Portland"),
        _account("games.example", "u/alexrivera", "Gamerlist (example)", "D", 0.35, "unverified",
                 "The page loads for any username, so it proves nothing"),
        _account("forum.example", "members/alexrivera", "Makers forum (example)", "C", 0.4, "verified",
                 "Profile page found", "alexrivera · joined 2011 · Madrid"),
    ],
    "holehe": [
        EntityCandidate("registration", "Design community (example)",
                        {"site": "Design community (example)", "email": "alex.rivera@example.com"},
                        "B", 0.7, {"value": 0.7}, "registered_on", "email is registered"),
    ],
    "websearch": [
        _mention("https://news.example/2024/portland-design-week-speakers", "Portland Design Week: speakers",
                 "…product designer Alex Rivera will talk about accessible checkout flows…", "D", 0.5,
                 "search result names the subject"),
        _mention("https://people.example/alex-rivera-realtor", "Alex Rivera, realtor in Phoenix",
                 "Alex Rivera has sold homes in Phoenix since 2009…", "E", 0.3, "same name, different person"),
    ],
}  # fmt: skip


async def create_sample_case(session: AsyncSession, user: User) -> Investigation:
    """A finished-looking case built from invented data, so a new analyst can try every screen."""
    from app.correlation.engine import correlate_case
    from app.services.scans import persist_candidates

    case = await create_case(
        session,
        owner=user,
        name=SAMPLE_NAME,
        authorization_note="Sample case with invented data, created to show how unmask works. "
        "No real person is researched and it cannot be scanned.",
        lawful_basis_confirmed=True,
        targets=[
            TargetInput(value="alexrivera", type="username", context_tags=["portland", "designer"]),
            TargetInput(value="alex.rivera@example.com", type="email", context_tags=["portland", "designer"]),
            TargetInput(value="Alex Rivera", type="name", context_tags=["portland", "designer"]),
        ],
        disabled_tools=[],
    )
    case.is_sample = True
    case.retention_days = 30
    now = datetime.now(UTC)
    run = ScanRun(case_id=case.id, run_number=1, status="completed", triggered_by="manual",
                  tools_included=sorted(_SAMPLE_FINDINGS), tools_completed=sorted(_SAMPLE_FINDINGS), tools_failed=[],
                  failure_details={}, jobs_total=len(_SAMPLE_FINDINGS), jobs_done=len(_SAMPLE_FINDINGS),
                  started_at=now, completed_at=now)  # fmt: skip
    session.add(run)
    await session.flush()
    seeds = {
        e.type: e
        for e in (
            await session.scalars(select(Entity).where(Entity.case_id == case.id, Entity.is_seed.is_(True)))
        ).all()
    }
    parents = {"sherlock": seeds["username"], "holehe": seeds["email"], "websearch": seeds["name"]}
    for tool, candidates in _SAMPLE_FINDINGS.items():
        await persist_candidates(session, run=run, parent=parents[tool], tool=tool, candidates=candidates)
    await session.flush()
    await correlate_case(session, case.id, semantic=False)
    case.last_reviewed_run_number = 1
    return case


async def sample_case_id(session: AsyncSession, user: User) -> uuid.UUID | None:
    return await session.scalar(
        select(Investigation.id).where(Investigation.owner_id == user.id, Investigation.is_sample.is_(True)).limit(1)
    )
