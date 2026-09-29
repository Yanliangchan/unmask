"""Evidence that outlives the web: page snapshots, and read-only share links to the report."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import safefetch
from app.models import Entity, Investigation, ShareLink, Snapshot, User
from app.proxy import proxy_for

log = logging.getLogger(__name__)

# --- Snapshots -----------------------------------------------------------------------------------


class _Text(HTMLParser):
    """Readable text of a page: scripts, styles and markup dropped, blocks on their own lines."""

    SKIP = {"script", "style", "noscript", "template", "svg", "head"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header",
             "footer", "blockquote", "pre", "table", "ul", "ol", "dd", "dt"}  # fmt: skip

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = " ".join(data.split())[:300]
        if not self.skip:
            self.parts.append(data)


def page_text(html: str) -> tuple[str, str]:
    """(title, readable text) of an HTML page."""
    parser = _Text()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:  # malformed markup: keep whatever was read
        log.debug("page text extraction stopped early: %s", exc)
    lines = [" ".join(line.split()) for line in "".join(parser.parts).splitlines()]
    text = "\n".join(line for line in lines if line)
    return parser.title, text


def snapshot_body(s: Snapshot) -> bytes:
    return base64.b64decode(s.body_b64)


def snapshot_intact(s: Snapshot) -> bool:
    """True if the stored copy still hashes to the value recorded at capture."""
    return hashlib.sha256(snapshot_body(s)).hexdigest() == s.sha256


def decode(s: Snapshot) -> str:
    body = snapshot_body(s)
    charset = "utf-8"
    if "charset=" in (s.content_type or ""):
        charset = s.content_type.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
    try:
        return body.decode(charset, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


async def capture(session: AsyncSession, case: Investigation, entity: Entity, user: User) -> Snapshot:
    url = (entity.attributes or {}).get("url") or (
        entity.value if entity.value.startswith(("http://", "https://")) else ""
    )
    if not url:
        raise safefetch.BlockedURL("This finding has no web address to capture")
    page = await safefetch.fetch(url, proxy=proxy_for("verify"))
    title = ""
    if "html" in page.content_type or page.body[:200].lstrip().lower().startswith((b"<!doctype", b"<html")):
        title, _ = page_text(page.body.decode("utf-8", "replace"))
    snap = Snapshot(
        case_id=case.id,
        entity_id=entity.id,
        url=url,
        final_url=page.final_url,
        status_code=page.status_code,
        content_type=page.content_type[:200],
        sha256=hashlib.sha256(page.body).hexdigest(),
        size=len(page.body),
        truncated=page.truncated,
        title=title or None,
        body_b64=base64.b64encode(page.body).decode("ascii"),
        captured_by=user.id,
    )
    session.add(snap)
    await session.flush()
    return snap


async def snapshots_for(session: AsyncSession, case_id: uuid.UUID, entity_id: uuid.UUID) -> list[Snapshot]:
    return list(
        (
            await session.scalars(
                select(Snapshot)
                .where(Snapshot.case_id == case_id, Snapshot.entity_id == entity_id)
                .order_by(Snapshot.created_at.desc())
            )
        ).all()
    )


# --- Share links ---------------------------------------------------------------------------------

MAX_SHARE_DAYS = 30


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_share_link(
    session: AsyncSession, case: Investigation, user: User, *, days: int, label: str | None
) -> tuple[ShareLink, str]:
    """A new link and its token. The token is returned once and never stored."""
    token = secrets.token_urlsafe(32)
    link = ShareLink(
        case_id=case.id,
        token_hash=_hash(token),
        label=(label or "").strip()[:120] or None,
        created_by=user.id,
        expires_at=datetime.now(UTC) + timedelta(days=max(1, min(MAX_SHARE_DAYS, days))),
    )
    session.add(link)
    await session.flush()
    return link, token


async def resolve_share_link(session: AsyncSession, token: str) -> ShareLink | None:
    """The live link for a token, or None (unknown, revoked or expired all look the same)."""
    if not token or len(token) > 100:
        return None
    link = await session.scalar(select(ShareLink).where(ShareLink.token_hash == _hash(token)))
    if link is None or link.revoked_at is not None or link.expires_at <= datetime.now(UTC):
        return None
    return link


async def share_links_for(session: AsyncSession, case_id: uuid.UUID) -> list[ShareLink]:
    return list(
        (
            await session.scalars(
                select(ShareLink).where(ShareLink.case_id == case_id).order_by(ShareLink.created_at.desc())
            )
        ).all()
    )
