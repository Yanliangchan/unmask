"""Measure the tools against identities whose accounts are known.

    python -m app.cli eval identities.json [--tools sherlock,maigret,websearch] [--json results.json]

The file lists people you are allowed to search (your own accounts, or
volunteers who agreed) and the account URLs that really are theirs:

    {
      "authorization": "Own accounts and two consenting colleagues, ref EVAL-1",
      "identities": [
        {"label": "me", "username": "janedoe", "tags": ["lisbon"],
         "expected": ["https://github.com/janedoe", "https://www.reddit.com/user/janedoe"]}
      ]
    }

For each tool it reports what the tool claimed and what survived the page
check (the default view), as precision (share of hits that are expected
accounts) and recall (share of expected accounts found), plus run time.
Precision assumes the expected list is complete: an unlisted real account
counts as a false positive, so list every account you know of.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.adapters.base import AdapterError
from app.adapters.registry import get_adapter
from app.services.accuracy import site_host
from app.verify import VERIFIED, linked_accounts, verify_candidates

DEFAULT_TOOLS = ["sherlock", "maigret", "websearch"]


def account_key(url: str) -> str:
    from urllib.parse import urlparse

    p = urlparse(url.strip())
    query = f"?{p.query}" if p.query else ""
    return f"{site_host(url) or ''}{p.path.rstrip('/').lower()}{query.lower()}"


@dataclass
class ToolResult:
    tool: str
    identity: str
    seconds: float
    reported: int = 0
    reported_correct: int = 0
    shown: int = 0
    shown_correct: int = 0
    expected: int = 0
    error: str | None = None
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    @staticmethod
    def _ratio(n: int, d: int) -> float | None:
        return round(n / d, 3) if d else None

    @property
    def precision_reported(self) -> float | None:
        return self._ratio(self.reported_correct, self.reported)

    @property
    def precision_shown(self) -> float | None:
        return self._ratio(self.shown_correct, self.shown)

    @property
    def recall_reported(self) -> float | None:
        return self._ratio(self.reported_correct, self.expected)

    @property
    def recall_shown(self) -> float | None:
        return self._ratio(self.shown_correct, self.expected)


class EvalFileError(ValueError):
    pass


def load(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text())
    if not str(data.get("authorization", "")).strip():
        raise EvalFileError('the file must say who authorized these searches ("authorization")')
    identities = data.get("identities") or []
    if not identities:
        raise EvalFileError("no identities listed")
    for i, ident in enumerate(identities):
        if not ident.get("username") or not ident.get("expected"):
            raise EvalFileError(f"identity {i + 1} needs a username and a non-empty expected list")
    return data


async def evaluate_tool(tool: str, ident: dict) -> ToolResult:
    label = str(ident.get("label") or ident["username"])
    expected = {account_key(u) for u in ident["expected"]}
    result = ToolResult(tool=tool, identity=label, seconds=0.0, expected=len(expected))
    adapter = get_adapter(tool)
    if adapter is None:
        result.error = "unknown tool"
        return result
    if (why := adapter.configured()) is not None:
        result.error = why
        return result
    started = time.monotonic()
    try:
        raws = await adapter.run(ident["username"], list(ident.get("tags") or []))
        found = [c for raw in raws for c in adapter.parse(raw) if c.type == "account"]
    except AdapterError as exc:
        result.error, result.seconds = str(exc), round(time.monotonic() - started, 1)
        return result
    reported = {account_key(c.value) for c in found}
    kept, _ = await verify_candidates(found) if adapter.verify_accounts else (found, None)
    if adapter.verify_accounts:
        linked, _ = await verify_candidates(linked_accounts(kept))
        kept = kept + linked
    shown = {
        account_key(c.value)
        for c in kept
        if not adapter.verify_accounts or (c.attributes or {}).get("verification") == VERIFIED
    }
    result.seconds = round(time.monotonic() - started, 1)
    result.reported, result.reported_correct = len(reported), len(reported & expected)
    result.shown, result.shown_correct = len(shown), len(shown & expected)
    result.missed = sorted(expected - shown)
    result.false_positives = sorted(shown - expected)
    return result


async def run_eval(data: dict, tools: list[str]) -> list[ToolResult]:
    results = []
    for ident in data["identities"]:
        for tool in tools:
            results.append(await evaluate_tool(tool, ident))
    return results


def _fmt(value: float | None) -> str:
    return "  –  " if value is None else f"{value * 100:4.0f}%"


def summarize(results: list[ToolResult]) -> str:
    lines = [
        f"{'identity':<14} {'tool':<10} {'time':>6}  {'claimed':>7} {'prec':>5} {'recall':>6}"
        f"   {'shown':>5} {'prec':>5} {'recall':>6}",
    ]
    for r in results:
        if r.error:
            lines.append(f"{r.identity[:14]:<14} {r.tool:<10} {r.seconds:>5.0f}s  error: {r.error[:70]}")
            continue
        lines.append(
            f"{r.identity[:14]:<14} {r.tool:<10} {r.seconds:>5.0f}s  {r.reported:>7} {_fmt(r.precision_reported)} "
            f"{_fmt(r.recall_reported):>6}   {r.shown:>5} {_fmt(r.precision_shown)} {_fmt(r.recall_shown):>6}"
        )
    totals: dict[str, list[ToolResult]] = {}
    for r in results:
        if not r.error:
            totals.setdefault(r.tool, []).append(r)
    if totals:
        lines += ["", "totals (all identities):"]
        for tool, rs in totals.items():
            shown, correct = sum(r.shown for r in rs), sum(r.shown_correct for r in rs)
            expected, secs = sum(r.expected for r in rs), sum(r.seconds for r in rs)
            prec = correct / shown if shown else None
            rec = correct / expected if expected else None
            lines.append(
                f"  {tool:<10} shown precision {_fmt(prec)}  recall {_fmt(rec)}  avg {secs / len(rs):.0f}s per identity"
            )
    lines += ["", "claimed = what the tool reported; shown = what survives the page check (the default view)."]
    return "\n".join(lines)


def to_json(results: list[ToolResult]) -> str:
    rows = []
    for r in results:
        row = asdict(r)
        row.update(
            precision_reported=r.precision_reported,
            precision_shown=r.precision_shown,
            recall_reported=r.recall_reported,
            recall_shown=r.recall_shown,
        )
        rows.append(row)
    return json.dumps(rows, indent=2)
