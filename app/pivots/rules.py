"""Pivot rules: which findings automatically trigger which tools.

Each rule turns an entity's value into zero or more tool inputs. Expansion is
deterministic, so the inputs a pivot ran on can always be recomputed from the
pivot log (which never stores the values themselves in plaintext).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from app.config import get_settings
from app.correlation import normalize as norm

# Shared mail providers and large platforms: pivoting onto these domains would
# enumerate the provider, not the subject.
SHARED_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me",
    "gmx.com", "gmx.de", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "qq.com", "163.com",
    "github.com", "gitlab.com", "google.com", "facebook.com", "twitter.com", "x.com", "linkedin.com",
    "instagram.com", "reddit.com", "medium.com", "wordpress.com", "blogspot.com",
}  # fmt: skip

_EMAIL_LOCAL = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,63}$")


@dataclass(frozen=True)
class PivotInput:
    type: str  # the target type the tool receives
    value: str
    guessed: bool = False  # derived by guessing, not observed


def same_value(entity_type: str) -> Callable[[str], list[PivotInput]]:
    return lambda value: [PivotInput(entity_type, value)]


def guessed_emails(username: str) -> list[PivotInput]:
    """username -> username@<common provider>, for registration checks."""
    local = norm.fold(username)
    if not _EMAIL_LOCAL.match(local):
        return []
    providers = [p.strip() for p in get_settings().pivot_email_providers.split(",") if p.strip()]
    return [PivotInput("email", f"{local}@{p}", guessed=True) for p in providers]


def email_domain(email: str) -> list[PivotInput]:
    domain = email.rsplit("@", 1)[-1].casefold().strip()
    return [] if not domain or domain in SHARED_DOMAINS else [PivotInput("domain", domain)]


def own_domain(domain: str) -> list[PivotInput]:
    domain = norm.canonical("domain", domain)
    return [] if domain in SHARED_DOMAINS else [PivotInput("domain", domain)]


@dataclass(frozen=True)
class PivotRule:
    id: str
    label: str
    entity_type: str
    min_confidence: float
    tool: str
    expand: Callable[[str], list[PivotInput]]


RULES: list[PivotRule] = [
    PivotRule("username-holehe", "username found (conf > 0.6) → guessed emails", "username", 0.6, "holehe",
              guessed_emails),
    PivotRule("username-maigret", "username found (conf > 0.6)", "username", 0.6, "maigret", same_value("username")),
    PivotRule("email-h8mail", "email found (conf > 0.6)", "email", 0.6, "h8mail", same_value("email")),
    PivotRule("email-theharvester", "email found (conf > 0.6) → its domain", "email", 0.6, "theharvester",
              email_domain),
    PivotRule("domain-amass", "domain found", "domain", 0.0, "amass", own_domain),
    PivotRule("domain-crtsh", "domain found", "domain", 0.0, "crtsh", own_domain),
    PivotRule("domain-spiderfoot", "domain found", "domain", 0.0, "spiderfoot", own_domain),
]  # fmt: skip

RULES_BY_ID = {r.id: r for r in RULES}


def rule_text(rule: PivotRule, confidence: float, note: str | None = None) -> str:
    """What pivot_log.rule_matched stores: rule id first so it can be parsed back."""
    text = f"{rule.id}: {rule.label}, conf {confidence:.2f}"
    return f"{text} — {note}" if note else text


def rule_from_text(text: str) -> PivotRule | None:
    return RULES_BY_ID.get(text.split(":", 1)[0])
