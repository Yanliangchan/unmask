"""Canonical forms: two values with the same canonical form are the same identifier.

Equality here means "the same email address / URL / hostname written
differently", never "probably the same person" — that is a separate,
human-reviewed judgement.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
_NON_WORD = re.compile(r"[^\w\s]", re.UNICODE)
_SPACES = re.compile(r"\s+")


def fold(text: str) -> str:
    """Casefold and strip accents: 'José' -> 'jose'."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold().strip()


def canonical_email(value: str) -> str:
    local, _, domain = fold(value).partition("@")
    if domain in _GMAIL_DOMAINS:
        # Gmail ignores dots and +tags: these all reach one mailbox.
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"
    return f"{local}@{domain}"


def canonical_url(value: str) -> str:
    parts = urlsplit(value.strip())
    host = (parts.hostname or "").lower().removeprefix("www.").removeprefix("m.")
    path = parts.path.rstrip("/").lower()
    query = f"?{parts.query}" if parts.query else ""
    return f"{host}{path}{query}"


def canonical_name(value: str) -> str:
    """Punctuation-free, lower-case, tokens sorted: 'Chan, Yan-Liang' == 'yan liang chan'."""
    cleaned = _SPACES.sub(" ", _NON_WORD.sub(" ", fold(value).replace("_", " "))).strip()
    return " ".join(sorted(cleaned.split()))


def canonical_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return digits.lstrip("0") if not value.strip().startswith("+") else digits


def canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip().lower()


def canonical(entity_type: str, value: str) -> str:
    if entity_type == "email":
        return canonical_email(value)
    if entity_type == "account":
        return canonical_url(value)
    if entity_type == "hostname":
        return fold(value).rstrip(".")
    if entity_type == "domain":
        return fold(value).rstrip(".").removeprefix("www.")
    if entity_type == "name":
        return canonical_name(value)
    if entity_type == "phone":
        return canonical_phone(value)
    if entity_type == "ip":
        return canonical_ip(value)
    return fold(value)


def initials(name: str) -> list[str]:
    return [tok[0] for tok in _NON_WORD.sub(" ", fold(name)).split() if tok]


def initials_compatible(a: str, b: str) -> bool:
    """'J. Chan' fits 'John Chan'; 'J. Chan' does not fit 'Yan Liang Chan'.

    Every token of the shorter name must match a token of the longer one,
    either exactly or as an initial of it.
    """
    ta = _NON_WORD.sub(" ", fold(a)).split()
    tb = _NON_WORD.sub(" ", fold(b)).split()
    short, long_ = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    remaining = list(long_)
    for tok in short:
        match = next((t for t in remaining if t == tok or (len(tok) == 1 and t.startswith(tok))), None)
        if match is None:
            return False
        remaining.remove(match)
    return True


def email_handle(value: str) -> str:
    """Local part without +tags and separators, for comparing with usernames."""
    local = fold(value).split("@", 1)[0].split("+", 1)[0]
    return re.sub(r"[._\-]", "", local)


def handle(value: str) -> str:
    return re.sub(r"[._\-]", "", fold(value))
