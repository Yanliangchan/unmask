"""Recognise what kind of identifier a bare value is."""

from __future__ import annotations

import ipaddress
import re

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)
_PHONE = re.compile(r"^\+?[\d\s().\-]{7,}$")
_URL = re.compile(r"^https?://", re.I)
_SPLIT = re.compile(r"[\n,;]+")


def guess_type(value: str) -> str:
    """username | email | domain | phone | ip | name. Tools and the new-case form both use it."""
    v = value.strip()
    if _EMAIL.match(v):
        return "email"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _PHONE.match(v) and sum(c.isdigit() for c in v) >= 7:
        return "phone"
    if _URL.match(v):
        v = re.sub(r"^https?://(www\.)?", "", v, flags=re.I).split("/", 1)[0]
        return "domain" if _DOMAIN.match(v) else "username"
    if _DOMAIN.match(v):
        return "domain"
    return "name" if " " in v else "username"


def split_identifiers(text: str) -> list[tuple[str, str]]:
    """Pasted text (one per line, or comma-separated) as (value, type) pairs, in order, without repeats."""
    out, seen = [], set()
    for raw in _SPLIT.split(text or ""):
        value = raw.strip().strip("\"'")
        if not value or len(value) > 200:
            continue
        kind = guess_type(value)
        if kind == "domain" and _URL.match(value):
            value = re.sub(r"^https?://(www\.)?", "", value, flags=re.I).split("/", 1)[0]
        key = (kind, value.casefold())
        if key not in seen:
            seen.add(key)
            out.append((value, kind))
    return out
