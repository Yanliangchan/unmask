"""Versions and details for the legal pages, and the rule that users accept the current Terms.

Bump TERMS_VERSION whenever the Terms of Service or the Acceptable Use Policy
change in substance: every user is then asked to accept the new version before
they can use the app again. The Privacy Notice and Trust page are notices, not
contract terms, so changing them alone doesn't require re-acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import get_settings

TERMS_VERSION = "2026-09-29"
EFFECTIVE_DATE = "29 September 2026"

PAGES = [
    ("/trust", "Trust"),
    ("/terms", "Terms of Service"),
    ("/acceptable-use", "Acceptable Use Policy"),
    ("/privacy", "Privacy Notice"),
]


@dataclass(frozen=True)
class LegalDetails:
    operator: str  # who users contract with
    operator_is_named: bool
    contact: str
    security_contact: str
    law: str
    version: str = TERMS_VERSION
    effective: str = EFFECTIVE_DATE


def details() -> LegalDetails:
    s = get_settings()
    named = bool(s.operator_name.strip())
    return LegalDetails(
        operator=s.operator_name.strip() or "the operator of this unmask service",
        operator_is_named=named,
        contact=s.legal_contact.strip(),
        security_contact=(s.security_contact or s.legal_contact).strip(),
        law=s.governing_law.strip() or "Singapore",
    )


def needs_acceptance(user) -> bool:
    return user is not None and user.terms_version != TERMS_VERSION
