"""Case templates: sensible starting points for common kinds of investigation.

A template fills in the new-case form (target types, scan depth, tools, watch
mode) and suggests what the authorization note should say. It never writes
the authorization for the analyst: that has to be their own record.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CaseTemplate:
    key: str
    label: str
    summary: str
    name_hint: str
    authorization_hint: str
    target_types: list[str]
    depth: str = "quick"
    # Tools to select; None keeps the default choice for the depth.
    tools: list[str] | None = None
    context_hint: str = "A city, an employer, a school… then comma"
    watch: str | None = None  # "daily" | "weekly" | "monthly"
    tips: list[str] = field(default_factory=list)


TEMPLATES: list[CaseTemplate] = [
    CaseTemplate(
        key="due_diligence",
        label="Person due diligence",
        summary="Check that a person is who they say they are before a deal, hire or partnership.",
        name_hint="e.g. Due diligence: supplier director",
        authorization_hint="The engagement or HR reference, who approved the check, and the candidate's consent "
        "or the legal basis you rely on.",
        target_types=["name", "email", "username"],
        depth="deep",
        context_hint="Their employer, city, school or industry… then comma",
        tips=[
            "Add the employer and city as context: findings that mention them rank higher.",
            "Confirm only what you can tie to the person; the report lists confirmed findings first.",
        ],
    ),
    CaseTemplate(
        key="username_sweep",
        label="Username sweep",
        summary="Find where one handle is registered, and which of those accounts are really the same person.",
        name_hint="e.g. Handle sweep: janedoe",
        authorization_hint="Why this handle is in scope (ticket, engagement ID) and who asked for it.",
        target_types=["username"],
        depth="quick",
        tools=["sherlock", "maigret", "websearch", "duckduckgo"],
        tips=["Common handles match many people: use Review to rule accounts in or out quickly."],
    ),
    CaseTemplate(
        key="email_exposure",
        label="Email exposure",
        summary="See which services an address is registered on and whether it appears in known breaches.",
        name_hint="e.g. Exposure check: finance mailbox",
        authorization_hint="Whose address this is and their consent, or the security engagement that covers it.",
        target_types=["email"],
        depth="quick",
        tools=["holehe", "h8mail", "websearch", "duckduckgo"],
        tips=["Breach results come from configured sources only; add h8mail keys on the Tools page for more."],
    ),
    CaseTemplate(
        key="domain_footprint",
        label="Domain footprint",
        summary="Map an organisation's subdomains, hosts and public mentions.",
        name_hint="e.g. Attack surface: acme.example",
        authorization_hint="The scope letter or engagement ID, and that you are authorized to assess this domain.",
        target_types=["domain"],
        depth="deep",
        tools=["crtsh", "theharvester", "amass", "spiderfoot", "websearch"],
        watch="weekly",
        tips=["Watch mode re-scans weekly and the Timeline shows what changed."],
    ),
    CaseTemplate(
        key="impersonation",
        label="Impersonation watch",
        summary="Keep an eye on accounts and pages that use a person's or brand's name.",
        name_hint="e.g. Impersonation watch: CEO",
        authorization_hint="Who you are protecting, their request or your role, and what you'll do with findings.",
        target_types=["name", "username"],
        depth="quick",
        watch="daily",
        tips=["New look-alike accounts show up as New on the Timeline after each watch scan."],
    ),
]

BY_KEY = {t.key: t for t in TEMPLATES}


def get_template(key: str | None) -> CaseTemplate | None:
    return BY_KEY.get(key or "")


def form_for(template: CaseTemplate) -> dict:
    """New-case form values for a template."""
    return {
        "depth": template.depth,
        "template": template.key,
        "targets": [{"value": "", "type": t, "tags": ""} for t in template.target_types],
    }
