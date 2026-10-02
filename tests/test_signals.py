"""Evidence for and against a finding, and the highlight filter."""

import uuid

from app.models import Entity, Relation, Target
from app.services.signals import CaseIndex, evidence
from app.web import _highlight


def _target(kind, value, tags=()):
    return Target(id=uuid.uuid4(), type=kind, value=value, context_tags=list(tags))


def _entity(kind="account", value="https://code.example/janedoe", **attrs):
    e = Entity(
        id=uuid.uuid4(),
        type=kind,
        value=value,
        attributes=attrs,
        confidence=0.7,
        is_seed=False,
        confirmed_flag=False,
        dismissed_flag=False,
        merged_into_id=None,
        verification=attrs.get("verification"),
    )
    return e


TARGETS = [_target("username", "janedoe", ["lisbon", "logistics"]), _target("name", "Jane Doe")]


def labels(signals):
    return [s.label for s in signals]


def test_a_matching_profile_has_its_evidence_spelled_out():
    e = _entity(
        site="CodeHub",
        url="https://code.example/janedoe",
        username="janedoe",
        verification="verified",
        verification_reason="profile page names the username in its title",
        preview={
            "title": "janedoe (Jane Doe) · CodeHub",
            "description": "Logistics lead in Lisbon",
            "checked_at": "2026-09-28T10:00:00+00:00",
        },
    )
    ev = evidence(e, targets=TARGETS, tools=["sherlock", "maigret", "analyst"])
    assert labels(ev.for_) == [
        "Profile page checked",
        "Same username as the subject",
        "Display name matches the subject",
        "Mentions the case context",
        "Found by 2 tools",
    ]
    assert ev.for_[0].detail == "Profile page names the username in its title · checked 28 Sep 2026"
    assert ev.for_[3].detail == "lisbon, logistics"  # which tags, by name
    assert ev.against == [] and ev.summary == "5 for"
    assert ev.profile.name == "Jane Doe" and ev.profile.handle == "janedoe"
    assert "lisbon" in ev.terms and "janedoe" in ev.terms


def test_a_different_person_and_a_common_handle_count_against():
    e = _entity(
        value="https://forum.example/alex",
        url="https://forum.example/alex",
        username="alex",
        verification="unverified",
        verification_reason="login wall: the profile is only visible when signed in",
        profile={"fullname": "Alejandro Ruiz"},
    )
    ev = evidence(e, targets=[_target("username", "alex"), _target("name", "Alex Rivera")])
    assert "Profile page couldn't be confirmed" in labels(ev.against)
    assert "Common username: a match means little" in labels(ev.against)
    assert "The page names someone else" in labels(ev.against)
    assert ev.against[0].detail.startswith("Login wall")


def test_the_sites_own_account_is_flagged():
    e = _entity(value="https://x.example/tryhackme", url="https://tryhackme.com/tryhackme", username="tryhackme")
    e.value = "https://tryhackme.com/tryhackme"
    ev = evidence(e, targets=[_target("username", "janedoe")])
    assert "Looks like the site's own account" in labels(ev.against)


def test_links_to_confirmed_findings_are_strong_evidence_and_point_at_them():
    confirmed = _entity(value="https://github.com/janedoe")
    confirmed.confirmed_flag = True
    seed = _entity(kind="email", value="jane@acme.example")
    seed.is_seed = True
    e = _entity(
        url="https://code.example/janedoe",
        username="janedoe",
        verification="verified",
        preview={"links": ["https://github.com/janedoe", "https://janedoe.dev"], "emails": ["Jane@Acme.example"]},
    )
    ev = evidence(e, targets=TARGETS, index=CaseIndex.build([confirmed, seed]))
    states = {c.label: c.state for c in ev.links}
    assert states == {"github.com/janedoe": "confirmed", "janedoe.dev": "", "Jane@Acme.example": "target"}
    assert ev.links[0].state == "target"  # strongest first
    link_line = next(s for s in ev.for_ if s.label == "Links to what you already know")
    assert "github.com/janedoe" in link_line.detail


def test_corroborating_relations_quote_their_explanation():
    other = _entity(value="https://gitlab.example/janedoe")
    rel = Relation(id=uuid.uuid4(), relation_type="shares_handle", match_explanation="same handle 'janedoe' on both")
    e = _entity(url="https://code.example/janedoe", username="janedoe")
    ev = evidence(e, targets=TARGETS, relations=[(rel, other), (rel, other)])
    assert [s.detail for s in ev.for_ if s.label == "Corroborated"] == ["Same handle 'janedoe' on both"]


def test_a_target_only_says_it_is_a_target():
    e = _entity(kind="username", value="janedoe")
    e.is_seed = True
    ev = evidence(e, targets=TARGETS)
    assert (
        ev.for_ == [] and ev.against == [] and labels(ev.notes) == ["This is one of the identifiers you searched for"]
    )


def test_highlight_escapes_first_and_never_marks_inside_markup():
    out = str(_highlight('<script>alert("jane")</script> Jane & amp', ["jane", "amp"]))
    assert "<script>" not in out
    assert out.count("<mark>") == 3  # jane, Jane, amp: matched in the text, not in the escaped entities
    assert "&amp;" in out and "<mark>amp</mark>" in out
    assert str(_highlight("nothing here", [])) == "nothing here"
