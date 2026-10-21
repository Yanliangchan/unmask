"""The Identity Resolution Lab as a regression gate: the failure modes it was built around
must not come back. Runs the real pipeline on synthetic cases and rolls everything back."""

from sqlalchemy import func, select

from app import lab
from app.models import Investigation


async def test_lab_metrics_hold_and_leave_nothing_behind(db):
    before = await db.scalar(select(func.count(Investigation.id)))
    result = lab.report(await lab.run(db, lab.generate(16)))
    assert await db.scalar(select(func.count(Investigation.id))) == before  # rolled back
    assert result["false_merges"] == 0
    assert result["likely"]["precision"] >= 0.95
    traps = result["traps"]
    # Another person's accounts that link to each other must not vouch for each other.
    assert traps["mutual_decoys"]["wrong_at_likely"] == 0
    for trap in ("namesake_handle", "common_handle", "namesake_name", "phone_country", "name_order"):
        assert traps[trap]["wrong_at_likely"] == 0, trap


def test_calibration_and_threshold_metrics():
    rows = [("a", "subject", 0.9), ("b", "other", 0.8), ("c", "subject", 0.3), ("d", "other", 0.1)]
    out = [lab.Outcome("c", key, "baseline", truth, score) for key, truth, score in rows]
    r = lab.report(out)
    assert r["likely"] == {"precision": 0.5, "recall": 0.5, "tp": 1, "fp": 1, "fn": 1}
    assert r["calibration"]["brier"] == round((0.01 + 0.64 + 0.49 + 0.01) / 4, 4)
    worse = {**r, "false_merges": 1}
    assert any("false merge" in p for p in lab.regressions(worse, r))


def test_the_generator_is_deterministic():
    assert [c.name for c in lab.generate(5)] == [c.name for c in lab.generate(5)]
    assert lab.generate(3)[0].findings[0].value == lab.generate(3)[0].findings[0].value
