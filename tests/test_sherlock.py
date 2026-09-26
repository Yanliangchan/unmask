import pytest

from app.adapters.base import InvalidTarget, RawResult, SignatureMismatch
from app.adapters.sherlock import SherlockAdapter, parse_output

GOOD = """A problem occurred while checking for an update: 'tag_name'
[*] Checking username torvalds on:

[+] GitHub: https://www.github.com/torvalds
[+] GitLab: https://gitlab.com/torvalds
[-] Instagram: Not Found!
[-] 7Cups: Illegal Username Format For This Site!
[-] Reddit: Not Found!
[-] Imgur: Timeout Error

[*] Search completed with 2 results

Go deeper than a username.
"""


def test_parses_found_not_found_and_errors():
    report = parse_output(GOOD)
    assert report.username == "torvalds"
    assert report.found == {"GitHub": "https://www.github.com/torvalds", "GitLab": "https://gitlab.com/torvalds"}
    assert set(report.not_found) == {"Instagram", "Reddit"}
    assert report.illegal == ["7Cups"]
    assert report.errored == {"Imgur": "Timeout Error"}


def test_strips_ansi_colour_codes():
    coloured = GOOD.replace("[+] GitHub:", "\x1b[1m\x1b[37m[\x1b[32m+\x1b[37m]\x1b[32m GitHub:\x1b[0m")
    assert "GitHub" in parse_output(coloured).found


@pytest.mark.parametrize(
    "output, reason",
    [
        ("", "start banner"),
        ("<html>Access denied</html>", "start banner"),
        ("[*] Checking username x on:\n[+] GitHub: https://github.com/x\n", "completion"),
        ("[*] Checking username x on:\n[*] Search completed with 0 results\n", "zero sites"),
        ("[*] Checking username x on:\n[+] A: https://a/x\n[*] Search completed with 3 results\n", "reported 3"),
    ],
)
def test_output_without_signature_is_not_an_empty_result(output, reason):
    with pytest.raises(SignatureMismatch, match=reason):
        parse_output(output)


def test_mostly_blocked_run_is_rejected_not_reported_as_no_accounts():
    lines = ["[*] Checking username x on:"]
    lines += [f"[-] Site{i}: Blocked by bot detection (proxy may help)" for i in range(8)]
    lines += ["[-] Other: Not Found!", "[*] Search completed with 0 results"]
    with pytest.raises(SignatureMismatch, match="8/9 sites errored"):
        parse_output("\n".join(lines))


def test_parse_emits_accounts_with_reliability_distinct_from_confidence():
    adapter = SherlockAdapter()
    cands = adapter.parse(RawResult("sherlock", "torvalds", parse_output(GOOD)))
    assert [c.attributes["site"] for c in cands] == ["GitHub", "GitLab"]
    assert all(c.type == "account" and c.source_reliability == "C" for c in cands)
    assert all(c.confidence < 0.5 for c in cands)  # username reuse is weak identity evidence
    assert adapter.check_health_output(cands).ok


@pytest.mark.parametrize("bad", ["-rf", "--proxy=http://evil", "a b", "x;rm", "{?}", ""])
def test_rejects_usernames_that_could_become_arguments(bad):
    with pytest.raises(InvalidTarget):
        SherlockAdapter().build_argv(bad)


def test_username_follows_end_of_options_marker(monkeypatch):
    monkeypatch.setattr("app.adapters.sherlock.resolve_binary", lambda name: "/bin/sherlock")
    argv = SherlockAdapter().build_argv("torvalds")
    assert argv[-2:] == ["--", "torvalds"]
