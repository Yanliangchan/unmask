"""How much a username match means.

Finding "john" on a site proves almost nothing: thousands of people hold that
handle. Finding "jdoe_lisbon_92" is far more telling. ``username_rarity``
gives a rough 0-1 estimate from length and whether the handle is a common
word or first name; scoring scales username-based account priors by it.
"""

from __future__ import annotations

import re

# Common first names and everyday words that are taken as handles on every site.
_COMMON = set(
    """
    admin administrator test user guest info support root demo hello hi love cool star king queen boss master
    player gamer game games music art photo photos travel food life happy sunny angel devil dragon wolf tiger lion
    bear fox eagle shadow ghost ninja pro best real official the team news shop store online web blog dev code
    coder hacker tech data cloud blue red green black white gold silver dark light fire ice sky moon sun rain
    storm night day summer winter spring baby sweet honey pretty lucky magic dream smile crazy super mega ultra
    john james robert michael william david richard joseph thomas charles chris christopher daniel matthew
    anthony mark donald steven paul andrew joshua kevin brian george edward ryan jacob gary nicholas eric jonathan
    stephen larry justin scott brandon benjamin samuel frank gregory raymond alexander patrick jack dennis jerry
    tyler aaron jose adam henry nathan peter zachary kyle walter harold carl jeremy keith roger gerald ethan arthur
    sean alex sam max ben tom tim jim bob joe mike nick dan matt josh jake luke leo noah liam lucas oliver
    mary patricia jennifer linda elizabeth barbara susan jessica sarah karen nancy lisa betty margaret sandra
    ashley kimberly emily donna michelle dorothy carol amanda melissa deborah stephanie rebecca sharon laura
    cynthia kathleen amy angela shirley anna brenda pamela emma nicole helen samantha katherine christine debra
    rachel carolyn janet catherine maria heather diane ruth julie olivia joyce virginia victoria kelly lauren
    christina joan evelyn judith megan andrea cheryl hannah jacqueline martha gloria teresa ann sara madison
    frances kathryn janice jean abigail alice judy sophia grace denise amber doris marilyn danielle beverly
    isabella theresa diana natalie brittany charlotte marie kayla alexis lori jane kate lily mia ella zoe amy
    mohamed muhammad ahmed ali omar wei li wang zhang liu chen yang huang kim lee park nguyen tran singh kumar
    """.split()
)
_DIGITS = re.compile(r"\d+$")


def _fold(username: str) -> str:
    return re.sub(r"[._\-\s]", "", username.casefold())


def username_rarity(username: str) -> tuple[float, str]:
    """(0-1 rarity, reason). 1 = distinctive enough that a match means something."""
    h = _fold(username)
    if not h:
        return 1.0, ""
    if len(h) <= 3:
        return 0.15, f"'{username}' is very short, so many people use it"
    if h in _COMMON:
        return 0.25, f"'{username}' is a common word or first name"
    core = _DIGITS.sub("", h)
    if core in _COMMON and len(h) - len(core) <= 2:
        return 0.35, f"'{username}' is a common word or name with a number"
    if h.isdigit():
        return 0.3, f"'{username}' is only digits"
    rarity = max(0.5, min(1.0, 0.35 + 0.05 * len(h)))
    return rarity, "" if rarity >= 0.9 else f"'{username}' is fairly short, so a match means less"
