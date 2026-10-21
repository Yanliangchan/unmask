"""Seed a synthetic case of N findings for graph performance work.

    python scripts/graphbench.py --owner admin@example.com --nodes 500 1500

Each case is made-up data on reserved .example domains (marked as a sample, so it can't be
scanned) with an OSINT-like shape: three targets, accounts and registrations hanging off them,
a few shared hubs (a provider domain, a common name), cross-links from profiles, and
similarity suggestions. Prints each case id; open /cases/<id>/graph to measure.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app import crypto  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import dispose_engine, sessionmaker  # noqa: E402
from app.models import Entity, Relation, User  # noqa: E402
from app.services.cases import TargetInput, create_case  # noqa: E402

TYPES = ["account"] * 6 + ["registration", "web_mention", "hostname", "username", "breach", "name"]


async def seed(owner_email: str, n: int, rng: random.Random) -> str:
    async with sessionmaker()() as session:
        owner = await session.scalar(select(User).where(User.email == owner_email))
        if owner is None:
            raise SystemExit(f"no user {owner_email}")
        case = await create_case(
            session, owner=owner, name=f"Synthetic graph: {n} findings",
            authorization_note="Synthetic benchmark data on reserved example domains; no real person.",
            lawful_basis_confirmed=True, disabled_tools=[],
            targets=[TargetInput("benchuser", "username"), TargetInput("bench@example.com", "email"),
                     TargetInput("Bench Example", "name")],
        )  # fmt: skip
        case.is_sample = True
        await session.flush()
        seeds = list((await session.scalars(select(Entity).where(Entity.case_id == case.id))).all())
        made: list[Entity] = []
        hubs: list[Entity] = []
        for i in range(n - len(seeds)):
            etype = rng.choice(TYPES)
            value = f"https://site{i}.example/benchuser" if etype == "account" else f"{etype}-{i}.example"
            conf = round(rng.betavariate(2, 2.5), 3)
            check = ("verified" if rng.random() < 0.6 else "unverified") if etype == "account" else None
            tool = rng.choice(["sherlock", "maigret", "holehe", "websearch"])
            e = Entity(case_id=case.id, type=etype, value=value, value_digest=crypto.digest(etype, value),
                       attributes={"site": f"Site {i} (example)"}, source_tool=tool, confidence=conf,
                       field_confidence={"value": conf}, source_reliability=rng.choice("BCD"),
                       verification=check)  # fmt: skip
            session.add(e)
            made.append(e)
            if i < 4:
                hubs.append(e)
        await session.flush()

        def rel(a, b, rtype, basis, conf, directed):
            session.add(Relation(case_id=case.id, entity_a_id=a.id, entity_b_id=b.id, relation_type=rtype,
                                 source_tool="correlation" if basis != "observed" else a.source_tool,
                                 match_explanation=f"synthetic {rtype}", confidence=conf, basis=basis,
                                 directed=directed))  # fmt: skip

        for e in made:
            rel(rng.choice(seeds + hubs), e, "has_account", "observed", e.confidence, True)
        for _ in range(int(n * 0.4)):
            a, b = rng.sample(made, 2)
            kind = rng.random()
            if kind < 0.5:
                rel(a, b, "profile_links_to", "observed", 0.9, True)
            elif kind < 0.8:
                rel(a, b, "shares_handle", "rule", 0.7, False)
            else:
                rel(a, b, "possible_same", "similarity", round(rng.uniform(0.85, 0.97), 3), False)
        await session.commit()
        return str(case.id)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--owner", required=True)
    parser.add_argument("--nodes", type=int, nargs="+", default=[500])
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    s = get_settings()
    crypto.cipher.configure(s.data_keys, s.index_key)
    rng = random.Random(args.seed)  # noqa: S311 — reproducible synthetic data, not security
    for n in args.nodes:
        print(n, await seed(args.owner, n, rng))
    await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())
