"""Operator commands.

python -m app.cli gen-keys
python -m app.cli create-user EMAIL [--admin]
python -m app.cli health-check [TOOL]
python -m app.cli preflight
python -m app.cli eval FILE [--tools sherlock,maigret,websearch] [--json OUT]
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import secrets
import sys
import time
from urllib.parse import urlsplit

from sqlalchemy import select

from app import crypto
from app.config import get_settings
from app.db import dispose_engine, sessionmaker
from app.models import User
from app.security import hash_password


def gen_keys() -> None:
    print("# Store these in your secret manager, not alongside the database.")
    print(f"SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"UNMASK_DATA_KEYS={crypto.generate_key()}")
    print(f"UNMASK_INDEX_KEY={secrets.token_urlsafe(48)}")


def config_problems(env: dict[str, str] | None = None) -> list[str]:
    """Settings a production container cannot run without, in plain words."""
    env = os.environ if env is None else env
    s = get_settings()
    problems = []
    if s.is_production:
        # The defaults point at localhost, which never exists inside the container.
        if not env.get("DATABASE_URL"):
            problems.append("DATABASE_URL is not set (on Railway: ${{Postgres.DATABASE_URL}})")
        if s.queue_backend == "rq" and not env.get("REDIS_URL"):
            problems.append("REDIS_URL is not set (on Railway: ${{Redis.REDIS_URL}})")
    try:
        s.validate_for_startup()
    except RuntimeError as exc:
        problems.extend(str(exc).removeprefix("Invalid configuration: ").split("; "))
    return problems


async def _database_ready() -> str | None:
    from sqlalchemy import text

    from app.db import get_engine

    try:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        return None
    except Exception as exc:  # noqa: BLE001  (any failure means "not ready yet")
        return f"{type(exc).__name__}: {exc}"
    finally:
        await dispose_engine()


def preflight(wait_seconds: int) -> None:
    """Check configuration, then wait for Postgres before migrations run."""
    problems = config_problems()
    if problems:
        print("unmask cannot start. Fix these service variables and redeploy:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("Generate the three secrets with: python -m app.cli gen-keys", file=sys.stderr)
        sys.exit(1)
    url = urlsplit(get_settings().database_url)
    where = f"{url.hostname}:{url.port or 5432}"
    # Private networking can take a few seconds to come up after a deploy starts.
    deadline = time.monotonic() + wait_seconds
    while True:
        error = asyncio.run(_database_ready())
        if error is None:
            print(f"database at {where} is ready")
            return
        if time.monotonic() >= deadline:
            print(f"unmask cannot start: database at {where} did not answer within {wait_seconds}s.", file=sys.stderr)
            print(f"  last error: {error}", file=sys.stderr)
            sys.exit(1)
        print(f"waiting for database at {where}...", file=sys.stderr)
        time.sleep(2)


async def create_user(email: str, admin: bool) -> None:
    password = getpass.getpass("Password: ")
    if len(password) < 12:
        sys.exit("Password must be at least 12 characters.")
    if password != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match.")
    async with sessionmaker()() as session:
        email = email.strip().lower()
        if await session.scalar(select(User.id).where(User.email == email)):
            sys.exit(f"{email} already exists.")
        session.add(User(email=email, password_hash=hash_password(password), is_admin=admin))
        await session.commit()
    await dispose_engine()
    print(f"Created {email}{' (admin)' if admin else ''}.")


async def health_check(tool: str | None) -> None:
    from app.adapters.registry import all_adapters
    from app.services.tools import run_health_check, sync_tool_config

    s = get_settings()
    crypto.cipher.configure(s.data_keys, s.index_key)
    async with sessionmaker()() as session:
        await sync_tool_config(session)
        names = [tool] if tool else [a.name for a in all_adapters()]
        for name in names:
            result = await run_health_check(session, name)
            print(f"{name:<14} {result.status_label:<14} {result.detail}")
    await dispose_engine()


def evaluate(path: str, tools: list[str], json_out: str | None) -> None:
    from app import evaluation

    try:
        data = evaluation.load(path)
    except (OSError, ValueError) as exc:
        sys.exit(f"Can't use {path}: {exc}")
    print(f"Authorization: {data['authorization']}")
    print(f"{len(data['identities'])} identities x {len(tools)} tools. Live tools are slow; this can take a while.\n")
    results = asyncio.run(evaluation.run_eval(data, tools))
    print(evaluation.summarize(results))
    if json_out:
        with open(json_out, "w") as fh:
            fh.write(evaluation.to_json(results))
        print(f"\nDetails (missed accounts, false positives) written to {json_out}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-keys", help="print fresh secrets for a new deployment")
    cu = sub.add_parser("create-user", help="create a login")
    cu.add_argument("email")
    cu.add_argument("--admin", action="store_true")
    hc = sub.add_parser("health-check", help="run tool health checks against known-good targets")
    hc.add_argument("tool", nargs="?")
    ev = sub.add_parser("eval", help="measure the tools against identities whose accounts are known")
    ev.add_argument("file")
    ev.add_argument("--tools", default="sherlock,maigret,websearch")
    ev.add_argument("--json", dest="json_out")
    pf = sub.add_parser("preflight", help="check configuration and wait for the database (run before migrations)")
    pf.add_argument("--wait", type=int, default=int(os.environ.get("UNMASK_DB_WAIT", "60")))
    args = parser.parse_args()

    if args.cmd == "gen-keys":
        gen_keys()
    elif args.cmd == "create-user":
        asyncio.run(create_user(args.email, args.admin))
    elif args.cmd == "health-check":
        asyncio.run(health_check(args.tool))
    elif args.cmd == "eval":
        evaluate(args.file, [t.strip() for t in args.tools.split(",") if t.strip()], args.json_out)
    elif args.cmd == "preflight":
        preflight(args.wait)


if __name__ == "__main__":
    main()
