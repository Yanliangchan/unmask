"""Operator commands.

python -m app.cli gen-keys
python -m app.cli create-user EMAIL [--admin]
python -m app.cli health-check [TOOL]
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import secrets
import sys

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


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-keys", help="print fresh secrets for a new deployment")
    cu = sub.add_parser("create-user", help="create a login")
    cu.add_argument("email")
    cu.add_argument("--admin", action="store_true")
    hc = sub.add_parser("health-check", help="run tool health checks against known-good targets")
    hc.add_argument("tool", nargs="?")
    args = parser.parse_args()

    if args.cmd == "gen-keys":
        gen_keys()
    elif args.cmd == "create-user":
        asyncio.run(create_user(args.email, args.admin))
    elif args.cmd == "health-check":
        asyncio.run(health_check(args.tool))


if __name__ == "__main__":
    main()
