from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AccessLog


def log_access(
    session: AsyncSession,
    action: str,
    *,
    user_id: uuid.UUID | None,
    case_id: uuid.UUID | None = None,
    ip: str | None = None,
    **detail: Any,
) -> None:
    """Queue an audit row on the session; committed with the caller's transaction."""
    session.add(AccessLog(case_id=case_id, user_id=user_id, action=action, ip=ip, detail=detail))
