"""Tool configuration, health state and the circuit breaker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.registry import all_adapters, get_adapter
from app.models import ToolConfig

CIRCUIT_BREAKER_THRESHOLD = 3


async def sync_tool_config(session: AsyncSession) -> None:
    """Make sure every registered adapter has a tool_config row."""
    for adapter in all_adapters():
        stmt = (
            insert(ToolConfig)
            .values(tool_name=adapter.name, enabled=adapter.enabled_by_default)
            .on_conflict_do_nothing(index_elements=[ToolConfig.tool_name])
        )
        await session.execute(stmt)
    await session.commit()


async def tool_configs(session: AsyncSession) -> dict[str, ToolConfig]:
    rows = (await session.scalars(select(ToolConfig))).all()
    return {row.tool_name: row for row in rows}


def record_success(cfg: ToolConfig) -> None:
    cfg.consecutive_failures = 0
    cfg.last_success_at = datetime.now(UTC)


def record_failure(cfg: ToolConfig, reason: str) -> bool:
    """Returns True if this failure tripped the circuit breaker."""
    cfg.consecutive_failures += 1
    cfg.last_failure_at = datetime.now(UTC)
    cfg.last_failure_reason = reason[:1000]
    if cfg.enabled and cfg.consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
        cfg.enabled = False
        cfg.circuit_open = True
        return True
    return False


@dataclass
class ToolHealth:
    name: str
    label: str
    status: str  # "ok" | "degraded" | "down" | "off"
    status_label: str
    detail: str


def health_of(cfg: ToolConfig) -> ToolHealth:
    adapter = get_adapter(cfg.tool_name)
    label = adapter.label if adapter else cfg.tool_name
    # A tool that can't work on this server says so first, whatever its past failures.
    missing = adapter.configured() if adapter else None
    if missing:
        return ToolHealth(cfg.tool_name, label, "off", "Not configured", missing)
    if cfg.circuit_open:
        return ToolHealth(
            cfg.tool_name,
            label,
            "down",
            "Circuit open",
            f"Auto-disabled after {cfg.consecutive_failures} consecutive failures: {cfg.last_failure_reason or ''}",
        )
    if not cfg.enabled:
        return ToolHealth(cfg.tool_name, label, "off", "Disabled", "Disabled by configuration")
    if cfg.last_health_ok is False:
        reason = (cfg.last_failure_reason or "").removeprefix("health check: ")
        return ToolHealth(cfg.tool_name, label, "degraded", "Degraded", f"Health check failed: {reason}")
    if cfg.consecutive_failures > 0:
        return ToolHealth(
            cfg.tool_name,
            label,
            "degraded",
            "Degraded",
            f"{cfg.consecutive_failures} consecutive failure(s): {cfg.last_failure_reason}",
        )
    return ToolHealth(cfg.tool_name, label, "ok", "Healthy", "No recent failures")


async def tool_health(session: AsyncSession) -> list[ToolHealth]:
    cfgs = await tool_configs(session)
    return [health_of(cfgs[name]) for name in sorted(cfgs) if get_adapter(name) is not None]


async def run_health_check(session: AsyncSession, tool_name: str) -> ToolHealth:
    """Re-run a tool against its known-good target; success closes the circuit."""
    adapter = get_adapter(tool_name)
    cfg = await session.get(ToolConfig, tool_name)
    if adapter is None or cfg is None:
        raise KeyError(tool_name)
    result = await adapter.health_check()
    cfg.last_health_check_at = datetime.now(UTC)
    cfg.last_health_ok = result.ok
    if result.ok:
        record_success(cfg)
        if cfg.circuit_open:
            cfg.circuit_open = False
            cfg.enabled = True
    else:
        cfg.last_failure_reason = f"health check: {result.detail}"[:1000]
    await session.commit()
    return health_of(cfg)
