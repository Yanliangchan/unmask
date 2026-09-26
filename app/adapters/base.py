"""The tool adapter contract.

Every external OSINT tool is wrapped in a ToolAdapter. Adapters talk to tools
only through a subprocess or an HTTP API — third-party (often GPL) source code
is never imported into this codebase.

The single most important rule for an adapter: *an empty result must be
proven empty*. Bot-detection pages, rate-limit interstitials and "soft 200"
responses look like "nothing found" unless the adapter checks that the output
carries the signature of a genuine, completed run. When that signature is
missing the adapter raises ``SignatureMismatch`` instead of returning ``[]``.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

from app.config import get_settings


class AdapterError(Exception):
    """The tool could not produce a trustworthy result."""


class SignatureMismatch(AdapterError):
    """Output did not look like a genuine completed run (soft-200, bot wall, ...)."""


class InvalidTarget(AdapterError):
    """The target value is not acceptable input for this tool."""


@dataclass
class RawResult:
    tool: str
    target_value: str
    payload: Any
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class EntityCandidate:
    type: str
    value: str
    attributes: dict[str, Any] = field(default_factory=dict)
    # Admiralty scale A–F: trust in the source class, *not* identity confidence.
    source_reliability: str = "F"
    # Initial "same person" estimate before correlation refines it.
    confidence: float = 0.5
    field_confidence: dict[str, float] = field(default_factory=dict)
    # How this candidate relates to the target it was discovered from.
    relation_type: str | None = None
    relation_explanation: str | None = None


@dataclass
class HealthResult:
    ok: bool
    detail: str


class ToolAdapter(ABC):
    name: ClassVar[str]
    label: ClassVar[str]
    input_types: ClassVar[list[str]]
    description: ClassVar[str] = ""
    enabled_by_default: ClassVar[bool] = True
    # A target whose results are known, used by the health check.
    health_check_target: ClassVar[str | None] = None

    @abstractmethod
    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]: ...

    @abstractmethod
    def parse(self, raw: RawResult) -> list[EntityCandidate]: ...

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        """Validate a health-check run. Override with an adapter-specific signature."""
        if candidates:
            return HealthResult(True, f"{len(candidates)} results for known-good target")
        return HealthResult(False, "known-good target returned no results")

    async def health_check(self) -> HealthResult:
        if not self.health_check_target:
            return HealthResult(False, "no health-check target defined")
        try:
            raws = await self.run(self.health_check_target, [])
            candidates = [c for raw in raws for c in self.parse(raw)]
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        return self.check_health_output(candidates)


# --- Subprocess helper ------------------------------------------------------

_MAX_OUTPUT_BYTES = 8 * 1024 * 1024


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


def resolve_binary(name: str) -> str:
    bin_dir = get_settings().tools_bin_dir
    if bin_dir:
        candidate = os.path.join(bin_dir, name)
        if os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which(name)
    if not found:
        raise AdapterError(f"{name} is not installed")
    return found


async def run_tool_subprocess(argv: list[str], *, timeout: float | None = None) -> ProcessResult:  # noqa: ASYNC109
    """Run a third-party tool with a scrubbed environment in a throwaway cwd.

    The child never inherits DATABASE_URL, encryption keys or the session
    secret. No shell is involved, so target values cannot inject commands.
    """
    timeout = timeout or get_settings().tool_timeout_seconds
    with tempfile.TemporaryDirectory(prefix="unmask-tool-") as workdir:
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": workdir,
            "LANG": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
            "NO_COLOR": "1",
        }
        for passthrough in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
            if passthrough in os.environ:
                env[passthrough] = os.environ[passthrough]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=workdir,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise AdapterError(f"{argv[0]} is not installed") from exc
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise AdapterError(f"{os.path.basename(argv[0])} timed out after {timeout:.0f}s") from exc
    return ProcessResult(
        returncode=proc.returncode or 0,
        stdout=stdout[:_MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
        stderr=stderr[:_MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
    )
