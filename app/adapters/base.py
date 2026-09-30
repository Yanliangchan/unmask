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
import glob
import os
import re
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
    # Upper bound for one run of this tool (None = UNMASK_TOOL_TIMEOUT).
    timeout_seconds: ClassVar[int | None] = None
    # Fetch each reported account's page before keeping it (app/verify.py).
    verify_accounts: ClassVar[bool] = False
    # "fast" tools run in a Quick scan (about a minute or two); "slow" ones only in Deep.
    speed: ClassVar[str] = "fast"

    def configured(self) -> str | None:
        """Return why the tool can't run yet (e.g. a missing API key), or None.

        Unconfigured tools are skipped at dispatch and shown as such in the
        health panel. They must never run and report "nothing found".
        """
        return None

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
    # Files the tool wrote into its working directory, by relative path.
    files: dict[str, str] = field(default_factory=dict)


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


def _write_inputs(workdir: str, files_in: dict[str, str]) -> None:
    for rel, content in files_in.items():
        path = os.path.join(workdir, rel)
        # 0600 and O_EXCL: config files may hold API keys.
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as fh:
            fh.write(content)


def _collect_outputs(workdir: str, patterns: list[str]) -> dict[str, str]:
    files: dict[str, str] = {}
    for pattern in patterns:
        for path in sorted(glob.glob(os.path.join(workdir, pattern), recursive=True)):
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as fh:
                    files[os.path.relpath(path, workdir)] = fh.read(_MAX_OUTPUT_BYTES).decode("utf-8", "replace")
    return files


async def run_tool_subprocess(
    argv: list[str],
    *,
    timeout: float | None = None,  # noqa: ASYNC109 — also bounds process cleanup
    files_in: dict[str, str] | None = None,
    collect: list[str] | None = None,
    tool: str | None = None,
) -> ProcessResult:
    """Run a third-party tool with a scrubbed environment in a throwaway cwd.

    The child never inherits DATABASE_URL, encryption keys or the session
    secret. No shell is involved, so target values cannot inject commands.

    ``tool`` names the adapter, so a configured proxy can be applied to it
    (through the environment, never argv; see app/proxy.py).

    ``files_in`` are written into the working directory before the run (e.g. a
    config file holding API keys, which keeps them out of the process list);
    files matching the ``collect`` globs are read back afterwards.
    """
    timeout = timeout or get_settings().tool_timeout_seconds
    # Waiting for a slot doesn't count against the tool's timeout.
    async with _process_slot():
        return await _run_tool_process(argv, timeout, tool, files_in, collect)


# Command-line tools are whole processes (a Python interpreter plus the tool's
# site data, 50-500 MB each); running every one at once is what makes a scan's
# memory spike. Semaphores are per event loop: each RQ job runs its own loop.
_slots: dict[int, tuple[int, asyncio.Semaphore]] = {}


def _process_slot() -> asyncio.Semaphore:
    key = id(asyncio.get_running_loop())
    limit = max(1, get_settings().tool_processes)
    held = _slots.get(key)
    if held is None or held[0] != limit:
        if len(_slots) > 16:
            _slots.clear()
        held = _slots[key] = (limit, asyncio.Semaphore(limit))
    return held[1]


async def _run_tool_process(argv, timeout, tool, files_in, collect) -> ProcessResult:  # noqa: ASYNC109
    with tempfile.TemporaryDirectory(prefix="unmask-tool-") as workdir:
        await asyncio.to_thread(_write_inputs, workdir, files_in or {})
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
        if tool:
            from app.proxy import proxy_env

            env.update(proxy_env(tool))
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
        except asyncio.CancelledError:
            # The scan was stopped: never leave the tool running on its own.
            proc.kill()
            await asyncio.shield(proc.wait())
            raise
        files = await asyncio.to_thread(_collect_outputs, workdir, collect or [])
    return ProcessResult(
        returncode=proc.returncode or 0,
        stdout=stdout[:_MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
        stderr=stderr[:_MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
        files=files,
    )


# Colour codes, OSC-8 hyperlinks and carriage returns (progress bars).
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;;.*?\x1b\\|\r")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


# --- Input validation -------------------------------------------------------
# Target values end up on tool command lines; anything that could parse as an
# option or carry shell/URL metacharacters is refused outright.

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9\-]{1,63})+$"
)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def validate_email(value: str) -> str:
    value = value.strip()
    if value.startswith("-") or not _EMAIL_RE.match(value):
        raise InvalidTarget(f"'{value}' is not a plain email address")
    return value


def validate_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("-") or not _DOMAIN_RE.match(value):
        raise InvalidTarget(f"'{value}' is not a plain domain name")
    return value
