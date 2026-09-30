"""Handing memory back to the OS after bursts of work.

CPython frees objects into glibc's heap, which keeps the pages for reuse. After
a scan (thousands of rows, parsed tool output) that can leave tens of MB
resident that nothing uses. ``trim()`` collects cycles and asks glibc to return
free heap pages; it is cheap (a few ms) and a no-op on other C libraries.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import gc
import logging

log = logging.getLogger(__name__)

_libc = None
_looked_up = False


def _malloc_trim():
    global _libc, _looked_up
    if not _looked_up:
        _looked_up = True
        try:
            lib = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
            _libc = lib if hasattr(lib, "malloc_trim") else None
        except OSError:
            _libc = None
    return _libc


def rss_mb() -> float:
    """Resident memory of this process in MB (0 where /proc isn't available)."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


def trim() -> None:
    gc.collect()
    libc = _malloc_trim()
    if libc is not None:
        try:
            libc.malloc_trim(0)
        except Exception:  # noqa: BLE001 — best effort, never fatal
            log.debug("malloc_trim failed", exc_info=True)
