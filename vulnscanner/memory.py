"""Memory-based limit for the number of scan worker processes.

Every worker process keeps its own copy of the repository text (`all_contents`) plus the analyzers and
the parse trees of the file it is working on, so N workers cost N times that.  The cap below is
``usable memory / peak memory of one worker``, measured on this scanner:

    one worker ~= WORKER_BASE_BYTES + WORKER_TEXT_FACTOR * (size of the repository text)
    parent     ~= PARENT_BASE_BYTES + PARENT_TEXT_FACTOR * (size of the repository text)

``VULNSCANNER_MEMORY_BUDGET_MB`` replaces the detected free memory (tests, containers, shared machines).
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys

MB = 1024 * 1024

# Calibrated with PeakWorkingSet64 of real scans on Windows (pixelfed: 16.7 MB of source -> workers
# 100-175 MB; librenms: 146 MB -> 215-231 MB, parent ~230 MB), then rounded up for headroom.  The state is
# handed to the workers through a file, so each one holds the repository text once.
WORKER_BASE_BYTES = 150 * MB
WORKER_TEXT_FACTOR = 1.0
PARENT_BASE_BYTES = 150 * MB
PARENT_TEXT_FACTOR = 1.0
# Share of the free memory the scan may plan to use; the rest is for the OS, the browser, the IDE.
USABLE_FRACTION = 0.6


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def available_memory_bytes() -> int | None:
    """Free physical memory (what a new process can use without swapping), or None if unknown."""
    override = os.environ.get("VULNSCANNER_MEMORY_BUDGET_MB")
    if override:
        try:
            return int(float(override) * MB)
        except ValueError:
            pass
    try:
        if sys.platform == "win32":
            status = _MemoryStatusEx()
            status.dwLength = ctypes.sizeof(_MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
                return int(status.ullAvailPhys)
            return None
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo", encoding="ascii") as fh:
                for line in fh:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
            return None
        if sys.platform == "darwin":
            out = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=5).stdout
            page = 4096
            free = 0
            for line in out.splitlines():
                if "page size of" in line:
                    page = int(line.split("page size of")[1].split()[0])
                elif line.split(":")[0] in ("Pages free", "Pages inactive", "Pages speculative"):
                    free += int(line.split(":")[1].strip().rstrip("."))
            return free * page or None
    except Exception:  # noqa: BLE001 - an unreadable meminfo must never stop a scan
        return None
    return None


def worker_memory_bytes(text_bytes: int) -> int:
    """Planned peak memory of one worker process for a repository holding *text_bytes* of source."""
    return int(WORKER_BASE_BYTES + WORKER_TEXT_FACTOR * text_bytes)


def max_workers_for_memory(text_bytes: int, available_bytes: int | None) -> int | None:
    """Most worker processes the free memory can carry (>= 0); None when the free memory is unknown."""
    if available_bytes is None:
        return None
    parent = PARENT_BASE_BYTES + PARENT_TEXT_FACTOR * text_bytes
    budget = available_bytes * USABLE_FRACTION - parent
    if budget <= 0:
        return 0
    return int(budget // worker_memory_bytes(text_bytes))
