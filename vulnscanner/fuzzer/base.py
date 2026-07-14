"""Fuzzer base types and legal guardrails.

All fuzzing MUST operate on local paths only.
Network targets and production systems are explicitly refused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vulnscanner.models import Finding, VulnType, Severity
from vulnscanner.fuzzer.malware_check import MalwareWarning

# ── Legal disclaimer (shown before execution) ─────────────────────────────────

LEGAL_NOTICE = """
╔══════════════════════════════════════════════════════════╗
║      VulnScanner Fuzzer — Legal & Safety Notice          ║
╠══════════════════════════════════════════════════════════╣
║  This will EXECUTE code from the target repository.      ║
║                                                          ║
║  By proceeding you confirm:                              ║
║   • You own or have written permission to test this code ║
║   • This is NOT a live/production system                 ║
║   • Results will only be used for responsible disclosure ║
║   • No data will be sent to external systems             ║
╚══════════════════════════════════════════════════════════╝
"""

# Exceptions that indicate normal application behavior, not bugs.
# We do NOT report these as findings.
SAFE_EXCEPTIONS = (
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    NotImplementedError,
    StopIteration,
    UnicodeDecodeError,
    UnicodeEncodeError,
    PermissionError,
    FileNotFoundError,
    IsADirectoryError,
    OSError,
)


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class FuzzPayload:
    """A concrete test input derived from a static finding."""
    value: str
    vuln_type: VulnType
    description: str  # e.g. "SQL UNION-based injection"
    source_finding: Finding | None = None


@dataclass
class FuzzFinding:
    """A vulnerability confirmed or newly discovered through dynamic execution."""
    payload: str
    exception_type: str
    exception_msg: str
    file_path: str
    function_name: str
    line_number: int = 0
    vuln_type: VulnType = VulnType.COMMAND_INJECTION  # best guess
    severity: Severity = Severity.HIGH
    confirmed: bool = False   # True = matches a static finding
    source_finding: Finding | None = None

    def to_display(self) -> str:
        tag = "[CONFIRMED]" if self.confirmed else "[NEW]"
        return (
            f"  {tag} {self.function_name}() in {self.file_path}\n"
            f"    Payload   : {self.payload!r}\n"
            f"    Exception : {self.exception_type}: {self.exception_msg}"
        )


@dataclass
class FuzzResult:
    """Complete result of a fuzzing run."""
    target_path: Path
    static_findings: list[Finding] = field(default_factory=list)
    payloads: list[FuzzPayload] = field(default_factory=list)
    fuzz_findings: list[FuzzFinding] = field(default_factory=list)
    skipped_functions: list[str] = field(default_factory=list)
    malware_warnings: list[MalwareWarning] = field(default_factory=list)
    execution_blocked: bool = False
    error: str = ""

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.fuzz_findings if f.confirmed)

    @property
    def new_count(self) -> int:
        return sum(1 for f in self.fuzz_findings if not f.confirmed)


# ── Legal target validation ────────────────────────────────────────────────────

class FuzzTarget:
    """A validated, legally-scoped fuzzing target.

    Raises ValueError if the target is a network URL or does not exist.
    Only local filesystem paths are permitted.
    """

    def __init__(self, path: str, max_seconds: int = 30, max_examples: int = 300) -> None:
        # Hard block on network targets
        low = path.lower()
        if low.startswith(("http://", "https://", "ftp://", "ssh://", "git://", "github.com")):
            raise ValueError(
                "⚠️  Fuzzing is restricted to LOCAL paths.\n"
                "   Clone the repository first:\n"
                "     git clone <url> && vulnscan fuzz <local_path>"
            )

        resolved = Path(path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Path not found: {resolved}")
        if not resolved.is_dir():
            raise ValueError(f"Target must be a directory, not a file: {resolved}")

        self.path = resolved
        self.max_seconds = max_seconds
        self.max_examples = max_examples
