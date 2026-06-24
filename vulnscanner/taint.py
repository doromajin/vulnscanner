"""
Three-state taint model for vulnerability analysis.

TaintStatus
-----------
TAINTED  — value is demonstrably derived from user-controlled input
UNKNOWN  — cannot determine origin; emit as needs_review at lower severity
CLEAN    — value is a literal, constant, or provably safe transformation

Usage in AST analyzer
---------------------
  taint = _taint_of(arg_node, assignments, class_attrs)
  if taint.status == TaintStatus.CLEAN:
      emit suppressed finding (suppression_reason="clean_taint_source")
  elif taint.status == TaintStatus.TAINTED:
      emit HIGH/CRITICAL finding
  else:  # UNKNOWN
      emit MEDIUM finding with "[needs_review]" label
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TaintStatus(Enum):
    TAINTED = "tainted"
    UNKNOWN = "unknown"
    CLEAN   = "clean"


@dataclass
class TaintInfo:
    status: TaintStatus
    reason: str
    source: Optional[str] = None
    sanitizers: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        return {
            TaintStatus.TAINTED: 0.9,
            TaintStatus.UNKNOWN: 0.5,
            TaintStatus.CLEAN:   0.0,
        }[self.status]

    def __str__(self) -> str:
        parts = [f"{self.status.value}: {self.reason}"]
        if self.source:
            parts.append(f"source={self.source}")
        if self.sanitizers:
            parts.append(f"sanitized_by={','.join(self.sanitizers)}")
        return "; ".join(parts)


# ── Pre-built singletons for common cases ─────────────────────────────────────

CLEAN_LITERAL = TaintInfo(TaintStatus.CLEAN, "literal constant")
CLEAN_BUILTIN = TaintInfo(TaintStatus.CLEAN, "Python built-in constant")
UNKNOWN_FUNCTION = TaintInfo(TaintStatus.UNKNOWN, "function call result")
UNKNOWN_UNRESOLVED = TaintInfo(TaintStatus.UNKNOWN, "unresolved variable")
