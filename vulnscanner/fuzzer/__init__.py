"""VulnScanner fuzzing module.

Public API:
  from vulnscanner.fuzzer import run_fuzz, FuzzResult, FuzzTarget
"""
from vulnscanner.fuzzer.base import FuzzFinding, FuzzPayload, FuzzResult, FuzzTarget, LEGAL_NOTICE
from vulnscanner.fuzzer.runner import run_fuzz

__all__ = [
    "run_fuzz",
    "FuzzFinding",
    "FuzzPayload",
    "FuzzResult",
    "FuzzTarget",
    "LEGAL_NOTICE",
]
