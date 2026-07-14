"""Orchestrate the full fuzzing pipeline.

Pipeline:
  1. Static analysis (uses existing VulnScanner)
  2. Payload generation from findings (always runs)
  3. Python dynamic execution via Hypothesis (runs if imports succeed)
"""
from __future__ import annotations

from pathlib import Path

from vulnscanner.fuzzer.base import FuzzResult, FuzzTarget
from vulnscanner.fuzzer.malware_check import BLOCK, scan_for_malware
from vulnscanner.fuzzer.payload_gen import generate_all_payloads


def run_fuzz(
    target_path: str,
    *,
    execute: bool = True,
    max_seconds: int = 30,
    max_examples: int = 300,
    github_token: str | None = None,
) -> FuzzResult:
    """Run the full fuzz pipeline on a local repository.

    Args:
        target_path:  Local directory path (network URLs are rejected).
        execute:      If False, skip dynamic execution and only generate payloads.
        max_seconds:  Per-function execution time limit.
        max_examples: Hypothesis max_examples per function.
        github_token: Unused (local only), kept for API symmetry.

    Returns:
        FuzzResult with payloads and any dynamic findings.
    """
    target = FuzzTarget(target_path, max_seconds=max_seconds, max_examples=max_examples)

    result = FuzzResult(target_path=target.path)

    # Step 0: Malware pre-flight scan (static, never executes code)
    result.malware_warnings = scan_for_malware(target.path)
    if any(w.severity == BLOCK for w in result.malware_warnings):
        result.execution_blocked = True
        execute = False

    # Step 1: Static analysis
    from vulnscanner.scanner import VulnScanner
    scanner = VulnScanner()
    scan_result = scanner.scan(str(target.path))
    result.static_findings = scan_result.findings

    # Filter out suppressed / INFO findings for fuzzing focus
    actionable = [
        f for f in result.static_findings
        if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM")
        and not getattr(f, "suppression_reason", None)
    ]

    # Step 2: Payload generation (always runs)
    result.payloads = generate_all_payloads(actionable)

    # Step 3: Dynamic execution (Python only, optional)
    if execute and actionable:
        from vulnscanner.fuzzer import python_harness
        fuzz_findings, skipped = python_harness.run(target, actionable)
        result.fuzz_findings = fuzz_findings
        result.skipped_functions = skipped

    return result
