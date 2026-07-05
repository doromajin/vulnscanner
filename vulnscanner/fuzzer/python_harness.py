"""Python dynamic fuzzing harness using Hypothesis.

Workflow:
  1. Locate the function containing a static finding
  2. Attempt to import it (graceful failure if deps are missing)
  3. Run known payloads first, then Hypothesis-generated strings
  4. Report unexpected exceptions as FuzzFindings
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import time
from pathlib import Path
from typing import Callable

from vulnscanner.fuzzer.base import FuzzFinding, FuzzTarget, SAFE_EXCEPTIONS
from vulnscanner.fuzzer.payload_gen import generate_payloads
from vulnscanner.models import Finding


def run(target: FuzzTarget, findings: list[Finding]) -> tuple[list[FuzzFinding], list[str]]:
    """Run Hypothesis fuzzing against Python functions identified by static findings.

    Returns (fuzz_findings, skipped_reasons).
    Skipped means the function could not be imported or is not testable.
    """
    fuzz_findings: list[FuzzFinding] = []
    skipped: list[str] = []

    # Group findings by file to avoid re-importing the same module multiple times
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.file_path.endswith(".py"):
            by_file.setdefault(f.file_path, []).append(f)

    for rel_path, file_findings in by_file.items():
        abs_path = target.path / rel_path
        if not abs_path.exists():
            skipped.append(f"{rel_path}: file not found")
            continue

        # Find function names from findings
        func_names = _find_functions_at_lines(
            abs_path, [f.line_number for f in file_findings]
        )
        if not func_names:
            skipped.append(f"{rel_path}: no function boundary found")
            continue

        # Try to import the module
        mod = _import_module(abs_path, target.path)
        if mod is None:
            skipped.append(f"{rel_path}: import failed (missing dependencies)")
            continue

        # Fuzz each identified function
        for func_name in func_names:
            func = getattr(mod, func_name, None)
            if func is None or not callable(func):
                skipped.append(f"{rel_path}:{func_name}: not callable")
                continue

            # Collect payloads relevant to findings in this function
            func_findings = [
                f for f in file_findings
                if _finding_in_function(abs_path, f.line_number, func_name)
            ]
            payloads = []
            seen_vals: set[str] = set()
            for ff in func_findings:
                for p in generate_payloads(ff):
                    if p.value not in seen_vals:
                        payloads.append(p)
                        seen_vals.add(p.value)

            results = _fuzz_function(
                func=func,
                func_name=func_name,
                file_path=rel_path,
                payloads=[p.value for p in payloads],
                source_findings=func_findings,
                max_examples=target.max_examples,
                max_seconds=target.max_seconds,
            )
            fuzz_findings.extend(results)

    return fuzz_findings, skipped


# ── Internal helpers ───────────────────────────────────────────────────────────

def _find_functions_at_lines(file_path: Path, lines: list[int]) -> list[str]:
    """Return function names that contain any of the given line numbers."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except Exception:
        return []

    names: list[str] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", None)
        if end is None:
            continue
        for ln in lines:
            if node.lineno <= ln <= end and node.name not in seen:
                names.append(node.name)
                seen.add(node.name)
                break
    return names


def _finding_in_function(file_path: Path, line: int, func_name: str) -> bool:
    """True if the given line falls inside the named function."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except Exception:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == func_name:
                end = getattr(node, "end_lineno", None)
                if end and node.lineno <= line <= end:
                    return True
    return False


def _import_module(file_path: Path, repo_root: Path):
    """Attempt to import a Python file as a module.

    Adds repo_root to sys.path temporarily so intra-repo imports work.
    Returns None on any import error.
    """
    saved_path = sys.path.copy()
    # Insert repo root so `from module import x` works
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    try:
        spec = importlib.util.spec_from_file_location("_vulnscanner_fuzz_target", file_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None
    finally:
        sys.path = saved_path


def _fuzz_function(
    func: Callable,
    func_name: str,
    file_path: str,
    payloads: list[str],
    source_findings: list[Finding],
    max_examples: int,
    max_seconds: int,
) -> list[FuzzFinding]:
    """Run payloads + Hypothesis against a single function."""
    results: list[FuzzFinding] = []
    seen_exceptions: set[str] = set()
    deadline = time.monotonic() + max_seconds

    def _try_call(value: str, confirmed: bool, sf: Finding | None) -> None:
        if time.monotonic() > deadline:
            return
        try:
            func(value)
        except SAFE_EXCEPTIONS:
            pass
        except Exception as exc:
            key = f"{type(exc).__name__}:{str(exc)[:80]}"
            if key in seen_exceptions:
                return
            seen_exceptions.add(key)
            results.append(FuzzFinding(
                payload=value[:300],
                exception_type=type(exc).__name__,
                exception_msg=str(exc)[:200],
                file_path=file_path,
                function_name=func_name,
                line_number=sf.line_number if sf else 0,
                vuln_type=sf.vuln_type if sf else source_findings[0].vuln_type
                           if source_findings else results[0].vuln_type
                           if results else __import__(
                               "vulnscanner.models", fromlist=["VulnType"]
                           ).VulnType.COMMAND_INJECTION,
                confirmed=confirmed,
                source_finding=sf,
            ))

    # Phase 1: known vulnerability payloads (guided)
    for payload in payloads:
        sf = source_findings[0] if source_findings else None
        _try_call(payload, confirmed=True, sf=sf)

    # Phase 2: Hypothesis property-based testing (broader coverage)
    if time.monotonic() < deadline:
        try:
            from hypothesis import given, settings, HealthCheck
            from hypothesis import strategies as st

            fuzz_results_ref: list[FuzzFinding] = []

            @given(st.text(max_size=256))
            @settings(
                max_examples=max_examples,
                deadline=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.large_base_example],
            )
            def _hyp_test(s: str) -> None:
                if time.monotonic() > deadline:
                    return
                try:
                    func(s)
                except SAFE_EXCEPTIONS:
                    pass
                except Exception as exc:
                    key = f"{type(exc).__name__}:{str(exc)[:80]}"
                    if key not in seen_exceptions:
                        seen_exceptions.add(key)
                        fuzz_results_ref.append(FuzzFinding(
                            payload=s[:300],
                            exception_type=type(exc).__name__,
                            exception_msg=str(exc)[:200],
                            file_path=file_path,
                            function_name=func_name,
                            confirmed=False,
                            source_finding=None,
                        ))

            _hyp_test()
            results.extend(fuzz_results_ref[:5])  # Cap Hypothesis new findings at 5

        except Exception:
            pass  # Hypothesis unavailable or test setup error

    return results
