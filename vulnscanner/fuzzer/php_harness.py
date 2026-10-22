"""PHP dynamic fuzzing harness.

Confirms command-injection and code-injection findings in PHP files by:
  1. Extracting the PHP function that contains the static finding
  2. Generating a minimal PHP wrapper script
  3. Running it via the `php` CLI with marker payloads
  4. Checking whether the marker appears in stdout (confirmed exploitation)

Only runs on LOCAL paths (enforced by FuzzTarget).
Requires `php` on PATH; silently skips if unavailable.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from vulnscanner.fuzzer.base import FuzzFinding, FuzzTarget
from vulnscanner.models import Finding, Severity, VulnType

# Marker injected into payloads — benign string unlikely to appear naturally
_MARKER = "VULNSCAN_CONFIRMED_7x3k9"

# Payloads per vulnerability type: (shell_input, description)
_CMD_PAYLOADS: list[tuple[str, str]] = [
    (f"; echo {_MARKER}", "semicolon injection"),
    (f"| echo {_MARKER}", "pipe injection"),
    (f"`echo {_MARKER}`", "backtick subshell"),
    (f"$(echo {_MARKER})", "dollar subshell"),
    (f"\n echo {_MARKER}", "newline injection"),
]

_EVAL_PAYLOADS: list[tuple[str, str]] = [
    (f"echo '{_MARKER}';", "echo statement"),
    (f"print('{_MARKER}');", "print statement"),
]

# PHP sinks that indicate command injection
_CMD_SINKS = re.compile(
    r'\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(',
    re.IGNORECASE,
)

# PHP sinks that indicate code injection
_EVAL_SINKS = re.compile(
    r'\beval\s*\(',
    re.IGNORECASE,
)

# Regex to find PHP function definitions
_FUNC_DEF_RE = re.compile(
    r'(?:public\s+|protected\s+|private\s+|static\s+)*'
    r'function\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*\??\w+\s*)?\{',
    re.MULTILINE,
)


def run(target: FuzzTarget, findings: list[Finding]) -> tuple[list[FuzzFinding], list[str]]:
    """Run PHP fuzzing against findings in PHP files.

    Returns (fuzz_findings, skipped_reasons).
    """
    if not shutil.which("php"):
        return [], ["php not found on PATH — install PHP CLI to enable PHP fuzzing"]

    fuzz_findings: list[FuzzFinding] = []
    skipped: list[str] = []

    php_findings = [f for f in findings if f.file_path.endswith(".php")]
    by_file: dict[str, list[Finding]] = {}
    for f in php_findings:
        by_file.setdefault(f.file_path, []).append(f)

    for rel_path, file_findings in by_file.items():
        abs_path = target.path / rel_path
        if not abs_path.exists():
            skipped.append(f"{rel_path}: file not found")
            continue

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped.append(f"{rel_path}: cannot read")
            continue

        for finding in file_findings:
            func_info = _find_enclosing_function(source, finding.line_number)
            if func_info is None:
                skipped.append(f"{rel_path}:{finding.line_number}: no enclosing function found")
                continue

            func_name, func_params, func_body = func_info
            payloads = _select_payloads(func_body)
            if not payloads:
                skipped.append(f"{rel_path}:{func_name}: no applicable payload type")
                continue

            results = _fuzz_php_function(
                func_name=func_name,
                func_params=func_params,
                func_body=func_body,
                payloads=payloads,
                file_path=rel_path,
                finding=finding,
                max_seconds=target.max_seconds,
            )
            fuzz_findings.extend(results)

    return fuzz_findings, skipped


# ── Internal helpers ───────────────────────────────────────────────────────────

def _find_enclosing_function(
    source: str,
    target_line: int,
) -> tuple[str, str, str] | None:
    """Return (func_name, params_str, body_str) of the function at target_line."""
    lines = source.splitlines(keepends=True)

    for m in _FUNC_DEF_RE.finditer(source):
        func_start_line = source[: m.start()].count("\n") + 1
        func_name = m.group(1)
        func_params = m.group(2).strip()

        # Find matching closing brace via brace counting
        brace_depth = 0
        func_end_line = func_start_line
        in_func = False
        for i, char in enumerate(source[m.start():], start=m.start()):
            if char == "{":
                brace_depth += 1
                in_func = True
            elif char == "}":
                brace_depth -= 1
                if in_func and brace_depth == 0:
                    func_end_line = source[: i].count("\n") + 1
                    break

        if func_start_line <= target_line <= func_end_line:
            body = "".join(lines[func_start_line - 1 : func_end_line])
            return func_name, func_params, body

    return None


def _select_payloads(func_body: str) -> list[tuple[str, str, VulnType]]:
    """Return (payload, description, vuln_type) tuples applicable to this function body."""
    payloads: list[tuple[str, str, VulnType]] = []
    if _CMD_SINKS.search(func_body):
        payloads += [(p, d, VulnType.COMMAND_INJECTION) for p, d in _CMD_PAYLOADS]
    if _EVAL_SINKS.search(func_body):
        payloads += [(p, d, VulnType.COMMAND_INJECTION) for p, d in _EVAL_PAYLOADS]
    return payloads


def _fuzz_php_function(
    func_name: str,
    func_params: str,
    func_body: str,
    payloads: list[tuple[str, str, VulnType]],
    file_path: str,
    finding: Finding,
    max_seconds: int,
) -> list[FuzzFinding]:
    """Build a PHP test harness, run it with each payload, check for marker."""
    results: list[FuzzFinding] = []
    deadline = time.monotonic() + max_seconds

    # Build the first parameter name to pass payloads into
    first_param = _extract_first_param(func_params)
    if not first_param:
        return []

    for payload, description, vuln_type in payloads:
        if time.monotonic() > deadline:
            break

        script = _build_php_script(func_name, func_body, first_param, payload)
        output = _run_php(script, timeout=10)
        if output is None:
            continue

        if _MARKER in output:
            results.append(FuzzFinding(
                payload=payload,
                exception_type="CommandExecution",
                exception_msg=f"Marker output confirmed: {description}",
                file_path=file_path,
                function_name=func_name,
                line_number=finding.line_number,
                vuln_type=vuln_type,
                severity=Severity.CRITICAL,
                confirmed=True,
                source_finding=finding,
            ))

    return results


def _extract_first_param(params_str: str) -> str:
    """Return the bare name of the first parameter (strips type hints and defaults)."""
    if not params_str.strip():
        return ""
    first = params_str.split(",")[0].strip()
    # Strip type hint: `string $name = 'x'` → `$name`
    m = re.search(r'\$(\w+)', first)
    return f"${m.group(1)}" if m else ""


def _build_php_script(
    func_name: str,
    func_body: str,
    first_param: str,
    payload: str,
) -> str:
    """Return a minimal PHP script that calls the target function with the payload."""
    escaped = payload.replace("'", "\\'")
    return (
        "<?php\n"
        "error_reporting(0);\n"
        f"{func_body}\n"
        f"${first_param.lstrip('$')}_input = '{escaped}';\n"
        f"try {{ {func_name}(${first_param.lstrip('$')}_input); }} "
        f"catch (Throwable $e) {{ /* ignore */ }}\n"
    )


def _run_php(script: str, timeout: int) -> str | None:
    """Write script to a temp file, run with `php`, return stdout or None on error."""
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".php", mode="w", encoding="utf-8", delete=False
        ) as tmp:
            tmp.write(script)
            tmp_path = tmp.name

        result = subprocess.run(
            ["php", tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except Exception:
        return None
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass
