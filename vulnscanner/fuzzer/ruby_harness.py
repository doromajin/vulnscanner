"""Ruby dynamic fuzzing harness.

Confirms command-injection and code-injection findings in Ruby files by:
  1. Extracting the method that contains the static finding
  2. Generating a minimal Ruby wrapper script
  3. Running it via the `ruby` CLI with marker payloads
  4. Checking whether the marker appears in stdout (confirmed exploitation)

Only runs on LOCAL paths (enforced by FuzzTarget).
Requires `ruby` on PATH; silently skips if unavailable.
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

_MARKER = "VULNSCAN_CONFIRMED_7x3k9"

_CMD_PAYLOADS: list[tuple[str, str]] = [
    (f"; echo {_MARKER}", "semicolon injection"),
    (f"| echo {_MARKER}", "pipe injection"),
    (f"`echo {_MARKER}`", "backtick subshell"),
    (f"$(echo {_MARKER})", "dollar subshell"),
]

_EVAL_PAYLOADS: list[tuple[str, str]] = [
    (f"puts '{_MARKER}'", "puts statement"),
    (f"print '{_MARKER}'", "print statement"),
]

# Ruby sinks indicating command injection
_CMD_SINKS = re.compile(
    r'\b(?:system|exec|spawn|Kernel\.system|Kernel\.exec)\s*\('
    r'|IO\.popen\s*\('
    r'|`[^`]*#\{',   # string interpolation inside backtick
    re.IGNORECASE,
)

# Ruby sinks indicating code injection
_EVAL_SINKS = re.compile(r'\beval\s*\(', re.IGNORECASE)

# open("|cmd") — shell via Ruby's open()
_OPEN_PIPE = re.compile(r'\bopen\s*\(\s*["\']?\|', re.IGNORECASE)

# Ruby method definition
_METHOD_RE = re.compile(
    r'^\s*def\s+(\w+)\s*(\(([^)]*)\))?',
    re.MULTILINE,
)


def run(target: FuzzTarget, findings: list[Finding]) -> tuple[list[FuzzFinding], list[str]]:
    """Run Ruby fuzzing against findings in .rb files."""
    if not shutil.which("ruby"):
        return [], ["ruby not found on PATH — install Ruby to enable Ruby fuzzing"]

    fuzz_findings: list[FuzzFinding] = []
    skipped: list[str] = []

    ruby_findings = [f for f in findings if f.file_path.endswith(".rb")]
    by_file: dict[str, list[Finding]] = {}
    for f in ruby_findings:
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
            method_info = _find_enclosing_method(source, finding.line_number)
            if method_info is None:
                skipped.append(f"{rel_path}:{finding.line_number}: no enclosing method found")
                continue

            method_name, params, body = method_info
            payloads = _select_payloads(body)
            if not payloads:
                skipped.append(f"{rel_path}:{method_name}: no applicable payload type")
                continue

            results = _fuzz_ruby_method(
                method_name=method_name,
                params=params,
                body=body,
                payloads=payloads,
                file_path=rel_path,
                finding=finding,
                max_seconds=target.max_seconds,
            )
            fuzz_findings.extend(results)

    return fuzz_findings, skipped


# ── Internals ──────────────────────────────────────────────────────────────────

def _find_enclosing_method(
    source: str,
    target_line: int,
) -> tuple[str, str, str] | None:
    """Return (method_name, params_str, body) of the method at target_line."""
    lines = source.splitlines(keepends=True)

    for m in _METHOD_RE.finditer(source):
        method_name = m.group(1)
        params = m.group(3) or ""
        method_start = source[: m.start()].count("\n") + 1

        # Find matching `end` via depth counting (def/do/if... increment, end decrements)
        _OPEN_KW = re.compile(r'\b(?:def|do|begin|if|unless|while|until|for|case|class|module)\b')
        _CLOSE_KW = re.compile(r'\bend\b')
        depth = 0
        method_end = method_start
        for i, line in enumerate(lines[method_start - 1:], start=method_start):
            depth += len(_OPEN_KW.findall(line))
            depth -= len(_CLOSE_KW.findall(line))
            if depth <= 0:
                method_end = i
                break

        if method_start <= target_line <= method_end:
            body = "".join(lines[method_start - 1 : method_end])
            return method_name, params, body

    return None


def _select_payloads(body: str) -> list[tuple[str, str, VulnType]]:
    """Return (payload, description, vuln_type) applicable to this method body."""
    payloads: list[tuple[str, str, VulnType]] = []
    if _CMD_SINKS.search(body) or _OPEN_PIPE.search(body):
        payloads += [(p, d, VulnType.COMMAND_INJECTION) for p, d in _CMD_PAYLOADS]
    if _EVAL_SINKS.search(body):
        payloads += [(p, d, VulnType.COMMAND_INJECTION) for p, d in _EVAL_PAYLOADS]
    return payloads


def _fuzz_ruby_method(
    method_name: str,
    params: str,
    body: str,
    payloads: list[tuple[str, str, VulnType]],
    file_path: str,
    finding: Finding,
    max_seconds: int,
) -> list[FuzzFinding]:
    """Build a Ruby test harness, run it with each payload, check for marker."""
    results: list[FuzzFinding] = []
    deadline = time.monotonic() + max_seconds

    first_param = _extract_first_param(params)
    if not first_param:
        return []

    for payload, description, vuln_type in payloads:
        if time.monotonic() > deadline:
            break

        script = _build_ruby_script(method_name, body, first_param, payload)
        output = _run_ruby(script, timeout=10)
        if output is None:
            continue

        if _MARKER in output:
            results.append(FuzzFinding(
                payload=payload,
                exception_type="CommandExecution",
                exception_msg=f"Marker confirmed: {description}",
                file_path=file_path,
                function_name=method_name,
                line_number=finding.line_number,
                vuln_type=vuln_type,
                severity=Severity.CRITICAL,
                confirmed=True,
                source_finding=finding,
            ))

    return results


def _extract_first_param(params: str) -> str:
    """Return the first bare parameter name."""
    if not params.strip():
        return ""
    first = params.split(",")[0].strip()
    m = re.match(r'(\w+)', first)
    return m.group(1) if m else ""


def _build_ruby_script(
    method_name: str,
    body: str,
    first_param: str,
    payload: str,
) -> str:
    """Return a minimal Ruby script that calls the method with the payload."""
    escaped = payload.replace("'", "\\'")
    return (
        f"{body}\n"
        f"begin\n"
        f"  {method_name}('{escaped}')\n"
        f"rescue => e\n"
        f"  # ignore\n"
        f"end\n"
    )


def _run_ruby(script: str, timeout: int) -> str | None:
    """Write script to a temp file, run with `ruby`, return stdout or None."""
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".rb", mode="w", encoding="utf-8", delete=False
        ) as tmp:
            tmp.write(script)
            tmp_path = tmp.name

        result = subprocess.run(
            ["ruby", tmp_path],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout
    except Exception:
        return None
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass
