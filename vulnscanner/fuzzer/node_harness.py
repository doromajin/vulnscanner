"""Node.js dynamic fuzzing harness.

Confirms command-injection and code-injection findings in JS/TS files by:
  1. Extracting the function that contains the static finding
  2. Generating a minimal Node.js wrapper script
  3. Running it via the `node` CLI with marker payloads
  4. Checking whether the marker appears in stdout (confirmed exploitation)

Only runs on LOCAL paths (enforced by FuzzTarget).
Requires `node` on PATH; silently skips if unavailable.
Supports: .js .mjs .cjs .ts .jsx .tsx
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
    (f"& echo {_MARKER}", "ampersand injection (Windows)"),
    (f"`echo {_MARKER}`", "backtick subshell"),
    (f"$(echo {_MARKER})", "dollar subshell"),
]

_EVAL_PAYLOADS: list[tuple[str, str]] = [
    (f"process.stdout.write('{_MARKER}')", "stdout write"),
    (f"console.log('{_MARKER}')", "console.log"),
]

_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}

# Node.js sinks for command injection
_CMD_SINKS = re.compile(
    r'\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\('
    r'|child_process\.',
    re.IGNORECASE,
)

# Node.js sinks for code injection
_EVAL_SINKS = re.compile(
    r'\beval\s*\('
    r'|new\s+Function\s*\(',
    re.IGNORECASE,
)

# Template literal with variable — potential injection via interpolation
_TEMPLATE_CMD = re.compile(r'`[^`]*\$\{[^}]+\}[^`]*`', re.DOTALL)

# JS function patterns to locate enclosing function
_FUNC_PATTERNS = [
    # function foo(params) {
    re.compile(r'\bfunction\s+(\w+)\s*\(([^)]*)\)\s*\{', re.MULTILINE),
    # const/let/var foo = (params) => {
    re.compile(r'\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>\s*\{', re.MULTILINE),
    # const/let/var foo = function(params) {
    re.compile(r'\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{', re.MULTILINE),
    # foo(params) { — class method
    re.compile(r'^\s+(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{', re.MULTILINE),
]


def run(target: FuzzTarget, findings: list[Finding]) -> tuple[list[FuzzFinding], list[str]]:
    """Run Node.js fuzzing against findings in JS/TS files."""
    if not shutil.which("node"):
        return [], ["node not found on PATH — install Node.js to enable JS/TS fuzzing"]

    fuzz_findings: list[FuzzFinding] = []
    skipped: list[str] = []

    js_findings = [
        f for f in findings
        if Path(f.file_path).suffix in _JS_EXTENSIONS
    ]
    by_file: dict[str, list[Finding]] = {}
    for f in js_findings:
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

            func_name, params, body = func_info
            payloads = _select_payloads(body)
            if not payloads:
                skipped.append(f"{rel_path}:{func_name}: no applicable payload type")
                continue

            results = _fuzz_js_function(
                func_name=func_name,
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

def _find_enclosing_function(
    source: str,
    target_line: int,
) -> tuple[str, str, str] | None:
    """Return (func_name, params_str, body) of the function at target_line."""
    lines = source.splitlines(keepends=True)

    best: tuple[int, int, str, str] | None = None  # (start, end, name, params)

    for pattern in _FUNC_PATTERNS:
        for m in pattern.finditer(source):
            func_name = m.group(1)
            params = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
            func_start = source[: m.start()].count("\n") + 1

            # Find closing brace via depth counting
            start_pos = m.end() - 1  # position of opening '{'
            depth = 0
            func_end = func_start
            char_count = 0
            for i, line in enumerate(lines[func_start - 1:], start=func_start):
                for ch in line:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth <= 0:
                            func_end = i
                            break
                else:
                    continue
                break

            if func_start <= target_line <= func_end:
                # Prefer smallest (most specific) enclosing function
                span = func_end - func_start
                if best is None or span < (best[1] - best[0]):
                    best = (func_start, func_end, func_name, params)

    if best is None:
        return None

    func_start, func_end, func_name, params = best
    body = "".join(lines[func_start - 1 : func_end])
    return func_name, params, body


def _select_payloads(body: str) -> list[tuple[str, str, VulnType]]:
    """Return (payload, description, vuln_type) applicable to this function body."""
    payloads: list[tuple[str, str, VulnType]] = []
    if _CMD_SINKS.search(body) or _TEMPLATE_CMD.search(body):
        payloads += [(p, d, VulnType.COMMAND_INJECTION) for p, d in _CMD_PAYLOADS]
    if _EVAL_SINKS.search(body):
        payloads += [(p, d, VulnType.COMMAND_INJECTION) for p, d in _EVAL_PAYLOADS]
    return payloads


def _fuzz_js_function(
    func_name: str,
    params: str,
    body: str,
    payloads: list[tuple[str, str, VulnType]],
    file_path: str,
    finding: Finding,
    max_seconds: int,
) -> list[FuzzFinding]:
    """Build a Node.js test harness, run it with each payload, check for marker."""
    results: list[FuzzFinding] = []
    deadline = time.monotonic() + max_seconds

    first_param = _extract_first_param(params)
    if not first_param:
        return []

    for payload, description, vuln_type in payloads:
        if time.monotonic() > deadline:
            break

        script = _build_node_script(func_name, body, first_param, payload)
        output = _run_node(script, timeout=10)
        if output is None:
            continue

        if _MARKER in output:
            results.append(FuzzFinding(
                payload=payload,
                exception_type="CommandExecution",
                exception_msg=f"Marker confirmed: {description}",
                file_path=file_path,
                function_name=func_name,
                line_number=finding.line_number,
                vuln_type=vuln_type,
                severity=Severity.CRITICAL,
                confirmed=True,
                source_finding=finding,
            ))

    return results


def _extract_first_param(params: str) -> str:
    """Return the first bare parameter name (handles defaults, destructuring)."""
    if not params.strip():
        return ""
    first = params.split(",")[0].strip()
    # Strip TypeScript type annotation: `name: string` → `name`
    first = first.split(":")[0].strip()
    # Strip default value: `name = 'foo'` → `name`
    first = first.split("=")[0].strip()
    # Strip destructuring: `{ id }` → skip (can't inject cleanly)
    if first.startswith("{") or first.startswith("["):
        return ""
    m = re.match(r'(\w+)', first)
    return m.group(1) if m else ""


def _build_node_script(
    func_name: str,
    body: str,
    first_param: str,
    payload: str,
) -> str:
    """Return a minimal Node.js script that calls the function with the payload."""
    # Strip TypeScript annotations for plain node execution
    stripped = _strip_typescript(body)
    escaped = payload.replace("'", "\\'").replace("\\", "\\\\")
    return (
        f"const child_process = require('child_process');\n"
        f"const {{ exec, execSync, spawn, spawnSync, execFile, execFileSync }} = child_process;\n"
        f"{stripped}\n"
        f"try {{\n"
        f"  const _result = {func_name}('{escaped}');\n"
        f"  if (_result && typeof _result.then === 'function') {{\n"
        f"    _result.catch(() => {{}});\n"
        f"  }}\n"
        f"}} catch(e) {{ /* ignore */ }}\n"
    )


def _strip_typescript(body: str) -> str:
    """Remove TypeScript-specific syntax so plain `node` can run the code."""
    # Remove type annotations on parameters: (x: string) → (x)
    body = re.sub(r'(\w)\s*:\s*[\w<>\[\]|&\s]+(?=[,)])', r'\1', body)
    # Remove return type annotations: ): string { → ) {
    body = re.sub(r'\)\s*:\s*[\w<>\[\]|&\s]+\s*\{', ') {', body)
    # Remove `async` keyword (node handles it but await needs --experimental-vm-modules)
    # Keep as-is; node supports async/await natively
    return body


def _run_node(script: str, timeout: int) -> str | None:
    """Write script to a temp .js file, run with `node`, return stdout or None."""
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".js", mode="w", encoding="utf-8", delete=False
        ) as tmp:
            tmp.write(script)
            tmp_path = tmp.name

        result = subprocess.run(
            ["node", tmp_path],
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
