#!/usr/bin/env python3
"""
recall_check.py — VulnScanner detection-rate (recall) validation.

Scans the `recall/` directory, which contains deliberately vulnerable code
snippets covering every major detection category, and verifies that each
expected finding is present with the correct rule ID and severity.

Usage:
    python recall_check.py           # scan recall/ relative to this file
    python recall_check.py --verbose # also print all actual findings

Exit codes:
    0  all checks pass
    1  one or more checks failed
"""
from __future__ import annotations

import argparse
import os
import sys

from vulnscanner.models import Severity
from vulnscanner.scanner import VulnScanner

RECALL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recall")

# ── Expected findings ─────────────────────────────────────────────────────────
# Each entry: (rule_id, file_suffix, expected_severity, description)
# file_suffix is matched against the end of the normalised file path.

EXPECTED: list[tuple[str, str, str, str]] = [
    # ── JavaScript ────────────────────────────────────────────────────────────
    ("XSS-001",       "js/xss.js",                       "HIGH",     "innerHTML XSS"),

    # ── PHP ───────────────────────────────────────────────────────────────────
    ("DESER-004",     "php/deser.php",                   "CRITICAL", "PHP unserialize() RCE"),
    ("SQL-004",       "php/sqli.php",                    "HIGH",     "PHP SQL string concatenation"),
    ("XSS-005",       "php/xss.php",                    "HIGH",     "PHP echo $_GET"),

    # ── Python: command injection ─────────────────────────────────────────────
    ("AST-CMD-001",   "python/command_injection.py",     "HIGH",     "os.system() with tainted arg"),
    ("AST-CMD-002",   "python/command_injection.py",     "HIGH",     "subprocess shell=True with tainted arg"),
    ("AST-CMD-003",   "python/eval_injection.py",        "CRITICAL", "eval() with tainted arg"),
    ("AST-CMD-004",   "python/exec_injection.py",        "CRITICAL", "exec() with tainted arg"),

    # ── Python: SQL injection ─────────────────────────────────────────────────
    ("AST-SQL-001",   "python/sql_injection.py",         "HIGH",     "SQL injection via f-string"),
    ("AST-SQL-002",   "python/sql_injection.py",         "HIGH",     "SQL injection via concatenation"),

    # ── Python: path traversal ────────────────────────────────────────────────
    ("AST-PATH-001",  "python/path_traversal.py",        "HIGH",     "open() with tainted variable path"),
    ("AST-PATH-002",  "python/path_traversal.py",        "HIGH",     "open() with tainted concatenated path"),

    # ── Python: SSRF ──────────────────────────────────────────────────────────
    ("AST-SSRF-001",  "python/ssrf.py",                  "HIGH",     "requests.get() with URL from user input"),

    # ── Python: deserialization ───────────────────────────────────────────────
    ("AST-DESER-001", "python/deserialization.py",       "CRITICAL", "pickle.loads() arbitrary object deserialization"),
    ("AST-DESER-004", "python/deserialization.py",       "HIGH",     "yaml.load() without Loader="),

    # ── Python: SSTI ─────────────────────────────────────────────────────────
    ("AST-SSTI-002",  "python/ssti.py",                  "HIGH",     "Jinja2 Environment.from_string() non-literal"),

    # ── Python: sanitizer bypass (taint propagation validation) ───────────────
    # html.escape() wraps tainted SQL input; taint must stay TAINTED so that
    # the SQL injection finding is NOT suppressed (FuguAI fix: commit 5b4815a).
    ("AST-SQL-002",   "python/sanitizer_bypass.py",      "HIGH",     "html.escape() does NOT suppress SQL injection"),

    # ── PHP: 1-hop taint (XSS-008) ────────────────────────────────────────────
    # $_GET/$_POST assigned to variable, then echoed without htmlspecialchars().
    ("XSS-008",       "php/xss_1hop.php",                "HIGH",     "PHP XSS 1-hop ($_GET → $var → echo)"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm(path: str) -> str:
    return path.replace("\\", "/").lower()


def _matches(finding_path: str, suffix: str) -> bool:
    n = _norm(finding_path)
    s = suffix.replace("\\", "/").lower()
    return n.endswith(s)


def _sev_value(sev: Severity | str) -> str:
    if isinstance(sev, Severity):
        return sev.value
    return str(sev)


# ── Main ──────────────────────────────────────────────────────────────────────

def run(verbose: bool = False) -> int:
    if not os.path.isdir(RECALL_DIR):
        print(f"[ERROR] recall/ directory not found at {RECALL_DIR}", file=sys.stderr)
        return 1

    print(f"Scanning {RECALL_DIR} ...", file=sys.stderr)
    result = VulnScanner().scan(RECALL_DIR)
    findings = result.findings

    if verbose:
        print("\n── All findings ──────────────────────────────────────────")
        for f in sorted(findings, key=lambda x: (x.file_path, x.line_number)):
            rel = f.file_path.replace("\\", "/").split("/recall/")[-1]
            print(f"  {f.rule_id:<18} {_sev_value(f.severity):<10} {rel}:{f.line_number}")
        print()

    passes: list[str] = []
    fails: list[str] = []

    for rule_id, file_suffix, expected_sev, desc in EXPECTED:
        matched = [
            f for f in findings
            if f.rule_id == rule_id
            and _matches(f.file_path, file_suffix)
            and f.suppression_reason is None
        ]
        if not matched:
            fails.append(f"MISS  {rule_id:<18} {file_suffix:<40} — {desc}")
            continue

        wrong_sev = [f for f in matched if _sev_value(f.severity) != expected_sev]
        if wrong_sev:
            actual = _sev_value(wrong_sev[0].severity)
            fails.append(
                f"SEV   {rule_id:<18} {file_suffix:<40} — {desc} "
                f"(expected {expected_sev}, got {actual})"
            )
        else:
            passes.append(f"OK    {rule_id:<18} {file_suffix}")

    # ── Print results ──────────────────────────────────────────────────────────
    print(f"\n── recall_check results ({'─' * 46})")
    for msg in passes:
        print(f"  \033[32m{msg}\033[0m")
    for msg in fails:
        print(f"  \033[31m{msg}\033[0m")

    total = len(EXPECTED)
    n_pass = len(passes)
    n_fail = len(fails)
    print(f"\n  {n_pass}/{total} checks passed", end="")
    if result.suppressed_count:
        print(f"  ({result.suppressed_count} finding(s) suppressed: {result.suppression_breakdown})", end="")
    print()

    if n_fail:
        print(f"\n  \033[31m{n_fail} check(s) FAILED\033[0m")
        return 1

    print(f"\n  \033[32mAll {total} checks passed.\033[0m")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScanner recall validation")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print all findings before check results")
    args = parser.parse_args()
    sys.exit(run(verbose=args.verbose))
