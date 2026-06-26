#!/usr/bin/env python3
"""
recall_check.py — VulnScanner strict recall + precision validation.

Two-sided check:
  Recall    — every entry in EXPECTED is present with the correct severity.
  Precision — every active finding in recall/ matches an entry in EXPECTED
              (zero unexpected findings / false positives).

Usage:
    python recall_check.py           # strict mode (default)
    python recall_check.py --verbose # also print all findings before results

Exit codes:
    0  all recall AND precision checks pass
    1  one or more checks failed
"""
from __future__ import annotations

import argparse
import os
import sys

from vulnscanner.models import Finding, Severity
from vulnscanner.scanner import VulnScanner

RECALL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recall")

# ── Expected findings ─────────────────────────────────────────────────────────
# Each entry: (rule_id, file_suffix, expected_severity, description)
#
# file_suffix is matched against the TAIL of the normalised finding path, so
# "php/xss.js" matches any path that ends with that string.
#
# One entry covers ALL findings with that (rule_id, file_suffix) pair —
# a file may produce multiple lines with the same rule; they are all allowed.
# Any finding NOT covered by any entry → EXTRA (precision failure).

EXPECTED: list[tuple[str, str, str, str]] = [
    # ── JavaScript ────────────────────────────────────────────────────────────
    ("XSS-001",       "js/xss.js",                    "HIGH",     "innerHTML XSS"),

    # ── PHP ───────────────────────────────────────────────────────────────────
    ("DESER-004",     "php/deser.php",                "CRITICAL", "PHP unserialize() RCE"),
    ("SQL-004",       "php/sqli.php",                 "HIGH",     "PHP SQL string concatenation"),
    ("XSS-005",       "php/xss.php",                  "HIGH",     "PHP echo $_GET / $_POST"),
    ("XSS-008",       "php/xss_1hop.php",             "HIGH",     "PHP XSS 1-hop ($_GET/$_POST → $var → echo)"),

    # ── Python: command injection ─────────────────────────────────────────────
    ("AST-CMD-001",   "python/command_injection.py",  "HIGH",     "os.system() with tainted arg"),
    ("AST-CMD-002",   "python/command_injection.py",  "HIGH",     "subprocess shell=True with tainted arg"),
    ("AST-CMD-003",   "python/eval_injection.py",     "CRITICAL", "eval() with tainted arg"),
    ("AST-CMD-004",   "python/exec_injection.py",     "CRITICAL", "exec() with tainted arg"),

    # ── Python: SQL injection ─────────────────────────────────────────────────
    ("AST-SQL-001",   "python/sql_injection.py",      "HIGH",     "SQL injection via f-string"),
    ("AST-SQL-002",   "python/sql_injection.py",      "HIGH",     "SQL injection via concatenation"),

    # ── Python: path traversal ────────────────────────────────────────────────
    ("AST-PATH-001",  "python/path_traversal.py",     "HIGH",     "open() with tainted variable path"),
    ("AST-PATH-002",  "python/path_traversal.py",     "HIGH",     "open() with tainted concatenated path"),

    # ── Python: SSRF ──────────────────────────────────────────────────────────
    ("AST-SSRF-001",  "python/ssrf.py",               "HIGH",     "requests.get() with URL from user input"),

    # ── Python: deserialization ───────────────────────────────────────────────
    ("AST-DESER-001", "python/deserialization.py",    "CRITICAL", "pickle.loads() arbitrary object deserialization"),
    ("AST-DESER-004", "python/deserialization.py",    "HIGH",     "yaml.load() without Loader="),

    # ── Python: SSTI ─────────────────────────────────────────────────────────
    ("AST-SSTI-002",  "python/ssti.py",               "HIGH",     "Jinja2 Environment.from_string() non-literal"),

    # ── Python: sanitizer bypass ──────────────────────────────────────────────
    # html.escape() wraps tainted SQL input — taint must stay TAINTED so that
    # the finding is NOT suppressed (commit 5b4815a).
    ("AST-SQL-002",   "python/sanitizer_bypass.py",   "HIGH",     "html.escape() does NOT suppress SQL injection"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm(path: str) -> str:
    return path.replace("\\", "/").lower()


def _matches(finding_path: str, suffix: str) -> bool:
    return _norm(finding_path).endswith(suffix.replace("\\", "/").lower())


def _sev(f: Finding) -> str:
    s = f.severity
    return s.value if isinstance(s, Severity) else str(s)


def _rel(f: Finding) -> str:
    return f.file_path.replace("\\", "/").split("/recall/")[-1]


def _is_expected(f: Finding) -> bool:
    """Return True if finding is covered by any EXPECTED entry."""
    return any(
        f.rule_id == rule_id and _matches(f.file_path, suffix)
        for rule_id, suffix, _, _ in EXPECTED
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def run(verbose: bool = False) -> int:
    if not os.path.isdir(RECALL_DIR):
        print(f"[ERROR] recall/ directory not found at {RECALL_DIR}", file=sys.stderr)
        return 1

    print(f"Scanning {RECALL_DIR} ...", file=sys.stderr)
    result = VulnScanner().scan(RECALL_DIR)
    active = [f for f in result.findings if f.suppression_reason is None]

    if verbose:
        print("\n── All active findings ───────────────────────────────────")
        for f in sorted(active, key=lambda x: (x.file_path, x.line_number)):
            print(f"  {f.rule_id:<18} {_sev(f):<10} {_rel(f)}:{f.line_number}")
        print()

    passes: list[str] = []
    fails:  list[str] = []

    # ── Recall: every expected entry must have at least one matching finding ──
    for rule_id, suffix, exp_sev, desc in EXPECTED:
        matched = [
            f for f in active
            if f.rule_id == rule_id and _matches(f.file_path, suffix)
        ]
        if not matched:
            fails.append(f"MISS  {rule_id:<18} {suffix:<38} — {desc}")
            continue
        wrong = [f for f in matched if _sev(f) != exp_sev]
        if wrong:
            fails.append(
                f"SEV   {rule_id:<18} {suffix:<38} — {desc} "
                f"(want {exp_sev}, got {_sev(wrong[0])})"
            )
        else:
            passes.append(f"[recall]    OK  {rule_id:<18} {suffix}")

    # ── Precision: no finding may fall outside EXPECTED ───────────────────────
    unexpected = [f for f in active if not _is_expected(f)]
    if unexpected:
        for f in sorted(unexpected, key=lambda x: (x.file_path, x.line_number)):
            fails.append(
                f"EXTRA {f.rule_id:<18} {_rel(f)}:{f.line_number:<4}"
                f" — {f.description[:70]}"
            )
    else:
        passes.append(
            f"[precision] OK  {len(active)} finding(s) active, "
            f"none unexpected"
        )

    # ── Print results ─────────────────────────────────────────────────────────
    width = 68
    print(f"\n── recall_check {'─' * width}")
    for msg in passes:
        print(f"  \033[32m{msg}\033[0m")
    if fails:
        print()
    for msg in fails:
        print(f"  \033[31m{msg}\033[0m")

    n_recall   = len(EXPECTED)
    n_r_pass   = sum(1 for m in passes if m.startswith("[recall]"))
    n_extra    = len(unexpected)

    print(f"\n  recall {n_r_pass}/{n_recall}", end="")
    if result.suppressed_count:
        print(f"  |  suppressed {result.suppressed_count} "
              f"({result.suppression_breakdown})", end="")
    print(f"  |  unexpected {n_extra}")

    if fails:
        print(f"\n  \033[31m{len(fails)} check(s) FAILED\033[0m")
        return 1

    print(f"\n  \033[32mAll {n_recall} recall + precision checks passed.\033[0m")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScanner strict recall/precision check")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print all active findings before results")
    args = parser.parse_args()
    sys.exit(run(verbose=args.verbose))
