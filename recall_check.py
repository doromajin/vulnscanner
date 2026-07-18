#!/usr/bin/env python3
"""
recall_check.py -- VulnScanner benchmark: recall + precision + regression.

Three-part check:
  Positive   -- every entry in EXPECTED is present with the correct severity (TP/FN).
  Negative   -- every file in recall/negative/ produces zero active findings (TN/FP).
  Real FP    -- every file in recall/real_fp/ produces zero active findings (regression).

Metrics:
  Precision   = TP / (TP + FP)
  Recall      = TP / (TP + FN)
  Specificity = TN / (TN + FP)
  F1          = 2 * Precision * Recall / (Precision + Recall)

  TP  = positive EXPECTED entries detected with correct severity
  FN  = positive EXPECTED entries missed
  FP  = negative/real_fp FILES with at least one active finding
  TN  = negative/real_fp FILES with zero active findings

Usage:
    python recall_check.py            # benchmark
    python recall_check.py --verbose  # also print all active findings

Exit codes:
    0  all checks pass
    1  one or more checks failed
"""
from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from vulnscanner.models import Finding, Severity
from vulnscanner.scanner import VulnScanner

_BASE        = os.path.dirname(os.path.abspath(__file__))
RECALL_DIR   = os.path.join(_BASE, "recall")
POSITIVE_DIR = os.path.join(RECALL_DIR, "positive")
NEGATIVE_DIR = os.path.join(RECALL_DIR, "negative")
REAL_FP_DIR  = os.path.join(RECALL_DIR, "real_fp")

# ── Expected findings (positive/ only) ────────────────────────────────────────
# Each entry: (rule_id, file_suffix, expected_severity, description)
#
# file_suffix is matched against the TAIL of the finding path returned by the
# scanner (which is relative to the scanned directory).  "js/xss.js" matches
# any path ending with that string.
#
# One entry covers ALL findings with that (rule_id, file_suffix) pair.

EXPECTED: list[tuple[str, str, str, str]] = [
    # -- JavaScript ---------------------------------------------------------------
    ("XSS-001",       "js/xss.js",                    "HIGH",     "innerHTML XSS"),

    # -- PHP ----------------------------------------------------------------------
    ("DESER-004",     "php/deser.php",                "CRITICAL", "PHP unserialize() RCE"),
    ("SQL-004",       "php/sqli.php",                 "HIGH",     "PHP SQL string concatenation"),
    ("XSS-005",       "php/xss.php",                  "HIGH",     "PHP echo $_GET / $_POST"),
    ("XSS-008",       "php/xss_1hop.php",             "HIGH",     "PHP XSS 1-hop"),
    # PHP AST: multi-hop taint patterns (tree-sitter-php)
    ("PHP-XSS-010",   "php/xss_2hop.php",             "HIGH",     "PHP XSS 2-hop taint propagation"),
    ("PHP-XSS-011",   "php/xss_nullcoalesce.php",     "HIGH",     "PHP XSS null-coalescing taint propagation"),
    ("PHP-XSS-012",   "php/xss_func.php",             "HIGH",     "PHP XSS function return taint"),

    # -- Python: command injection ------------------------------------------------
    ("AST-CMD-001",   "python/command_injection.py",  "HIGH",     "os.system() with tainted arg"),
    ("AST-CMD-002",   "python/command_injection.py",  "HIGH",     "subprocess shell=True with tainted arg"),
    ("AST-CMD-003",   "python/eval_injection.py",     "CRITICAL", "eval() with tainted arg"),
    ("AST-CMD-004",   "python/exec_injection.py",     "CRITICAL", "exec() with tainted arg"),

    # -- Python: SQL injection ----------------------------------------------------
    ("AST-SQL-001",   "python/sql_injection.py",      "HIGH",     "SQL injection via f-string"),
    ("AST-SQL-002",   "python/sql_injection.py",      "HIGH",     "SQL injection via concatenation"),

    # -- Python: path traversal ---------------------------------------------------
    ("AST-PATH-001",  "python/path_traversal.py",     "HIGH",     "open() with tainted variable path"),
    ("AST-PATH-002",  "python/path_traversal.py",     "HIGH",     "open() with tainted concatenated path"),

    # -- Python: SSRF -------------------------------------------------------------
    ("AST-SSRF-001",  "python/ssrf.py",               "HIGH",     "requests.get() with URL from user input"),

    # -- Python: deserialization --------------------------------------------------
    ("AST-DESER-001", "python/deserialization.py",    "CRITICAL", "pickle.loads() arbitrary object deserialization"),
    ("AST-DESER-004", "python/deserialization.py",    "HIGH",     "yaml.load() without Loader="),

    # -- Python: SSTI -------------------------------------------------------------
    ("AST-SSTI-002",  "python/ssti.py",               "HIGH",     "Jinja2 Environment.from_string() non-literal"),

    # -- Python: sanitizer bypass -------------------------------------------------
    ("AST-SQL-002",   "python/sanitizer_bypass.py",   "HIGH",     "html.escape() does NOT suppress SQL injection"),

    # -- Python: interprocedural taint --------------------------------------------
    ("AST-CMD-001",   "python/interprocedural.py",    "HIGH",     "1-hop: get_user_direct() -> os.system()"),
    ("AST-SQL-002",   "python/interprocedural.py",    "HIGH",     "2-hop: wrap_raw() -> get_raw() -> execute() via concatenation"),
    ("AST-SQL-002",   "python/interprocedural.py",    "HIGH",     "Phase 3a: self._get_id() inherent taint source"),
    ("AST-CMD-001",   "python/interprocedural.py",    "HIGH",     "Phase 3b: self._wrap(tainted) passthrough"),

    # -- Java: interprocedural taint ----------------------------------------------
    ("JAST-SQL-001",  "java/interprocedural.java",   "HIGH",     "Java bare-call helper -> SQL injection"),
    ("JAST-SQL-001",  "java/interprocedural.java",   "HIGH",     "Java this.method(tainted) passthrough -> SQL injection"),

    # -- Java: deserialization ----------------------------------------------------
    ("DESER-005",     "java/deserialization.java",     "CRITICAL", "Java ObjectInputStream.readObject() RCE"),
    ("DESER-009",     "java/deserialization.java",     "CRITICAL", "Java XStream.fromXML() RCE"),
    ("DESER-010",     "java/deserialization.java",     "CRITICAL", "Java XMLDecoder arbitrary object instantiation"),
    ("JAST-DESER-001","java/deserialization.java",     "CRITICAL", "Java AST deserialization"),
    ("JAST-DESER-002","java/deserialization.java",     "CRITICAL", "SnakeYAML new Yaml() without SafeConstructor (CVE-2022-1471)"),
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
    """Path for display: strip everything up to and including /recall/[subdir]/."""
    n = _norm(f.file_path)
    for marker in ("/recall/positive/", "/recall/negative/", "/recall/real_fp/"):
        idx = n.find(marker)
        if idx >= 0:
            return n[idx + len(marker):]
    # already relative (no absolute prefix found)
    return n


def _is_expected(f: Finding) -> bool:
    return any(
        f.rule_id == rule_id and _matches(f.file_path, suffix)
        for rule_id, suffix, _, _ in EXPECTED
    )


def _scan_active(directory: str) -> list[Finding]:
    if not os.path.isdir(directory):
        return []
    result = VulnScanner().scan(directory)
    return [f for f in result.findings if f.suppression_reason is None]


def _count_source_files(directory: str) -> int:
    if not os.path.isdir(directory):
        return 0
    count = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        for fname in files:
            if not fname.startswith('.') and not fname.endswith('.md'):
                count += 1
    return count


def _fp_files(findings: list[Finding]) -> set[str]:
    return {_norm(f.file_path) for f in findings}


# ── Main ──────────────────────────────────────────────────────────────────────

def run(verbose: bool = False) -> int:
    if not os.path.isdir(RECALL_DIR):
        print(f"[ERROR] recall/ not found at {RECALL_DIR}", file=sys.stderr)
        return 1

    with ThreadPoolExecutor(max_workers=1) as pool:
        pos_f = pool.submit(_scan_active, POSITIVE_DIR)
        neg_f = pool.submit(_scan_active, NEGATIVE_DIR)
        rfp_f = pool.submit(_scan_active, REAL_FP_DIR)
        pos_active = pos_f.result()
        neg_active = neg_f.result()
        rfp_active = rfp_f.result()

    if verbose:
        all_findings = pos_active + neg_active + rfp_active
        print("\n-- All active findings -----------------------------------------------")
        for f in sorted(all_findings, key=lambda x: (x.file_path, x.line_number)):
            print(f"  {f.rule_id:<18} {_sev(f):<10} {_rel(f)}:{f.line_number}")
        print()

    passes: list[str] = []
    fails:  list[str] = []

    # ── Positive: every EXPECTED entry must be found with correct severity ──
    for rule_id, suffix, exp_sev, desc in EXPECTED:
        matched = [
            f for f in pos_active
            if f.rule_id == rule_id and _matches(f.file_path, suffix)
        ]
        if not matched:
            fails.append(f"FN    {rule_id:<18} {suffix:<40} | {desc}")
            continue
        wrong = [f for f in matched if _sev(f) != exp_sev]
        if wrong:
            fails.append(
                f"SEV   {rule_id:<18} {suffix:<40} | {desc} "
                f"(want {exp_sev}, got {_sev(wrong[0])})"
            )
        else:
            passes.append(f"[positive]  OK  {rule_id:<18} {suffix}")

    # ── Positive: precision -- no unexpected findings in positive/ ──────────
    pos_unexpected = [f for f in pos_active if not _is_expected(f)]
    if pos_unexpected:
        for f in sorted(pos_unexpected, key=lambda x: (x.file_path, x.line_number)):
            fails.append(
                f"EXTRA {f.rule_id:<18} positive/{_rel(f)}:{f.line_number}"
                f" | {f.description[:65]}"
            )

    # ── Negative: every file must produce zero active findings ─────────────
    neg_total = _count_source_files(NEGATIVE_DIR)
    neg_fp = _fp_files(neg_active)
    neg_tn = neg_total - len(neg_fp)

    if not neg_active:
        passes.append(f"[negative]  OK  {neg_total} file(s) clean, 0 active findings")
    else:
        for f in sorted(neg_active, key=lambda x: (x.file_path, x.line_number)):
            fails.append(
                f"FP    {f.rule_id:<18} negative/{_rel(f)}:{f.line_number}"
                f" | {f.description[:65]}"
            )

    # ── Real FP regression: every file must produce zero active findings ────
    rfp_total = _count_source_files(REAL_FP_DIR)
    rfp_fp = _fp_files(rfp_active)
    rfp_tn = rfp_total - len(rfp_fp)

    if not rfp_active:
        passes.append(f"[real_fp]   OK  {rfp_total} file(s) clean, no regressions")
    else:
        for f in sorted(rfp_active, key=lambda x: (x.file_path, x.line_number)):
            fails.append(
                f"REGR  {f.rule_id:<18} real_fp/{_rel(f)}:{f.line_number}"
                f" | {f.description[:65]}"
            )

    # ── Unified benchmark metrics ──────────────────────────────────────────
    n_expected = len(EXPECTED)
    n_r_pass   = sum(1 for m in passes if m.startswith("[positive]"))
    TP = n_r_pass
    FN = n_expected - TP
    FP = len(neg_fp) + len(rfp_fp)
    TN = neg_tn + rfp_tn

    precision   = TP / (TP + FP)       if (TP + FP) > 0       else 1.0
    recall_r    = TP / (TP + FN)       if (TP + FN) > 0       else 1.0
    specificity = TN / (TN + FP)       if (TN + FP) > 0       else 1.0
    f1          = (
        2 * precision * recall_r / (precision + recall_r)
        if (precision + recall_r) > 0
        else 0.0
    )

    # ── Output ────────────────────────────────────────────────────────────
    print(f"\n-- recall_check {'=' * 56}")
    for msg in passes:
        print(f"  \033[32m{msg}\033[0m")
    if fails:
        print()
    for msg in fails:
        print(f"  \033[31m{msg}\033[0m")

    print(f"\n  recall {n_r_pass}/{n_expected}", end="")
    print(f"  |  neg FP {len(neg_fp)}/{neg_total}", end="")
    print(f"  |  rfp FP {len(rfp_fp)}/{rfp_total}")

    print(f"\n  Benchmark (positive={n_expected}, negative+rfp={neg_total + rfp_total} files):")
    print(f"    TP: {TP}  FN: {FN}  FP: {FP}  TN: {TN}")
    print(f"    Precision:   {precision * 100:.1f}%")
    print(f"    Recall:      {recall_r * 100:.1f}%")
    print(f"    Specificity: {specificity * 100:.1f}%")
    print(f"    F1:          {f1 * 100:.1f}%")

    if fails:
        print(f"\n  \033[31m{len(fails)} check(s) FAILED\033[0m")
        return 1

    total_checks = n_expected + neg_total + rfp_total
    print(f"\n  \033[32mAll {total_checks} checks passed.\033[0m")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VulnScanner recall / precision / regression benchmark"
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print all active findings before results")
    args = parser.parse_args()
    sys.exit(run(verbose=args.verbose))
