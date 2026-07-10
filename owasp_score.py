"""
OWASP Benchmark scoring script for VulnScanner Java analyzers.

Benchmark Score = TPR - FPR  (range: -1 to 1)
  1.0 = perfect,  0.0 = random guess,  -1.0 = perfectly wrong

Usage:
  python owasp_score.py
"""
from __future__ import annotations

import csv
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

# ── paths ─────────────────────────────────────────────────────────────────────
BENCH_DIR  = Path(__file__).parent / "owasp_benchmark"
TESTCODE   = BENCH_DIR / "src/main/java/org/owasp/benchmark/testcode"
EXPECTED   = BENCH_DIR / "expectedresults-1.2.csv"

# ── VulnScanner imports ────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from vulnscanner.analyzers.ast_java   import JavaASTAnalyzer
from vulnscanner.analyzers.java_analyzer import JavaAnalyzer
from vulnscanner.models import VulnType

# ── category mapping: OWASP → VulnType ────────────────────────────────────────
CATEGORY_MAP: dict[str, set[VulnType]] = {
    "sqli":        {VulnType.SQL_INJECTION},
    "cmdi":        {VulnType.COMMAND_INJECTION},
    "xss":         {VulnType.XSS},
    "pathtraver":  {VulnType.PATH_TRAVERSAL},
    "ldapi":       {VulnType.LDAP_INJECTION},
    "crypto":      {VulnType.WEAK_CRYPTOGRAPHY},
    "hash":        {VulnType.WEAK_CRYPTOGRAPHY},
    "weakrand":    {VulnType.WEAK_CRYPTOGRAPHY},
    # trustbound / securecookie / xpathi - not covered by VulnScanner
}
COVERED = set(CATEGORY_MAP)
NOT_COVERED = {"trustbound", "securecookie", "xpathi"}

# ── load expected results ──────────────────────────────────────────────────────
Expected = dict[str, tuple[str, bool]]  # name → (category, is_vuln)

def load_expected(csv_path: Path) -> dict[str, tuple[str, bool]]:
    result: dict[str, tuple[str, bool]] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, cat, is_vuln = row[0].strip(), row[1].strip(), row[2].strip()
            result[name] = (cat, is_vuln.lower() == "true")
    return result

# ── run both Java analyzers on a file ─────────────────────────────────────────
_ast  = JavaASTAnalyzer()
_regex = JavaAnalyzer()

def scan(file_path: Path) -> set[VulnType]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    path_str = str(file_path)
    found: set[VulnType] = set()
    for f in _ast.analyze(path_str, content):
        if not f.suppression_reason:
            found.add(f.vuln_type)
    for f in _regex.analyze(path_str, content):
        if not f.suppression_reason:
            found.add(f.vuln_type)
    return found

# ── scoring ────────────────────────────────────────────────────────────────────
class Counter:
    def __init__(self) -> None:
        self.tp = self.fp = self.tn = self.fn = 0

    def add(self, detected: bool, expected: bool) -> None:
        if expected and detected:     self.tp += 1
        elif expected and not detected: self.fn += 1
        elif not expected and detected: self.fp += 1
        else:                           self.tn += 1

    @property
    def tpr(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    @property
    def score(self) -> float:
        return self.tpr - self.fpr

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


def main() -> None:
    expected = load_expected(EXPECTED)
    java_files = list(TESTCODE.glob("*.java"))
    print(f"Test cases: {len(java_files)}  |  Expected entries: {len(expected)}")
    print()

    counters: dict[str, Counter] = defaultdict(Counter)
    overall  = Counter()

    t0 = time.monotonic()
    for i, jf in enumerate(sorted(java_files), 1):
        name = jf.stem
        if name not in expected:
            continue
        cat, is_vuln = expected[name]
        if cat in NOT_COVERED:
            continue

        found_types = scan(jf)
        target_types = CATEGORY_MAP.get(cat, set())
        detected = bool(found_types & target_types)

        counters[cat].add(detected, is_vuln)
        overall.add(detected, is_vuln)

        if i % 200 == 0:
            elapsed = time.monotonic() - t0
            print(f"  {i}/{len(java_files)} scanned  ({elapsed:.0f}s)", flush=True)

    elapsed = time.monotonic() - t0
    print(f"  Done - {len(java_files)} files in {elapsed:.1f}s\n")

    # ── print results ──────────────────────────────────────────────────────────
    W = 12
    print(f"{'Category':<14} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5}  "
          f"{'TPR':>7} {'FPR':>7} {'Score':>8}")
    print("-" * 65)

    for cat in sorted(counters):
        c = counters[cat]
        print(f"{cat:<14} {c.tp:>5} {c.fp:>5} {c.tn:>5} {c.fn:>5}  "
              f"{c.tpr:>7.1%} {c.fpr:>7.1%} {c.score:>+8.3f}")

    print("-" * 65)
    c = overall
    print(f"{'OVERALL':<14} {c.tp:>5} {c.fp:>5} {c.tn:>5} {c.fn:>5}  "
          f"{c.tpr:>7.1%} {c.fpr:>7.1%} {c.score:>+8.3f}")
    print()
    print(f"Benchmark Score (TPR - FPR): {c.score:+.3f}")
    print(f"  TPR {c.tpr:.1%}  /  FPR {c.fpr:.1%}")
    print()
    print(f"Not covered (excluded): {', '.join(sorted(NOT_COVERED))}")


if __name__ == "__main__":
    main()
