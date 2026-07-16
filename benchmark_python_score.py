"""
OWASP Benchmark for Python scoring script.

Score = TPR - FPR  (range: -1 to 1)

Usage:
  python benchmark_python_score.py
  python benchmark_python_score.py --verbose
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer, set_cross_file_context
from vulnscanner.models import VulnType

BENCH_DIR  = Path(__file__).parent / "benchmark_python"
TESTCODE   = BENCH_DIR / "testcode"
HELPERS    = BENCH_DIR / "helpers"
EXPECTED   = BENCH_DIR / "expectedresults-0.1.csv"

# ── category → VulnType mapping ───────────────────────────────────────────────

CATEGORY_MAP: dict[str, set[VulnType]] = {
    "pathtraver":      {VulnType.PATH_TRAVERSAL},
    "sqli":            {VulnType.SQL_INJECTION},
    "xss":             {VulnType.XSS},
    "cmdi":            {VulnType.COMMAND_INJECTION},
    "weakrand":        {VulnType.WEAK_CRYPTOGRAPHY},
    "hash":            {VulnType.WEAK_CRYPTOGRAPHY},
    "ldapi":           {VulnType.LDAP_INJECTION},
    "xxe":             {VulnType.XXE},
    "redirect":        {VulnType.OPEN_REDIRECT},
    "deserialization": {VulnType.INSECURE_DESERIALIZATION},
    "codeinj":         {VulnType.COMMAND_INJECTION},   # exec/eval already detected
    "xpathi":          {VulnType.XPATH_INJECTION},
    "securecookie":    {VulnType.INSECURE_COOKIE},
    # trustbound (CWE-501): session key injection — FP risk too high in real Flask
    # apps; requires scope-boundary analysis incompatible with current taint arch
}
NOT_COVERED = {"trustbound"}

# ── helpers ───────────────────────────────────────────────────────────────────

def load_expected(csv_path: Path) -> dict[str, tuple[str, bool]]:
    result: dict[str, tuple[str, bool]] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, cat, is_vuln = row[0].strip(), row[1].strip(), row[2].strip()
            result[name] = (cat, is_vuln.lower() == "true")
    return result


def build_cross_file_context() -> dict[str, str]:
    """Load helper files as cross-file taint context (paths relative to BENCH_DIR)."""
    ctx: dict[str, str] = {}
    for py_file in HELPERS.glob("**/*.py"):
        rel = py_file.relative_to(BENCH_DIR).as_posix()
        ctx[rel] = py_file.read_text(encoding="utf-8", errors="replace")
    return ctx


_ast = PythonASTAnalyzer()


def scan(file_path: Path, cross_file_ctx: dict[str, str]) -> set[VulnType]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    # Path key relative to BENCH_DIR so helpers/ paths match import resolution
    rel_path = file_path.relative_to(BENCH_DIR).as_posix()
    full_ctx = dict(cross_file_ctx)
    full_ctx[rel_path] = content
    set_cross_file_context(full_ctx)
    found: set[VulnType] = set()
    for f in _ast.analyze(rel_path, content):
        if not f.suppression_reason:
            found.add(f.vuln_type)
    return found


# ── scoring ───────────────────────────────────────────────────────────────────

class Counter:
    def __init__(self) -> None:
        self.tp = self.fp = self.tn = self.fn = 0

    def add(self, detected: bool, expected: bool) -> None:
        if expected and detected:       self.tp += 1
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    expected = load_expected(EXPECTED)
    cross_file_ctx = build_cross_file_context()

    java_files = sorted(TESTCODE.glob("BenchmarkTest*.py"))
    print(f"Test cases: {len(java_files)}  |  Expected entries: {len(expected)}")
    print(f"Helper context files: {len(cross_file_ctx)}")
    print()

    counters: dict[str, Counter] = defaultdict(Counter)
    overall = Counter()

    t0 = time.monotonic()
    fn_details: list[tuple[str, str]] = []  # (name, file) for FNs

    for i, tf in enumerate(java_files, 1):
        name = tf.stem
        if name not in expected:
            continue
        cat, is_vuln = expected[name]
        if cat in NOT_COVERED:
            continue

        found_types = scan(tf, cross_file_ctx)
        target_types = CATEGORY_MAP.get(cat, set())
        detected = bool(found_types & target_types)

        counters[cat].add(detected, is_vuln)
        overall.add(detected, is_vuln)

        if is_vuln and not detected:
            fn_details.append((name, cat))

        if i % 200 == 0:
            elapsed = time.monotonic() - t0
            print(f"  {i}/{len(java_files)} scanned  ({elapsed:.0f}s)", flush=True)

    elapsed = time.monotonic() - t0
    print(f"  Done - {len(java_files)} files in {elapsed:.1f}s\n")

    print(f"{'Category':<16} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5}  "
          f"{'TPR':>7} {'FPR':>7} {'Score':>8}")
    print("-" * 67)
    for cat in sorted(counters):
        c = counters[cat]
        print(f"{cat:<16} {c.tp:>5} {c.fp:>5} {c.tn:>5} {c.fn:>5}  "
              f"{c.tpr:>7.1%} {c.fpr:>7.1%} {c.score:>+8.3f}")
    print("-" * 67)
    c = overall
    print(f"{'OVERALL':<16} {c.tp:>5} {c.fp:>5} {c.tn:>5} {c.fn:>5}  "
          f"{c.tpr:>7.1%} {c.fpr:>7.1%} {c.score:>+8.3f}")
    print()
    print(f"Benchmark Score (TPR - FPR): {c.score:+.3f}")
    print(f"  TPR {c.tpr:.1%}  /  FPR {c.fpr:.1%}")

    if args.verbose and fn_details:
        print(f"\nFalse Negatives ({len(fn_details)}):")
        for name, cat in fn_details[:30]:
            print(f"  {name}  [{cat}]")
        if len(fn_details) > 30:
            print(f"  ... and {len(fn_details) - 30} more")

    print(f"\nNot covered (excluded): {', '.join(sorted(NOT_COVERED))}")


if __name__ == "__main__":
    main()
