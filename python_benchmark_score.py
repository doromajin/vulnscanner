"""
OWASP BenchmarkPython scoring script for VulnScanner.

Benchmark Score (Youden Index) = TPR - FPR  (range: -1 to 1)
  +1.0 = perfect,  0.0 = random guess,  -1.0 = perfectly wrong

Usage:
  python python_benchmark_score.py
"""
from __future__ import annotations

import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

BENCH_DIR = Path(__file__).parent / "benchmark_python"
TESTCODE  = BENCH_DIR / "testcode"
EXPECTED  = BENCH_DIR / "expectedresults-0.1.csv"

sys.path.insert(0, str(Path(__file__).parent))
from vulnscanner.analyzers.ast_python      import PythonASTAnalyzer
from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
from vulnscanner.analyzers.sql_injection     import SQLInjectionAnalyzer
from vulnscanner.analyzers.path_traversal    import PathTraversalAnalyzer
from vulnscanner.analyzers.xss               import XSSAnalyzer
from vulnscanner.analyzers.open_redirect     import OpenRedirectAnalyzer
from vulnscanner.analyzers.deserialization   import DeserializationAnalyzer
from vulnscanner.analyzers.weak_crypto       import WeakCryptoAnalyzer
from vulnscanner.analyzers.ldap_injection    import LDAPInjectionAnalyzer
from vulnscanner.models import VulnType

# ── category → VulnType mapping ───────────────────────────────────────────────
CATEGORY_MAP: dict[str, set[VulnType]] = {
    "cmdi":            {VulnType.COMMAND_INJECTION},
    "codeinj":         {VulnType.COMMAND_INJECTION},
    "deserialization": {VulnType.INSECURE_DESERIALIZATION},
    "hash":            {VulnType.WEAK_CRYPTOGRAPHY},
    "ldapi":           {VulnType.LDAP_INJECTION},
    "pathtraver":      {VulnType.PATH_TRAVERSAL},
    "redirect":        {VulnType.OPEN_REDIRECT},
    "sqli":            {VulnType.SQL_INJECTION},
    "weakrand":        {VulnType.WEAK_CRYPTOGRAPHY},
    "xss":             {VulnType.XSS},
    "xxe":             {VulnType.XXE},
}
NOT_COVERED = {"securecookie", "trustbound", "xpathi"}

# ── load expected results ──────────────────────────────────────────────────────
def load_expected(csv_path: Path) -> dict[str, tuple[str, bool]]:
    result: dict[str, tuple[str, bool]] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, cat, is_vuln = row[0].strip(), row[1].strip(), row[2].strip()
            result[name] = (cat, is_vuln.lower() == "true")
    return result

# ── instantiate all analyzers once ────────────────────────────────────────────
_ANALYZERS = [
    PythonASTAnalyzer(),
    CommandInjectionAnalyzer(),
    SQLInjectionAnalyzer(),
    PathTraversalAnalyzer(),
    XSSAnalyzer(),
    OpenRedirectAnalyzer(),
    DeserializationAnalyzer(),
    WeakCryptoAnalyzer(),
    LDAPInjectionAnalyzer(),
]

def scan(file_path: Path) -> set[VulnType]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    path_str = str(file_path)
    found: set[VulnType] = set()
    for analyzer in _ANALYZERS:
        if not analyzer.supports(path_str):
            continue
        try:
            for f in analyzer.analyze(path_str, content):
                if not f.suppression_reason:
                    found.add(f.vuln_type)
        except Exception:
            pass
    return found

# ── scoring ────────────────────────────────────────────────────────────────────
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
    expected = load_expected(EXPECTED)
    py_files = list(TESTCODE.glob("*.py"))
    print(f"Test cases : {len(py_files)}  |  Expected entries: {len(expected)}")
    print(f"Not covered (excluded): {sorted(NOT_COVERED)}")
    print()

    counters: dict[str, Counter] = defaultdict(Counter)
    overall  = Counter()

    t0 = time.monotonic()
    for i, pf in enumerate(sorted(py_files), 1):
        name = pf.stem
        if name not in expected:
            continue
        cat, is_vuln = expected[name]
        if cat in NOT_COVERED or cat not in CATEGORY_MAP:
            continue

        found_types = scan(pf)
        target_types = CATEGORY_MAP[cat]
        detected = bool(found_types & target_types)

        counters[cat].add(detected, is_vuln)
        overall.add(detected, is_vuln)

        if i % 200 == 0:
            elapsed = time.monotonic() - t0
            print(f"  {i}/{len(py_files)} scanned  ({elapsed:.0f}s)", flush=True)

    elapsed = time.monotonic() - t0
    print(f"  Done - {len(py_files)} files in {elapsed:.1f}s\n")

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


if __name__ == "__main__":
    main()
