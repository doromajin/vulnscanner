#!/usr/bin/env python3
"""
juliet_c_score.py — Juliet C/C++ 1.3.1 benchmark for VulnScanner CAST-* rules.

Supports the NIST SARD 2022 package format:
  juliet_c/<pkg_id>-v1.0.0/src/testcases/CWE<N>_*/s*/CWE<N>_*.c

Scoring (file-level):
  TP = file has at least one expected CAST-* finding
  FN = file has no expected CAST-* finding (missed)
  Precision is not separately computable at file-level (good+bad mixed per file)
  so we report Recall and an F1 upper-bound assuming perfect precision.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from vulnscanner.analyzers.ast_c import CASTAnalyzer, CPPASTAnalyzer, _TS_C_AVAILABLE

if not _TS_C_AVAILABLE:
    print("ERROR: tree-sitter-c is not installed.")
    sys.exit(1)

_C_AZ = CASTAnalyzer()
_CPP_AZ = CPPASTAnalyzer()

# ── CWE → expected CAST-* rule mapping ───────────────────────────────────────
CWE_RULES: dict[str, list[str]] = {
    "CWE78":  ["CAST-CMD-001"],
    "CWE89":  ["CAST-SQL-001"],
    "CWE134": ["CAST-FMT-001"],
    "CWE22":  ["CAST-PATH-001"],
    "CWE121": ["CAST-BUF-001", "CAST-BUF-002", "CAST-MEM-001"],
    "CWE122": ["CAST-BUF-001", "CAST-BUF-002", "CAST-MEM-001"],
    "CWE124": ["CAST-BUF-001", "CAST-BUF-002", "CAST-MEM-001"],
    "CWE126": ["CAST-BUF-001", "CAST-BUF-002"],
    "CWE127": ["CAST-BUF-001", "CAST-BUF-002"],
}


def _cwe_from_dir(dirname: str) -> str | None:
    """Extract CWE code from a directory name like 'CWE78_OS_Command_Injection'."""
    for cwe in CWE_RULES:
        if dirname.startswith(cwe + "_") or dirname == cwe:
            return cwe
    return None


def _cwe_from_sarif(pkg_dir: Path) -> str | None:
    """Read CWE from manifest.sarif in a package directory."""
    sarif_path = pkg_dir / "manifest.sarif"
    if not sarif_path.exists():
        return None
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                # rule_id like "CWE-78" → "CWE78"
                if rule_id.startswith("CWE-"):
                    code = "CWE" + rule_id[4:].split(".")[0]
                    if code in CWE_RULES:
                        return code
    except Exception:
        pass
    return None


def _scan_file(path: Path) -> list[str]:
    """Return list of rule_ids fired for a single C/C++ file."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    ext = path.suffix.lower()
    if ext in (".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp"):
        findings = _CPP_AZ.analyze(str(path), content)
    else:
        findings = _C_AZ.analyze(str(path), content)
    return [f.rule_id for f in findings]


# Cross-file variant group key: strip the trailing letter from _51a, _53b, etc.
# e.g. "CWE78_foo_51a.c" → group key "CWE78_foo_51.c"
_CROSS_FILE_RE = re.compile(r'_(\d{2,})([a-e])$')


def _cross_file_group_key(path: Path) -> str | None:
    """Return a group key for cross-file variant files (_51a/_51b etc.), or None."""
    m = _CROSS_FILE_RE.search(path.stem)
    if m:
        base = path.stem[: m.start()] + "_" + m.group(1)
        return str(path.parent / base) + path.suffix
    return None


def _scan_group(paths: list[Path]) -> list[str]:
    """Concatenate a group of related files and scan as one compilation unit.

    This enables interprocedural taint to flow across file boundaries:
    e.g. _51a.c (source) + _51b.c (sink) → fixed-point connects them.
    """
    parts: list[str] = []
    for p in sorted(paths):  # sort a→b→c so source comes before sink
        try:
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    if not parts:
        return []
    combined = "\n\n".join(parts)
    # Use extension of the first file (all in a group share the same extension)
    ext = paths[0].suffix.lower()
    if ext in (".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp"):
        findings = _CPP_AZ.analyze(str(paths[0]), combined)
    else:
        findings = _C_AZ.analyze(str(paths[0]), combined)
    return [f.rule_id for f in findings]


def _collect_files_sard(juliet_root: Path) -> dict[str, list[Path]]:
    """
    Collect C/C++ files per CWE from the SARD 2022 package format.
    Each package: <pkg_id>-v1.0.0/src/testcases/CWE<N>_*/<s*>/*.c
    """
    result: dict[str, list[Path]] = {cwe: [] for cwe in CWE_RULES}

    for pkg_dir in sorted(juliet_root.iterdir()):
        if not pkg_dir.is_dir():
            continue

        # Approach 1: find CWE from src/testcases/CWE*/
        src_testcases = pkg_dir / "src" / "testcases"
        if src_testcases.exists():
            for cwe_dir in src_testcases.iterdir():
                if not cwe_dir.is_dir():
                    continue
                cwe = _cwe_from_dir(cwe_dir.name)
                if cwe is None:
                    continue
                for f in sorted(cwe_dir.rglob("*.c")):
                    result[cwe].append(f)
                for f in sorted(cwe_dir.rglob("*.cpp")):
                    result[cwe].append(f)
        else:
            # Approach 2: read manifest.sarif for CWE
            cwe = _cwe_from_sarif(pkg_dir)
            if cwe is None:
                continue
            for f in sorted(pkg_dir.rglob("*.c")):
                result[cwe].append(f)
            for f in sorted(pkg_dir.rglob("*.cpp")):
                result[cwe].append(f)

    return result


def _collect_files_classic(juliet_root: Path) -> dict[str, list[Path]]:
    """
    Collect C/C++ files per CWE from the classic Juliet format.
    testcases/CWE<N>_*/**/*.c
    """
    result: dict[str, list[Path]] = {cwe: [] for cwe in CWE_RULES}
    testcases = juliet_root / "testcases"
    if not testcases.exists():
        testcases = juliet_root
    for cwe_dir in sorted(testcases.iterdir()):
        if not cwe_dir.is_dir():
            continue
        cwe = _cwe_from_dir(cwe_dir.name)
        if cwe is None:
            continue
        for f in sorted(cwe_dir.rglob("*.c")):
            result[cwe].append(f)
        for f in sorted(cwe_dir.rglob("*.cpp")):
            result[cwe].append(f)
    return result


def run(juliet_root: Path, verbose: bool = False, max_workers: int = 4) -> None:
    # Detect format: if immediate children have "src/testcases" → SARD 2022
    sample = next((d for d in juliet_root.iterdir() if d.is_dir()), None)
    if sample and (sample / "src" / "testcases").exists():
        print("Format: SARD 2022 (numbered package directories)")
        files_by_cwe = _collect_files_sard(juliet_root)
    else:
        print("Format: classic Juliet (testcases/ directory)")
        files_by_cwe = _collect_files_classic(juliet_root)

    total_tp = total_fn = 0

    print(f"\n{'CWE':<10} {'Rule':<22} {'Files':>6} {'TP':>5} {'FN':>5} {'Recall':>8}")
    print("-" * 65)

    for cwe, files in files_by_cwe.items():
        if not files:
            rule_str = "/".join(sorted(CWE_RULES[cwe]))
            print(f"{cwe:<10} {rule_str:<22} {'(no files)':>6}")
            continue
        expected_rules = set(CWE_RULES[cwe])

        # Separate cross-file variant groups from single-file variants
        groups: dict[str, list[Path]] = {}
        solos: list[Path] = []
        for p in files:
            key = _cross_file_group_key(p)
            if key:
                groups.setdefault(key, []).append(p)
            else:
                solos.append(p)

        tp = fn = 0
        misses: list[Path] = []

        def _solo_job(p: Path) -> tuple[list[Path], list[str]]:
            return [p], _scan_file(p)

        def _group_job(grp: list[Path]) -> tuple[list[Path], list[str]]:
            return grp, _scan_group(grp)

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures: dict = {}
            for p in solos:
                futures[ex.submit(_solo_job, p)] = p
            for grp in groups.values():
                futures[ex.submit(_group_job, grp)] = grp[0]

            for fut in as_completed(futures):
                paths_in_job, rule_ids = fut.result()
                fired = bool(set(rule_ids) & expected_rules)
                for fpath in paths_in_job:
                    if fired:
                        tp += 1
                    else:
                        fn += 1
                        misses.append(fpath)

        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        rule_str = "/".join(sorted(expected_rules))
        print(f"{cwe:<10} {rule_str:<22} {len(files):>6} {tp:>5} {fn:>5} {recall:>7.1%}")

        if verbose and misses:
            for m in sorted(misses, key=lambda p: p.name)[:5]:
                print(f"           MISS: {m.name}")
            if len(misses) > 5:
                print(f"           ... and {len(misses)-5} more misses")

        total_tp += tp
        total_fn += fn

    print("-" * 65)
    total_files = total_tp + total_fn
    recall = total_tp / total_files if total_files > 0 else 0.0
    precision_lb = 1.0  # lower bound: we don't measure FP separately
    f1_ub = (2 * precision_lb * recall / (precision_lb + recall)) if (precision_lb + recall) > 0 else 0.0
    print(f"{'TOTAL':<10} {'':<22} {total_files:>6} {total_tp:>5} {total_fn:>5} {recall:>7.1%}")
    print(f"\nRecall (TP-rate) = {recall:.3f}")
    print(f"F1 upper-bound   = {f1_ub:.3f}  (assuming precision=1.0; Juliet mixes good+bad per file)")
    print()
    print("Note: 'files' = C/C++ files containing both good() and bad() variants.")
    print("A file is TP if the expected CAST-* rule fires anywhere in the file.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Juliet C/C++ benchmark for VulnScanner CAST-* rules")
    ap.add_argument("juliet_root", nargs="?", default="juliet_c",
                    help="Path to extracted Juliet C/C++ root (default: ./juliet_c)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Show missed files (up to 5 per CWE)")
    ap.add_argument("--workers", type=int, default=4,
                    help="Parallel scan threads (default: 4)")
    args = ap.parse_args()

    root = Path(args.juliet_root)
    if not root.exists():
        print(f"ERROR: Juliet root not found: {root}")
        sys.exit(1)

    pkg_count = sum(1 for _ in root.iterdir() if _.is_dir())
    print(f"Juliet C/C++ root : {root.resolve()}")
    print(f"Packages found    : {pkg_count}")
    print(f"Scoring CWEs      : {', '.join(CWE_RULES)}")
    run(root, verbose=args.verbose, max_workers=args.workers)
