#!/usr/bin/env python3
"""
check_real_world.py -- regression check against pinned real-world ground truth.

Two label files live next to this script:

  oss_labels.json   every non-INFO finding on a few OSS repos at a pinned commit, each
                    with a verdict (TP / FP / HARDENING / DEP_ADVISORY / UNTRIAGED).
  disclosed.json    human-confirmed, vendor-reported vulnerabilities and whether the
                    scanner is expected to find them.

Each repo is checked out from its pinned commit into a temp dir (the clone's own work
tree and index are never touched), scanned, and compared with the labels:

  NEW     finding with no label        -> triage it and add a label (exit 1)
  LOST    labelled TP no longer found  -> regression (exit 1)
  GONE    labelled FP/HARDENING gone   -> improvement, informational
  MISS    disclosed bug no longer found / FOUND disclosed bug newly found

Repos are not part of this checkout.  Point VULNSCANNER_REPOS (or --repos) at the
directory holding the clones; repos that are missing are skipped with a notice.

Usage:
    python recall/real_world/check_real_world.py                 # everything available
    python recall/real_world/check_real_world.py --only kimai    # one label set / repo
    python recall/real_world/check_real_world.py --init bludit    # print a skeleton entry

Exit codes: 0 all good, 1 NEW findings or a regression.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEFAULT_REPOS = Path(os.environ.get("VULNSCANNER_REPOS", "C:/VulnScanner/repos"))
WINDOW = 25  # lines around a disclosed bug in which a finding counts as detecting it


def _git(repo: Path, *args: str) -> bytes:
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode("utf-8", "replace").strip() or "git failed")
    return p.stdout


def export_and_scan(repo: Path, commit: str) -> list[dict]:
    """Scan *repo* as it was at *commit*; return the active non-INFO findings."""
    with tempfile.TemporaryDirectory(prefix="vsrw_") as tmp:
        src = Path(tmp) / "src"
        src.mkdir()
        # Not ``git archive``: it honours export-ignore, which drops assets/ and tests/ in
        # some projects.  A private index + work tree leaves the clone untouched.
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        for args in (["read-tree", commit], ["checkout-index", "-a", "-f"]):
            p = subprocess.run(["git", "-C", str(repo), f"--work-tree={src}", *args],
                               capture_output=True, env=env)
            if p.returncode != 0:
                raise RuntimeError(p.stderr.decode("utf-8", "replace").strip() or "git failed")
        out = Path(tmp) / "out.json"
        subprocess.run(
            [sys.executable, "-m", "vulnscanner.cli", "scan", str(src), "-o", str(out)],
            cwd=ROOT, capture_output=True,
        )
        if not out.exists():
            raise RuntimeError("scan produced no report")
        data = json.loads(out.read_text(encoding="utf-8"))
    return [
        f for f in data["findings"]
        if f["severity"] != "INFO" and not f.get("suppression_reason")
    ]


def _key(rule: str, file: str, content: str) -> tuple[str, str, str]:
    return (rule, file.replace("\\", "/"), content.strip())


def check_labels(repos_dir: Path, only: str | None) -> tuple[bool, list[str]]:
    labels = json.loads((HERE / "oss_labels.json").read_text(encoding="utf-8"))
    ok, report = True, []
    for name, entry in labels["repos"].items():
        if only and only not in (name, "oss"):
            continue
        repo = repos_dir / name
        if not (repo / ".git").exists():
            report.append(f"[{name}] skipped: no clone at {repo}")
            continue
        try:
            found = export_and_scan(repo, entry["commit"])
        except Exception as exc:  # noqa: BLE001 - report and carry on with the next repo
            report.append(f"[{name}] ERROR: {exc}")
            ok = False
            continue
        labelled = collections.defaultdict(collections.deque)
        for lab in entry["findings"]:
            labelled[_key(lab["rule"], lab["file"], lab["content"])].append(lab)
        verdicts: collections.Counter = collections.Counter()
        new = []
        for f in found:
            k = _key(f["rule_id"], f["file_path"], f["line_content"])
            if labelled[k]:
                verdicts[labelled[k].popleft()["verdict"]] += 1
            else:
                new.append(f)
        lost = [lab for q in labelled.values() for lab in q]
        lost_tp = [lab for lab in lost if lab["verdict"] == "TP"]
        gone = [lab for lab in lost if lab["verdict"] != "TP"]
        triaged = sum(verdicts[v] for v in ("TP", "FP", "HARDENING"))
        prec = f"{verdicts['TP']}/{triaged}" if triaged else "n/a"
        report.append(
            f"[{name}] {entry['commit'][:7]}  active={len(found)}  "
            + "  ".join(f"{v}={n}" for v, n in sorted(verdicts.items()))
            + f"  | TP among triaged: {prec}"
        )
        for f in new:
            ok = False
            report.append(f"   NEW   {f['severity'][:4]} {f['rule_id']} {f['file_path']}:{f['line_number']}"
                          f" | {f['line_content'].strip()[:70]}")
        for lab in lost_tp:
            ok = False
            report.append(f"   LOST  TP {lab['rule']} {lab['file']} | {lab['content'][:70]}")
        for lab in gone:
            report.append(f"   gone  {lab['verdict']} {lab['rule']} {lab['file']} | {lab['content'][:60]}")
    return ok, report


def check_disclosed(repos_dir: Path, only: str | None) -> tuple[bool, list[str]]:
    data = json.loads((HERE / "disclosed.json").read_text(encoding="utf-8"))
    ok, report = True, []
    cache: dict[tuple[str, str], list[dict] | None] = {}
    for case in data["cases"]:
        if "expect_detected" not in case:
            continue
        if only and only not in (case["dir"], case["id"], "disclosed"):
            continue
        repo = repos_dir / case["dir"]
        ck = (case["dir"], case["commit"])
        if ck not in cache:
            if not (repo / ".git").exists():
                cache[ck] = None
            else:
                try:
                    cache[ck] = export_and_scan(repo, case["commit"])
                except Exception as exc:  # noqa: BLE001
                    report.append(f"[{case['id']}] ERROR: {exc}")
                    ok = False
                    cache[ck] = None
        found = cache[ck]
        if found is None:
            report.append(f"[{case['id']}] skipped: no clone at {repo}")
            continue
        hit = any(
            f["file_path"].replace("\\", "/").endswith(case["file"])
            and abs(f["line_number"] - case["line"]) <= WINDOW
            and f["rule_id"] in case["expect_rules"]
            for f in found
        )
        want = case["expect_detected"]
        if hit and want:
            report.append(f"[{case['id']}] detected (as expected)")
        elif not hit and not want:
            report.append(f"[{case['id']}] not detected (known gap: {case.get('missing', 'see label')[:80]})")
        elif hit and not want:
            report.append(f"[{case['id']}] FOUND  now detected - set expect_detected=true")
        else:
            ok = False
            report.append(f"[{case['id']}] MISS   expected to be detected by {case['expect_rules']}")
    return ok, report


def init_skeleton(repos_dir: Path, name: str) -> None:
    repo = repos_dir / name
    commit = _git(repo, "rev-parse", "HEAD").decode().strip()
    rows = [
        {"rule": f["rule_id"], "file": f["file_path"].replace("\\", "/"),
         "content": f["line_content"].strip(), "verdict": "UNTRIAGED", "note": ""}
        for f in sorted(export_and_scan(repo, commit),
                        key=lambda f: (f["file_path"], f["line_number"], f["rule_id"]))
    ]
    print(json.dumps({name: {"commit": commit, "findings": rows}}, indent=2, ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repos", type=Path, default=DEFAULT_REPOS, help="directory with the clones")
    ap.add_argument("--only", help="a repo name, a disclosed-case id, 'oss' or 'disclosed'")
    ap.add_argument("--init", metavar="REPO", help="print a labels skeleton for REPO and exit")
    args = ap.parse_args()
    if args.init:
        init_skeleton(args.repos, args.init)
        return 0
    ok1, rep1 = check_labels(args.repos, args.only)
    ok2, rep2 = check_disclosed(args.repos, args.only)
    print("\n".join(["== labelled findings on pinned OSS commits"] + rep1
                    + ["", "== disclosed real-world bugs"] + rep2))
    print("\nOK" if ok1 and ok2 else "\nFAILED: see NEW / LOST / MISS lines above")
    return 0 if ok1 and ok2 else 1


if __name__ == "__main__":
    sys.exit(main())
