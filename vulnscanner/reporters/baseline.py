"""Baseline comparison: suppress already-known findings from a previous JSON scan."""
from __future__ import annotations

import json
from pathlib import Path


BaselineKey = tuple[str, int, str]  # (file_path, line_number, rule_id)


def load_baseline(path: str) -> set[BaselineKey]:
    """Load a previous JSON scan and return the set of (file, line, rule_id) keys."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    keys: set[BaselineKey] = set()
    for f in data.get("findings", []):
        fp   = f.get("file_path", "")
        line = f.get("line_number", 0)
        rule = f.get("rule_id", "")
        if fp and rule:
            keys.add((fp, line, rule))
    return keys


def split_findings(findings: list, baseline: set[BaselineKey]):
    """Return (new_findings, known_findings) split from a finding list."""
    new: list = []
    known: list = []
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        if key in baseline:
            known.append(f)
        else:
            new.append(f)
    return new, known
