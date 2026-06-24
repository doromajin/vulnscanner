"""
Vulnerability risk profiler.

Converts a ScanResult into a RiskProfile with a normalized 0-100 score,
grade, and recommendation — used by the `rank` command and the per-scan
summary line.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from vulnscanner.models import ScanResult, Severity

# Points awarded per finding (raw, before capping)
_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# (min_score, grade_label, recommendation)
_GRADE_TABLE = [
    (70, "HIGH",    "Serious vulnerabilities likely - prioritize for full audit"),
    (40, "MEDIUM",  "Multiple risk patterns detected - worth investigating"),
    (15, "LOW",     "Some patterns detected - lower priority"),
    (1,  "MINIMAL", "Very few patterns - likely low risk"),
    (0,  "CLEAN",   "No findings detected"),
]

_GRADE_COLORS = {
    "HIGH":    "bold red",
    "MEDIUM":  "yellow",
    "LOW":     "cyan",
    "MINIMAL": "dim",
    "CLEAN":   "green",
}


@dataclass
class RiskProfile:
    repo: str
    score: int                          # 0–100
    grade: str                          # HIGH / MEDIUM / LOW / MINIMAL / CLEAN
    grade_color: str
    recommendation: str
    finding_count: int
    by_severity: dict[str, int]         # {"HIGH": 6, "MEDIUM": 4, ...}
    top_vuln_types: list[str]           # up to 3 most-frequent types
    scanned_files: int = 0
    elapsed_seconds: float = 0.0


def profile(result: ScanResult) -> RiskProfile:
    """Build a RiskProfile from a completed scan result."""
    findings = result.findings

    # Raw score — cap at 100
    raw = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = min(raw, 100)

    # Grade
    grade, recommendation = "CLEAN", "No findings detected"
    for threshold, g, r in _GRADE_TABLE:
        if score >= threshold:
            grade, recommendation = g, r
            break

    # Severity breakdown (only non-zero)
    counts = Counter(f.severity.value for f in findings)
    by_severity = {
        s.value: counts[s.value]
        for s in Severity
        if counts.get(s.value, 0) > 0
    }

    # Top vulnerability categories — weighted by severity, not raw count
    type_scores: Counter[str] = Counter()
    for f in findings:
        type_scores[f.vuln_type.value] += _SEVERITY_WEIGHTS.get(f.severity, 0)
    top_vuln_types = [t for t, _ in type_scores.most_common(3)]

    return RiskProfile(
        repo=result.repo_url,
        score=score,
        grade=grade,
        grade_color=_GRADE_COLORS[grade],
        recommendation=recommendation,
        finding_count=len(findings),
        by_severity=by_severity,
        top_vuln_types=top_vuln_types,
        scanned_files=result.scanned_files,
        elapsed_seconds=result.elapsed_seconds,
    )
