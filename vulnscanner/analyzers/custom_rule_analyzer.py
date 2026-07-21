"""Pattern-based analyzer that applies user-defined YAML rules."""
from __future__ import annotations

from pathlib import Path

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding
from vulnscanner.rules.loader import CustomRule

_INLINE_IGNORE = "vulnscanner: ignore"


class CustomRuleAnalyzer(BaseAnalyzer):
    """Applies a list of :class:`CustomRule` objects to source files.

    This analyzer is instantiated with a list of rules and re-used across
    all files in a scan. Rules are matched line-by-line using their compiled
    regex (converted from $X wildcard patterns or raw regex strings).
    """

    supported_extensions = ()  # handled dynamically per rule set

    def __init__(self, rules: list[CustomRule]) -> None:
        self._rules = rules
        # Partition rules by extension for fast per-file lookup
        self._by_ext: dict[str, list[CustomRule]] = {}
        for rule in rules:
            for ext in rule.extensions:
                self._by_ext.setdefault(ext, []).append(rule)

    def supports(self, file_path: str) -> bool:
        ext = Path(file_path).suffix.lower()
        return ext in self._by_ext

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        ext = Path(file_path).suffix.lower()
        applicable = self._by_ext.get(ext)
        if not applicable:
            return []

        lines = content.splitlines()
        findings: list[Finding] = []
        seen: set[tuple] = set()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            # Honour inline suppression annotation
            if _INLINE_IGNORE in line:
                continue

            # Skip pure comment lines
            if self._is_comment(stripped):
                continue

            for rule in applicable:
                if not rule.matches(line):
                    continue
                key = (rule.id, lineno)
                if key in seen:
                    continue
                seen.add(key)

                snippet = self._extract_snippet(lines, lineno)
                finding = Finding(
                    vuln_type=rule.vuln_type,
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=lineno,
                    line_content=stripped,
                    description=rule.message,
                    rule_id=rule.id,
                    repo_url=repo_url,
                    snippet=snippet,
                )
                if rule.cwe is not None:
                    finding.cwe_id = rule.cwe
                findings.append(finding)

        return findings
