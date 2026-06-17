import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RULES = [
    (
        "SQL-001",
        # String concatenation into SQL (Python)
        r'(?:execute|query|cursor\.execute)\s*\(\s*["\'].*["\'\s]*\+|'
        r'(?:execute|query|cursor\.execute)\s*\(\s*f["\'].*\{',
        "SQL query built with string concatenation — susceptible to injection",
        Severity.HIGH,
    ),
    (
        "SQL-002",
        # Raw % formatting into SQL
        r'(?:execute|query)\s*\(\s*["\'].*%[sd].*["\'].*%',
        "SQL query uses %-formatting with user-controlled data",
        Severity.HIGH,
    ),
    (
        "SQL-003",
        # .format() inside execute
        r'(?:execute|query)\s*\(.*\.format\s*\(',
        "SQL query uses .format() — prefer parameterized queries",
        Severity.HIGH,
    ),
    (
        "SQL-004",
        # PHP mysqli/PDO string concat
        r'\$(?:sql|query|stmt)\s*=\s*["\']SELECT.*["\'\s]*\.\s*\$',
        "PHP SQL query built with string concatenation",
        Severity.HIGH,
    ),
    (
        "SQL-005",
        # Generic ORM raw() / extra()
        r'\.raw\s*\(|\.extra\s*\(.*where',
        "Django ORM raw()/extra() — ensure no unsanitized input",
        Severity.MEDIUM,
    ),
]


class SQLInjectionAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".php", ".js", ".ts", ".java", ".rb")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule_id, pattern, description, severity in _RULES:
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            vuln_type=VulnType.SQL_INJECTION,
                            severity=severity,
                            file_path=file_path,
                            line_number=lineno,
                            line_content=line.strip(),
                            description=description,
                            rule_id=rule_id,
                            repo_url=repo_url,
                            snippet=self._extract_snippet(lines, lineno),
                        )
                    )

        return findings
