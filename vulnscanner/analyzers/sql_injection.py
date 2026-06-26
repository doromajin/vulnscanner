import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_SI = VulnType.SQL_INJECTION

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "SQL-001",
        re.compile(
            r'(?:execute|query|cursor\.execute)\s*\(\s*["\'].*["\'\s]*\+'
            r'|(?:execute|query|cursor\.execute)\s*\(\s*f["\'].*\{',
            re.IGNORECASE,
        ),
        "SQL query built with string concatenation - susceptible to injection",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-002",
        re.compile(r'(?:execute|query)\s*\(\s*["\'].*%[sd].*["\'].*%', re.IGNORECASE),
        "SQL query uses %-formatting with user-controlled data",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-003",
        re.compile(r'(?:execute|query)\s*\(.*\.format\s*\(', re.IGNORECASE),
        "SQL query uses .format() - prefer parameterized queries",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-004",
        re.compile(r'\$(?:sql|query|stmt)\s*=\s*["\']SELECT.*["\'\s]*\.\s*\$', re.IGNORECASE),
        "PHP SQL query built with string concatenation",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-005",
        re.compile(r'\.raw\s*\(|\.extra\s*\(.*where', re.IGNORECASE),
        "Django ORM raw()/extra() - ensure no unsanitized input",
        Severity.MEDIUM, _SI,
    ),
]

_GUARD = re.compile(
    r'execute\s*\(|query\s*\(|cursor\.|\.raw\s*\(|\.extra\s*\(|\$sql|\$query|\$stmt',
    re.IGNORECASE,
)


class SQLInjectionAnalyzer(BaseAnalyzer):
    # .py is handled by PythonASTAnalyzer with higher precision
    supported_extensions = (".php", ".js", ".ts", ".java", ".rb")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        return self._scan_lines(file_path, content, repo_url, _RULES, guard=_GUARD)
