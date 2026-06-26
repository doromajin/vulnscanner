import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_HS = VulnType.HARDCODED_SECRET

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "SEC-001",
        re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "Hardcoded password literal",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-002",
        re.compile(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][A-Za-z0-9/+]{16,}["\']', re.IGNORECASE),
        "Hardcoded API key",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-003",
        re.compile(r'(?:secret_key|SECRET_KEY)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
        "Hardcoded secret key",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-004",
        re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
        "AWS access key ID pattern detected",
        Severity.CRITICAL, _HS,
    ),
    (
        "SEC-005",
        re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', re.IGNORECASE),
        "Private key material in source code",
        Severity.CRITICAL, _HS,
    ),
    (
        "SEC-006",
        re.compile(r'(?:token|auth_token|access_token)\s*=\s*["\'][A-Za-z0-9._\-]{20,}["\']', re.IGNORECASE),
        "Hardcoded token value",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-007",
        re.compile(
            r'(?:connection_string|conn_str|DATABASE_URL)\s*=\s*["\'](?:postgres|mysql|mongodb|redis)://[^"\']+["\']',
            re.IGNORECASE,
        ),
        "Database connection string with embedded credentials",
        Severity.HIGH, _HS,
    ),
]

# Merged allowlist: a single compiled OR pattern replaces three separate re.search calls.
_ALLOWLIST_RE = re.compile(
    r'example|sample|placeholder|your[_-]|<[^>]+>|\*{3,}|xxx|dummy|fake'
    r'|#.*(?:password|secret|key|token)'
    r'|^\s*//',
    re.IGNORECASE,
)

# Content-level guard: skip files that contain none of the relevant keywords.
_GUARD = re.compile(
    r'password|passwd|pwd|api[_-]?key|api[_-]?secret|secret[_-]?key|SECRET_KEY'
    r'|AKIA[0-9A-Z]|PRIVATE KEY|token|auth_token|access_token'
    r'|connection_string|conn_str|DATABASE_URL',
    re.IGNORECASE,
)


class HardcodedSecretsAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".js", ".ts", ".java", ".rb", ".php",
        ".env", ".yml", ".yaml", ".json", ".config",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            stripped = line.strip()
            for rule_id, pattern_re, description, severity, vuln_type in _RULES:
                if not pattern_re.search(line):
                    continue
                if _ALLOWLIST_RE.search(line):
                    continue
                findings.append(Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    file_path=file_path,
                    line_number=lineno,
                    line_content=stripped,
                    description=description,
                    rule_id=rule_id,
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, lineno),
                ))
        return findings
