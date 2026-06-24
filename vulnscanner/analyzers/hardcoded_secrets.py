import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RULES = [
    (
        "SEC-001",
        r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
        "Hardcoded password literal",
        Severity.HIGH,
    ),
    (
        "SEC-002",
        r'(?:api_key|apikey|api_secret)\s*=\s*["\'][A-Za-z0-9/+]{16,}["\']',
        "Hardcoded API key",
        Severity.HIGH,
    ),
    (
        "SEC-003",
        r'(?:secret_key|SECRET_KEY)\s*=\s*["\'][^"\']{8,}["\']',
        "Hardcoded secret key",
        Severity.HIGH,
    ),
    (
        "SEC-004",
        r'AKIA[0-9A-Z]{16}',
        "AWS access key ID pattern detected",
        Severity.CRITICAL,
    ),
    (
        "SEC-005",
        r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "Private key material in source code",
        Severity.CRITICAL,
    ),
    (
        "SEC-006",
        r'(?:token|auth_token|access_token)\s*=\s*["\'][A-Za-z0-9._\-]{20,}["\']',
        "Hardcoded token value",
        Severity.HIGH,
    ),
    (
        "SEC-007",
        r'(?:connection_string|conn_str|DATABASE_URL)\s*=\s*["\'](?:postgres|mysql|mongodb|redis)://[^"\']+["\']',
        "Database connection string with embedded credentials",
        Severity.HIGH,
    ),
]

_ALLOWLIST_PATTERNS = [
    r'example|sample|placeholder|your[_-]|<.*>|\*{3,}|xxx|dummy|fake',
    r'#.*password',
    r'^\s*//',
]


class HardcodedSecretsAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".js", ".ts", ".java", ".rb", ".php",
        ".env", ".yml", ".yaml", ".json", ".config",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule_id, pattern, description, severity in _RULES:
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                if any(re.search(a, line, re.IGNORECASE) for a in _ALLOWLIST_PATTERNS):
                    continue
                findings.append(
                    Finding(
                        vuln_type=VulnType.HARDCODED_SECRET,
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
