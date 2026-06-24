import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# Path segments that indicate test/fixture code - secrets there are low-risk
# Learned from WebGoat: 10 SEC-001 findings in src/test/ were expected test setup
_TEST_PATH_SEGMENTS = frozenset({
    "test", "tests", "spec", "specs", "__tests__",
    "fixtures", "mocks", "stubs", "fakes",
    "it",  # Java integration tests (src/it/)
})

_TEST_FILE_SUFFIXES = ("test.java", "tests.java", "spec.java", "test.py",
                       "_test.py", "test.js", "spec.js", "spec.ts", "test.ts")


def _is_test_path(file_path: str) -> bool:
    parts = file_path.replace("\\", "/").lower().split("/")
    if any(p in _TEST_PATH_SEGMENTS for p in parts):
        return True
    return file_path.lower().endswith(_TEST_FILE_SUFFIXES)


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
        # AWS access key pattern
        r'AKIA[0-9A-Z]{16}',
        "AWS access key ID pattern detected",
        Severity.CRITICAL,
    ),
    (
        "SEC-005",
        # Private key header
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

# Lines that are clearly test/example values - skip them
_ALLOWLIST_PATTERNS = [
    r'example|sample|placeholder|your[_-]|<.*>|\*{3,}|xxx|dummy|fake',
    r'#.*password',  # commented out
    r'^\s*//',       # JS/Java comment line
]


class HardcodedSecretsAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".js", ".ts", ".java", ".rb", ".php",
        ".env", ".yml", ".yaml", ".json", ".config",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        in_test = _is_test_path(file_path)

        for rule_id, pattern, description, severity in _RULES:
            # Downgrade non-CRITICAL findings in test/fixture code to LOW
            # Confirmed via WebGoat: test passwords are expected and not exploitable
            effective_severity = severity
            if in_test and severity not in (Severity.CRITICAL,):
                effective_severity = Severity.LOW

            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                if any(re.search(a, line, re.IGNORECASE) for a in _ALLOWLIST_PATTERNS):
                    continue
                desc = description
                if in_test and effective_severity != severity:
                    desc = f"{description} [test file - severity reduced]"
                findings.append(
                    Finding(
                        vuln_type=VulnType.HARDCODED_SECRET,
                        severity=effective_severity,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line.strip(),
                        description=desc,
                        rule_id=rule_id,
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    )
                )

        return findings
