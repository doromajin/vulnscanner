from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnType(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    HARDCODED_SECRET = "Hardcoded Secret"


@dataclass
class Finding:
    vuln_type: VulnType
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    description: str
    rule_id: str
    repo_url: Optional[str] = None
    snippet: Optional[str] = None  # surrounding lines for context


@dataclass
class ScanResult:
    repo_url: str
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_lines: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]
