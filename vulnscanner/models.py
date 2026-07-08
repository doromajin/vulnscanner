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
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    SSRF = "Server-Side Request Forgery (SSRF)"
    OPEN_REDIRECT = "Open Redirect"
    SSTI = "Server-Side Template Injection (SSTI)"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    VULNERABLE_DEPENDENCY = "Vulnerable Dependency"
    XXE = "XML External Entity (XXE)"
    JNDI_INJECTION = "JNDI Injection"
    RACE_CONDITION = "Race Condition"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    WEAK_CRYPTOGRAPHY = "Weak Cryptography"


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
    snippet: Optional[str] = None
    suppression_reason: Optional[str] = None  # set by scanner or AST analyzer
    taint_status: Optional[str] = None        # "tainted" | "unknown" | "clean"
    taint_reason: Optional[str] = None
    taint_source: Optional[str] = None
    confidence: float = 1.0


@dataclass
class ScanResult:
    repo_url: str
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_lines: int = 0
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    suppressed_count: int = 0
    suppression_breakdown: dict = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]
