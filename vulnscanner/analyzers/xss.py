import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RULES = [
    (
        "XSS-001",
        r'innerHTML\s*=\s*(?![\'"]\s*[\'"])',
        "Direct innerHTML assignment — user data written without sanitization",
        Severity.HIGH,
    ),
    (
        "XSS-002",
        r'document\.write\s*\(',
        "document.write() with potentially unsanitized input",
        Severity.HIGH,
    ),
    (
        "XSS-003",
        r'outerHTML\s*=\s*(?![\'"]\s*[\'"])',
        "Direct outerHTML assignment",
        Severity.HIGH,
    ),
    (
        "XSS-004",
        # Python: render without escape in Jinja2/Django templates
        r'\|\s*safe\b|mark_safe\s*\(|format_html\s*\(.*\+',
        "Template value marked safe without explicit sanitization",
        Severity.MEDIUM,
    ),
    (
        "XSS-005",
        # PHP echo with $_GET/$_POST/$_REQUEST
        r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE)',
        "PHP direct echo of user-supplied input",
        Severity.HIGH,
    ),
    (
        "XSS-006",
        r'insertAdjacentHTML\s*\(',
        "insertAdjacentHTML() — verify content is sanitized",
        Severity.MEDIUM,
    ),
    (
        "XSS-007",
        r'eval\s*\(\s*(?:location|document\.|window\.)',
        "eval() with browser-controlled input",
        Severity.CRITICAL,
    ),
]


class XSSAnalyzer(BaseAnalyzer):
    supported_extensions = (".js", ".ts", ".jsx", ".tsx", ".html", ".php", ".py")

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
                            vuln_type=VulnType.XSS,
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
