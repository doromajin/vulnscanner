import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RULES: list[tuple[str, str, str, Severity]] = [
    (
        "PROTO-001",
        r'__proto__\s*[\[=]',
        "Direct __proto__ assignment - prototype pollution can affect all objects in the process",
        Severity.HIGH,
    ),
    (
        "PROTO-002",
        r'constructor\s*\.\s*prototype\s*[\[.]',
        "Modification via constructor.prototype - prototype pollution risk",
        Severity.HIGH,
    ),
    (
        "PROTO-003",
        # Object.assign / merge into a target where the source comes from request data
        r'Object\.(?:assign|merge)\s*\(\s*\w+\s*,\s*(?:req\.(?:body|query|params)|JSON\.parse)',
        "Object.assign/merge with request data as source - prototype pollution if keys include __proto__",
        Severity.HIGH,
    ),
    (
        "PROTO-004",
        # Deep merge / extend libraries often used unsafely
        r'(?:_\.merge|_\.extend|jQuery\.extend|deepmerge|lodash\.merge)\s*\(\s*(?:true\s*,\s*)?\w+\s*,\s*(?:req\.|JSON\.parse)',
        "Deep merge with user-controlled object - prototype pollution risk",
        Severity.HIGH,
    ),
    (
        "PROTO-005",
        # React dangerouslySetInnerHTML - XSS risk
        r'dangerouslySetInnerHTML\s*=\s*\{\s*\{',
        "dangerouslySetInnerHTML bypasses React's XSS protection - ensure content is sanitized",
        Severity.HIGH,
    ),
]


class PrototypePollutionAnalyzer(BaseAnalyzer):
    supported_extensions = (".js", ".ts", ".jsx", ".tsx")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule_id, pattern, description, severity in _RULES:
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = (
                        VulnType.XSS if rule_id == "PROTO-005"
                        else VulnType.PROTOTYPE_POLLUTION
                    )
                    findings.append(Finding(
                        vuln_type=vuln,
                        severity=severity,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line.strip(),
                        description=description,
                        rule_id=rule_id,
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))

        return findings
