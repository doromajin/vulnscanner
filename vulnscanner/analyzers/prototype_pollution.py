import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_PP = VulnType.PROTOTYPE_POLLUTION
_XS = VulnType.XSS

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "PROTO-001",
        re.compile(r'__proto__\s*[\[=]', re.IGNORECASE),
        "Direct __proto__ assignment - prototype pollution can affect all objects in the process",
        Severity.HIGH, _PP,
    ),
    (
        "PROTO-002",
        re.compile(r'constructor\s*\.\s*prototype\s*[\[.]', re.IGNORECASE),
        "Modification via constructor.prototype - prototype pollution risk",
        Severity.HIGH, _PP,
    ),
    (
        "PROTO-003",
        re.compile(
            r'Object\.(?:assign|merge)\s*\(\s*\w+\s*,\s*(?:req\.(?:body|query|params)|JSON\.parse)',
            re.IGNORECASE,
        ),
        "Object.assign/merge with request data as source - prototype pollution if keys include __proto__",
        Severity.HIGH, _PP,
    ),
    (
        "PROTO-004",
        re.compile(
            r'(?:_\.merge|_\.extend|jQuery\.extend|deepmerge|lodash\.merge)\s*\(\s*(?:true\s*,\s*)?\w+\s*,\s*(?:req\.|JSON\.parse)',
            re.IGNORECASE,
        ),
        "Deep merge with user-controlled object - prototype pollution risk",
        Severity.HIGH, _PP,
    ),
    (
        "PROTO-005",
        re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\s*\{', re.IGNORECASE),
        "dangerouslySetInnerHTML bypasses React's XSS protection - ensure content is sanitized",
        Severity.HIGH, _XS,
    ),
]

_GUARD = re.compile(
    r'__proto__|constructor\.prototype|Object\.(?:assign|merge)|'
    r'_\.(?:merge|extend)|jQuery\.extend|deepmerge|lodash\.merge|dangerouslySetInnerHTML',
    re.IGNORECASE,
)


class PrototypePollutionAnalyzer(BaseAnalyzer):
    supported_extensions = (".js", ".ts", ".jsx", ".tsx")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        return self._scan_lines(file_path, content, repo_url, _RULES, guard=_GUARD)
