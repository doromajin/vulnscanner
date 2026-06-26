import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_ST = VulnType.SSTI

# (rule_id, compiled_re, description, severity, vuln_type, exts)
_RULES = [
    (
        "SSTI-001",
        re.compile(r'render_template_string\s*\(\s*(?![\'"`])', re.IGNORECASE),
        "Jinja2 render_template_string with non-literal template - SSTI leads to RCE",
        Severity.CRITICAL, _ST, (".py",),
    ),
    (
        "SSTI-002",
        re.compile(r'(?:Environment|jinja2\.Environment)\s*\(\s*\)\.from_string\s*\(\s*(?![\'"`])', re.IGNORECASE),
        "Jinja2 Environment.from_string with non-literal template - SSTI risk",
        Severity.HIGH, _ST, (".py",),
    ),
    (
        "SSTI-003",
        re.compile(r'\$twig->(?:render|display)\s*\(\s*\$(?!_)', re.IGNORECASE),
        "Twig render/display with variable template name - verify template is not user-controlled",
        Severity.HIGH, _ST, (".php",),
    ),
    (
        "SSTI-004",
        re.compile(r'\$smarty->(?:display|fetch)\s*\(\s*\$(?!_)', re.IGNORECASE),
        "Smarty display/fetch with variable template - SSTI risk",
        Severity.HIGH, _ST, (".php",),
    ),
    (
        "SSTI-005",
        re.compile(r'ERB\.new\s*\(\s*(?![\'"])', re.IGNORECASE),
        "Ruby ERB.new with non-literal template - SSTI risk if template is user-controlled",
        Severity.CRITICAL, _ST, (".rb",),
    ),
    (
        "SSTI-006",
        re.compile(r'\bejs\.render(?:File)?\s*\(\s*(?![\'"`])', re.IGNORECASE),
        "EJS render with non-literal template - SSTI risk",
        Severity.CRITICAL, _ST, (".js", ".ts"),
    ),
    (
        "SSTI-007",
        re.compile(r'\bHandlebars\.compile\s*\(\s*(?![\'"`])', re.IGNORECASE),
        "Handlebars compile with non-literal template - SSTI risk",
        Severity.CRITICAL, _ST, (".js", ".ts"),
    ),
    (
        "SSTI-008",
        re.compile(r'\bnunjucks\.renderString\s*\(\s*(?![\'"`])', re.IGNORECASE),
        "Nunjucks renderString with non-literal template - SSTI risk",
        Severity.CRITICAL, _ST, (".js", ".ts"),
    ),
    (
        "SSTI-009",
        re.compile(r'\bpug\.(?:compile|render)\s*\(\s*(?![\'"`])', re.IGNORECASE),
        "Pug compile/render with non-literal template - SSTI risk",
        Severity.CRITICAL, _ST, (".js", ".ts"),
    ),
]

_GUARD = re.compile(
    r'render_template_string|from_string|twig->|smarty->|ERB\.new|ejs\.render|Handlebars\.compile'
    r'|nunjucks\.renderString|pug\.(?:compile|render)',
    re.IGNORECASE,
)


class SSTIAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".php", ".rb", ".js", ".ts")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if file_path.endswith(exts)
        ]
        if not applicable:
            return []
        return self._scan_lines(file_path, content, repo_url, applicable, guard=_GUARD)
