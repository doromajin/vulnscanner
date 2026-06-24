import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# (rule_id, pattern, description, severity, extensions)
_RULES: list[tuple[str, str, str, Severity, tuple[str, ...]]] = [
    # ── Python / Jinja2 (regex fallback; AST handles .py with higher precision) ─
    (
        "SSTI-001",
        r'render_template_string\s*\(\s*(?![\'"`])',
        "Jinja2 render_template_string with non-literal template - SSTI leads to RCE",
        Severity.CRITICAL,
        (".py",),
    ),
    (
        "SSTI-002",
        r'(?:Environment|jinja2\.Environment)\s*\(\s*\)\.from_string\s*\(\s*(?![\'"`])',
        "Jinja2 Environment.from_string with non-literal template - SSTI risk",
        Severity.HIGH,
        (".py",),
    ),
    # ── PHP / Twig ─────────────────────────────────────────────────────────────
    (
        "SSTI-003",
        r'\$twig->(?:render|display)\s*\(\s*\$(?!_)',
        "Twig render/display with variable template name - verify template is not user-controlled",
        Severity.HIGH,
        (".php",),
    ),
    (
        "SSTI-004",
        r'\$smarty->(?:display|fetch)\s*\(\s*\$(?!_)',
        "Smarty display/fetch with variable template - SSTI risk",
        Severity.HIGH,
        (".php",),
    ),
    # ── Ruby / ERB ─────────────────────────────────────────────────────────────
    (
        "SSTI-005",
        r'ERB\.new\s*\(\s*(?![\'"])',
        "Ruby ERB.new with non-literal template - SSTI risk if template is user-controlled",
        Severity.CRITICAL,
        (".rb",),
    ),
    # ── Node.js template engines ───────────────────────────────────────────────
    (
        "SSTI-006",
        r'\bejs\.render(?:File)?\s*\(\s*(?![\'"`])',
        "EJS render with non-literal template - SSTI risk",
        Severity.CRITICAL,
        (".js", ".ts"),
    ),
    (
        "SSTI-007",
        r'\bHandlebars\.compile\s*\(\s*(?![\'"`])',
        "Handlebars compile with non-literal template - SSTI risk",
        Severity.CRITICAL,
        (".js", ".ts"),
    ),
    (
        "SSTI-008",
        r'\bnunjucks\.renderString\s*\(\s*(?![\'"`])',
        "Nunjucks renderString with non-literal template - SSTI risk",
        Severity.CRITICAL,
        (".js", ".ts"),
    ),
    (
        "SSTI-009",
        r'\bpug\.(?:compile|render)\s*\(\s*(?![\'"`])',
        "Pug compile/render with non-literal template - SSTI risk",
        Severity.CRITICAL,
        (".js", ".ts"),
    ),
]


class SSTIAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".php", ".rb", ".js", ".ts")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule_id, pattern, description, severity, exts in _RULES:
            if not file_path.endswith(exts):
                continue
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        vuln_type=VulnType.SSTI,
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
