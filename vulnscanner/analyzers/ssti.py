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


_PY_DEF_RE = re.compile(r"\s*(?:async\s+)?def\s")

# Twig's sandbox is the documented mitigation for rendering less-trusted templates
# (e.g. user-editable invoice layouts).  Registering SandboxExtension alone does not
# turn it on: it needs ->enableSandbox() or the "sandbox everything" flag (2nd arg true).
_TWIG_SANDBOX_ON = re.compile(
    r'->\s*enableSandbox\s*\('
    r'|new\s+(?:\\?[\w\\]+\\)?SandboxExtension\s*\([^;]*,\s*true\s*\)',
)


# A template read from the page itself (`<script type="text/template">`) with a literal selector / id
# is static markup shipped with the app, not attacker-controlled input.
_DOM_TEMPLATE_READ = (
    r'(?:(?:\$|jQuery)\s*\(\s*[\'"][^\'"`$+{}]+[\'"]\s*\)\s*\.\s*(?:html|text)\s*\(\s*\)'
    r'|document\s*\.\s*getElementById\s*\(\s*[\'"][^\'"`$+{}]+[\'"]\s*\)\s*\.\s*(?:innerHTML|textContent|text|innerText)'
    r'|document\s*\.\s*querySelector\s*\(\s*[\'"][^\'"`$+{}]+[\'"]\s*\)\s*\.\s*(?:innerHTML|textContent|text|innerText))'
)
_DOM_READ_FULL_RE = re.compile(r'^\s*' + _DOM_TEMPLATE_READ + r'\s*$')
_COMPILE_IDENT_RE = re.compile(r'\bHandlebars\.compile\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]')


def _is_dom_template_compile(line: str, lines: list[str], lineno: int) -> bool:
    ident = _COMPILE_IDENT_RE.search(line)
    if ident:
        name = re.escape(ident.group(1))
        assign = re.compile(r'(?:\b(?:var|let|const)\s+)?\b' + name + r'\s*=\s*(.+?)\s*;?\s*$')
        values = []
        for prev in lines[:lineno - 1]:
            m = assign.search(prev)
            if m and not re.search(r'\b' + name + r'\s*=[=>]', prev):
                values.append(m.group(1))
        return bool(values) and all(_DOM_READ_FULL_RE.match(v) for v in values)
    m = re.search(r'\bHandlebars\.compile\s*\(\s*(' + _DOM_TEMPLATE_READ + r')\s*[,)]', line)
    return bool(m)


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
        findings = self._scan_lines(file_path, content, repo_url, applicable, guard=_GUARD)
        findings = [
            f for f in findings
            if not (f.rule_id == "SSTI-001" and _PY_DEF_RE.match(f.line_content))
        ]
        if any(f.rule_id == "SSTI-007" for f in findings):
            src_lines = content.splitlines()
            findings = [
                f for f in findings
                if not (f.rule_id == "SSTI-007"
                        and _is_dom_template_compile(f.line_content, src_lines, f.line_number))
            ]
        if findings and _TWIG_SANDBOX_ON.search(content):
            findings = [f for f in findings if f.rule_id != "SSTI-003"]
        return findings
