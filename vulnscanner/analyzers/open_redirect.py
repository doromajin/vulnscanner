import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_OR = VulnType.OPEN_REDIRECT

# (rule_id, compiled_re, description, severity, vuln_type, exts)
_RULES = [
    (
        "REDIR-001",
        re.compile(r"header\s*\(\s*['\"]Location:\s*['\"].*\.\s*\$_(?:GET|POST|REQUEST)", re.IGNORECASE),
        "PHP Location header with user input - open redirect allows phishing attacks",
        Severity.HIGH, _OR, (".php",),
    ),
    (
        "REDIR-002",
        re.compile(r"header\s*\(\s*['\"]Location:\s*['\"]\s*\.\s*\$(?!_(?:GET|POST|REQUEST))", re.IGNORECASE),
        "PHP Location header with variable - verify redirect destination is allowlisted",
        Severity.MEDIUM, _OR, (".php",),
    ),
    (
        "REDIR-003",
        re.compile(r'(?:response\.)?sendRedirect\s*\(.*request\.getParameter\s*\(', re.IGNORECASE),
        "Java sendRedirect with request parameter - open redirect risk",
        Severity.HIGH, _OR, (".java",),
    ),
    (
        "REDIR-004",
        re.compile(r'RedirectView\s*\(.*(?:getParameter|getAttribute)\s*\(', re.IGNORECASE),
        "Spring RedirectView with request attribute - verify redirect target",
        Severity.HIGH, _OR, (".java",),
    ),
    (
        "REDIR-005",
        re.compile(r'res\.redirect\s*\(\s*(?:\d+\s*,\s*)?req\.(?:query|body|params)', re.IGNORECASE),
        "Express redirect with user-controlled URL - open redirect risk",
        Severity.HIGH, _OR, (".js", ".ts"),
    ),
    (
        "REDIR-006",
        re.compile(r'res\.redirect\s*\(\s*(?:\d+\s*,\s*)?`[^`]*\$\{req\.', re.IGNORECASE),
        "Express redirect with URL template containing request data - open redirect risk",
        Severity.HIGH, _OR, (".js", ".ts"),
    ),
    (
        "REDIR-007",
        re.compile(r'redirect_to\s+params\[', re.IGNORECASE),
        "Rails redirect_to with params - open redirect; validate with allow_other_host: false",
        Severity.HIGH, _OR, (".rb",),
    ),
    (
        "REDIR-008",
        re.compile(r'http\.Redirect\s*\(.*r\.(?:FormValue|URL\.Query|Header\.Get)', re.IGNORECASE),
        "Go http.Redirect with request-derived URL - open redirect risk",
        Severity.HIGH, _OR, (".go",),
    ),
    (
        "REDIR-009",
        re.compile(
            r'Response\.Redirect(?:Permanent)?\s*\(.*(?:HttpContext\.Current\.)?Request\.(?:QueryString|Form|Params)\s*\[',
            re.IGNORECASE,
        ),
        "ASP.NET Response.Redirect with Request.QueryString/Form/Params value - open redirect allows phishing attacks",
        Severity.HIGH, _OR, (".cs",),
    ),
    (
        "REDIR-010",
        re.compile(
            r'redirect\s*\(\s*request\.(?:args|form|values|GET|POST)\s*(?:\.get\s*\(|\[)',
            re.IGNORECASE,
        ),
        "Python redirect() with user-controlled request parameter - open redirect allows phishing attacks",
        Severity.HIGH, _OR, (".py",),
    ),
]

_GUARD = re.compile(
    r'Location:|sendRedirect|RedirectView|res\.redirect|redirect_to|http\.Redirect|Response\.Redirect|\bredirect\s*\(',
    re.IGNORECASE,
)


class OpenRedirectAnalyzer(BaseAnalyzer):
    # Python open redirects are detected by PythonASTAnalyzer.
    supported_extensions = (".php", ".java", ".js", ".ts", ".rb", ".go", ".cs", ".py")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if file_path.endswith(exts)
        ]
        if not applicable:
            return []
        return self._scan_lines(file_path, content, repo_url, applicable, guard=_GUARD)
