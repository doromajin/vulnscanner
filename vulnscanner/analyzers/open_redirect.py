import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# (rule_id, pattern, description, severity, extensions)
_RULES: list[tuple[str, str, str, Severity, tuple[str, ...]]] = [
    # ── PHP ────────────────────────────────────────────────────────────────────
    (
        "REDIR-001",
        r"header\s*\(\s*['\"]Location:\s*['\"].*\.\s*\$_(?:GET|POST|REQUEST)",
        "PHP Location header with user input — open redirect allows phishing attacks",
        Severity.HIGH,
        (".php",),
    ),
    (
        "REDIR-002",
        r"header\s*\(\s*['\"]Location:\s*['\"]\s*\.\s*\$(?!_(?:GET|POST|REQUEST))",
        "PHP Location header with variable — verify redirect destination is allowlisted",
        Severity.MEDIUM,
        (".php",),
    ),
    # ── Java / Spring ──────────────────────────────────────────────────────────
    (
        "REDIR-003",
        r'(?:response\.)?sendRedirect\s*\(.*request\.getParameter\s*\(',
        "Java sendRedirect with request parameter — open redirect risk",
        Severity.HIGH,
        (".java",),
    ),
    (
        "REDIR-004",
        r'RedirectView\s*\(.*(?:getParameter|getAttribute)\s*\(',
        "Spring RedirectView with request attribute — verify redirect target",
        Severity.HIGH,
        (".java",),
    ),
    # ── Node.js / Express ──────────────────────────────────────────────────────
    (
        "REDIR-005",
        r'res\.redirect\s*\(\s*(?:\d+\s*,\s*)?req\.(?:query|body|params)',
        "Express redirect with user-controlled URL — open redirect risk",
        Severity.HIGH,
        (".js", ".ts"),
    ),
    (
        "REDIR-006",
        r'res\.redirect\s*\(\s*(?:\d+\s*,\s*)?`[^`]*\$\{req\.',
        "Express redirect with URL template containing request data — open redirect risk",
        Severity.HIGH,
        (".js", ".ts"),
    ),
    # ── Ruby / Rails ───────────────────────────────────────────────────────────
    (
        "REDIR-007",
        r'redirect_to\s+params\[',
        "Rails redirect_to with params — open redirect; validate with allow_other_host: false",
        Severity.HIGH,
        (".rb",),
    ),
    # ── Go ─────────────────────────────────────────────────────────────────────
    (
        "REDIR-008",
        r'http\.Redirect\s*\(.*r\.(?:FormValue|URL\.Query|Header\.Get)',
        "Go http.Redirect with request-derived URL — open redirect risk",
        Severity.HIGH,
        (".go",),
    ),
]


class OpenRedirectAnalyzer(BaseAnalyzer):
    # Python open redirects are detected by PythonASTAnalyzer.
    supported_extensions = (".php", ".java", ".js", ".ts", ".rb", ".go")

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
                        vuln_type=VulnType.OPEN_REDIRECT,
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
