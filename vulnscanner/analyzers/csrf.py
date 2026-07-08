import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_CSRF = VulnType.CSRF

# ── Django ──────────────────────────────────────────────────────────────────────
# @csrf_exempt on a view that handles state-changing requests
_DJANGO_EXEMPT_RE = re.compile(r'@\s*csrf_exempt', re.IGNORECASE)

# Django form missing {% csrf_token %} — POST form without token tag
_DJANGO_FORM_RE  = re.compile(r'<form[^>]*method\s*=\s*["\']post["\'][^>]*>', re.IGNORECASE)
_DJANGO_TOKEN_RE = re.compile(r'\{%[-\s]*csrf_token[-\s]*%\}', re.IGNORECASE)

# ── Flask / Werkzeug ─────────────────────────────────────────────────────────────
# WTForms CSRF disabled: app.config['WTF_CSRF_ENABLED'] = False
_FLASK_CSRF_OFF_RE = re.compile(
    r'WTF_CSRF_ENABLED\s*[=:]\s*False',
    re.IGNORECASE,
)

# CSRFProtect not initialised but flask-wtf is imported
_FLASK_NO_PROTECT_RE = re.compile(
    r'from\s+flask_wtf(?:\.csrf)?\s+import\b(?!.*CSRFProtect)',
    re.IGNORECASE,
)

# ── Express / Node ───────────────────────────────────────────────────────────────
# csurf / csrf npm package not used while express-session is present
_EXPRESS_SESSION_RE = re.compile(r'require\s*\(\s*["\']express-session["\']', re.IGNORECASE)
_EXPRESS_CSRF_RE    = re.compile(r'require\s*\(\s*["\'](?:csurf|csrf)["\']', re.IGNORECASE)

# ── Spring (Java) ────────────────────────────────────────────────────────────────
# .csrf().disable() in Spring Security config
_SPRING_CSRF_DISABLE_RE = re.compile(
    r'\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)',
    re.IGNORECASE,
)

# ── Ruby on Rails ────────────────────────────────────────────────────────────────
# skip_before_action :verify_authenticity_token
_RAILS_SKIP_RE = re.compile(
    r'skip_before_action\s+:verify_authenticity_token',
    re.IGNORECASE,
)
# protect_from_forgery with: :null_session or :exception disabled
_RAILS_NULL_SESSION_RE = re.compile(
    r'protect_from_forgery\s+with:\s*:null_session',
    re.IGNORECASE,
)

# ── PHP ──────────────────────────────────────────────────────────────────────────
# Laravel: ->withoutMiddleware(VerifyCsrfToken::class)
_LARAVEL_SKIP_RE = re.compile(
    r'withoutMiddleware\s*\(\s*(?:VerifyCsrfToken|\\\\App\\\\Http\\\\Middleware\\\\VerifyCsrfToken)',
    re.IGNORECASE,
)

_GUARD = re.compile(
    r'csrf_exempt|WTF_CSRF|csrf\(\)|\.csrf\(\)|verify_authenticity_token'
    r'|VerifyCsrfToken|csurf|<form[^>]*method'
    r'|protect_from_forgery|express-session',
    re.IGNORECASE,
)


class CSRFAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".html", ".js", ".ts", ".java", ".rb", ".php",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            stripped = line.strip()

            # Django: @csrf_exempt decorator
            if file_path.endswith(".py") and _DJANGO_EXEMPT_RE.search(line):
                findings.append(self._make(
                    "CSRF-001", Severity.HIGH,
                    "Django @csrf_exempt disables CSRF protection on this view",
                    file_path, lineno, stripped, lines, repo_url,
                ))

            # Django HTML template: POST form without {% csrf_token %}
            if file_path.endswith((".html", ".htm")) and _DJANGO_FORM_RE.search(line):
                # Check the next 10 lines for a csrf_token tag
                window = "\n".join(lines[lineno - 1: lineno + 10])
                if not _DJANGO_TOKEN_RE.search(window):
                    findings.append(self._make(
                        "CSRF-002", Severity.HIGH,
                        "HTML POST form missing {% csrf_token %} — CSRF protection absent",
                        file_path, lineno, stripped, lines, repo_url,
                    ))

            # Flask/WTForms: CSRF disabled in config
            if file_path.endswith(".py") and _FLASK_CSRF_OFF_RE.search(line):
                findings.append(self._make(
                    "CSRF-003", Severity.HIGH,
                    "Flask-WTF CSRF protection explicitly disabled (WTF_CSRF_ENABLED = False)",
                    file_path, lineno, stripped, lines, repo_url,
                ))

            # Spring Security: .csrf().disable()
            if file_path.endswith(".java") and _SPRING_CSRF_DISABLE_RE.search(line):
                findings.append(self._make(
                    "CSRF-004", Severity.HIGH,
                    "Spring Security CSRF protection disabled via .csrf().disable()",
                    file_path, lineno, stripped, lines, repo_url,
                ))

            # Rails: skip_before_action :verify_authenticity_token
            if file_path.endswith(".rb") and _RAILS_SKIP_RE.search(line):
                findings.append(self._make(
                    "CSRF-005", Severity.HIGH,
                    "Rails skips CSRF token verification — all actions in this controller are unprotected",
                    file_path, lineno, stripped, lines, repo_url,
                ))

            # Rails: protect_from_forgery with: :null_session
            if file_path.endswith(".rb") and _RAILS_NULL_SESSION_RE.search(line):
                findings.append(self._make(
                    "CSRF-006", Severity.MEDIUM,
                    "Rails protect_from_forgery uses :null_session — API endpoints may accept forged requests",
                    file_path, lineno, stripped, lines, repo_url,
                ))

            # Laravel: withoutMiddleware(VerifyCsrfToken)
            if file_path.endswith(".php") and _LARAVEL_SKIP_RE.search(line):
                findings.append(self._make(
                    "CSRF-007", Severity.HIGH,
                    "Laravel route bypasses VerifyCsrfToken middleware",
                    file_path, lineno, stripped, lines, repo_url,
                ))

        # Express: session used but no csrf middleware required in same file
        if file_path.endswith((".js", ".ts")):
            if _EXPRESS_SESSION_RE.search(content) and not _EXPRESS_CSRF_RE.search(content):
                findings.append(self._make(
                    "CSRF-008", Severity.MEDIUM,
                    "Express session used without csurf/csrf middleware in this file — verify CSRF protection is configured",
                    file_path, 1, lines[0].strip() if lines else "", lines, repo_url,
                ))

        return findings

    def _make(
        self, rule_id: str, severity: Severity, description: str,
        file_path: str, lineno: int, stripped: str,
        lines: list[str], repo_url: str,
    ) -> Finding:
        return Finding(
            vuln_type=_CSRF,
            severity=severity,
            file_path=file_path,
            line_number=lineno,
            line_content=stripped,
            description=description,
            rule_id=rule_id,
            repo_url=repo_url,
            snippet=self._extract_snippet(lines, lineno),
        )
