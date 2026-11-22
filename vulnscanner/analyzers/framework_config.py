"""Framework configuration checks (Django settings, Laravel config files).

Only settings that are unsafe as written are reported, and only in the files that frameworks
read as production configuration:

  Django   settings*.py / settings/*.py   DEBUG = True, ALLOWED_HOSTS = ['*'], cookie flags off
  Laravel  config/app.php                 debug on by default, APP_KEY with a hardcoded fallback
           config/session.php             http_only / secure switched off
           config/cors.php                wildcard origins together with credentials

A value read from the environment with a safe default (``env('APP_DEBUG', false)``) is fine, so
the rules look for the literal unsafe value rather than for the setting's name.
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_CFG = VulnType.FRAMEWORK_MISCONFIGURATION

# Settings files meant for a developer machine or a test run, not for production.
_DEV_NAME_RE = re.compile(r"(?:^|[/_.-])(?:dev|develop|development|local|test|tests|testing|ci|example|sample|demo)(?:[/_.-]|$)",
                          re.IGNORECASE)

_DJANGO_MARKERS = re.compile(r"\bINSTALLED_APPS\b|\bSECRET_KEY\b|\bALLOWED_HOSTS\b|^DEBUG\s*=", re.MULTILINE)

# (rule_id, pattern, description, severity, dev_severity, cwe)
_DJANGO_RULES = [
    ("CFG-DJ-001", re.compile(r"^DEBUG\s*=\s*True\b"),
     "DEBUG = True: error pages expose settings, file paths and queries. Read it from the environment and default to False",
     Severity.MEDIUM, Severity.LOW, 489),
    ("CFG-DJ-002", re.compile(r"""^ALLOWED_HOSTS\s*=\s*[\[(]\s*['"]\*['"]\s*[\])]"""),
     "ALLOWED_HOSTS accepts every Host header (password-reset link poisoning, cache poisoning). List the real host names",
     Severity.MEDIUM, Severity.LOW, 16),
    ("CFG-DJ-003", re.compile(r"^(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False\b"),
     "Cookie 'Secure' flag is switched off: the session / CSRF cookie is also sent over plain HTTP",
     Severity.LOW, Severity.LOW, 614),
    ("CFG-DJ-005", re.compile(r"^AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]"),
     "AUTH_PASSWORD_VALIDATORS is empty: any password, however weak, is accepted. Enable Django's validators",
     Severity.LOW, Severity.LOW, 521),
    ("CFG-DJ-006", re.compile(r"^SESSION_COOKIE_SAMESITE\s*=\s*(?:None\b|['\"]None['\"])"),
     "SESSION_COOKIE_SAMESITE is off: the session cookie is sent on cross-site requests. Use 'Lax' or 'Strict'",
     Severity.LOW, Severity.LOW, 1275),
    ("CFG-DJ-004", re.compile(r"^SESSION_COOKIE_HTTPONLY\s*=\s*False\b"),
     "SESSION_COOKIE_HTTPONLY = False lets page scripts read the session cookie (turns any XSS into session theft)",
     Severity.MEDIUM, Severity.LOW, 1004),
]

_LV_DEBUG_RE = re.compile(r"""['"]debug['"]\s*=>\s*(?:true\b|env\(\s*['"]APP_DEBUG['"]\s*,\s*true\s*\))""", re.IGNORECASE)
_LV_KEY_RE = re.compile(r"""['"]key['"]\s*=>\s*env\(\s*['"]APP_KEY['"]\s*,\s*['"]([^'"]+)['"]\s*\)""")
# A key Laravel accepts: 16 or 32 raw characters, or base64 of 16 / 32 bytes.
_LV_VALID_KEY_RE = re.compile(r"^(?:base64:[A-Za-z0-9+/]{22}={2}|base64:[A-Za-z0-9+/]{43}=|.{16}|.{32})$")
_ENV_TEMPLATE_RE = re.compile(r"example|sample|dist|template|stub", re.IGNORECASE)
_ENV_KEY_RE = re.compile(r"""^\s*APP_KEY\s*=\s*['"]?(?!['"]?\s*$)(?!SomeRandomString)(?!base64:?['"]?\s*$)\S+""")
_ENV_DEBUG_RE = re.compile(r"""^\s*APP_DEBUG\s*=\s*['"]?true\b""", re.IGNORECASE)
_GATE_OPEN_RE = re.compile(
    r"""Gate::define\(\s*['"](view(?:Telescope|Horizon))['"]\s*,\s*function\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{\s*return\s+true\s*;""",
    re.IGNORECASE)
_LV_SAMESITE_RE = re.compile(r"""['"]same_site['"]\s*=>\s*(?:null\b|['"]none['"])""", re.IGNORECASE)
_LV_HTTPONLY_RE =re.compile(r"""['"]http_only['"]\s*=>\s*false\b""", re.IGNORECASE)
_LV_SECURE_RE = re.compile(r"""['"]secure['"]\s*=>\s*false\b""", re.IGNORECASE)
_LV_WILDCARD_ORIGIN_RE = re.compile(r"""['"]allowed_origins['"]\s*=>\s*\[\s*['"]\*['"]""")
_LV_CREDENTIALS_RE = re.compile(r"""['"]supports_credentials['"]\s*=>\s*true\b""", re.IGNORECASE)


class FrameworkConfigAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".php", ".env")

    def supports(self, file_path: str) -> bool:
        base = file_path.replace("\\", "/").rsplit("/", 1)[-1]
        return file_path.endswith(self.supported_extensions) or base.startswith(".env.")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        norm = file_path.replace("\\", "/")
        name = norm.rsplit("/", 1)[-1]
        if name.startswith(".env"):
            return self._dotenv(norm, name, content, repo_url)
        if norm.endswith(".py"):
            return self._django(norm, name, content, repo_url)
        if norm.endswith(".php"):
            findings: list[Finding] = []
            if "/config/" in "/" + norm:
                findings += self._laravel(norm, name, content, repo_url)
            if "viewTelescope" in content or "viewHorizon" in content:
                findings += self._dashboard_gate(norm, content, repo_url)
            return findings
        return []

    def _dotenv(self, path: str, name: str, content: str, repo_url: str) -> list[Finding]:
        """A committed .env (not the .env.example template) holds this deployment's real values."""
        if _ENV_TEMPLATE_RE.search(name):
            return []
        findings: list[Finding] = []
        lines = content.splitlines()
        production = any(re.match(r"\s*APP_ENV\s*=\s*['\"]?production\b", ln) for ln in lines)
        dev = bool(_DEV_NAME_RE.search(name))  # .env.testing / .env.local: a development file, not the deployment's
        for lineno, line in enumerate(lines, 1):
            if _ENV_KEY_RE.match(line):
                findings.append(self._make(
                    path, lineno, "APP_KEY=<redacted>",
                    "CFG-LV-007",
                    "A committed .env holds a real APP_KEY: whoever can read the repository can forge or decrypt "
                    "sessions and encrypted values. Remove the file from version control, rotate the key",
                    Severity.LOW if dev else Severity.HIGH, repo_url, 798))
            elif _ENV_DEBUG_RE.match(line) and not dev:
                findings.append(self._make(
                    path, lineno, line, "CFG-LV-008",
                    "A committed .env turns APP_DEBUG on" + (" for a production environment" if production else ""),
                    Severity.HIGH if production else Severity.MEDIUM, repo_url, 489))
        return findings

    def _dashboard_gate(self, path: str, content: str, repo_url: str) -> list[Finding]:
        """viewTelescope / viewHorizon gates that always return true expose the dashboards to everyone."""
        findings: list[Finding] = []
        for m in _GATE_OPEN_RE.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            findings.append(self._make(
                path, lineno, m.group(0).splitlines()[0], "CFG-LV-006",
                f"The {m.group(1)} gate lets every visitor in, so the dashboard (requests, queries, job payloads) "
                "is public. Restrict it to named administrators", Severity.HIGH, repo_url, 284))
        return findings

    def _make(self, path: str, lineno: int, line: str, rule: str, desc: str, sev: Severity,
              repo_url: str, cwe: int) -> Finding:
        return Finding(
            vuln_type=_CFG, severity=sev, file_path=path, line_number=lineno, line_content=line.strip(),
            description=desc, rule_id=rule, repo_url=repo_url, cwe_id=cwe,
        )

    def _django(self, path: str, name: str, content: str, repo_url: str) -> list[Finding]:
        is_settings = name.startswith("settings") or "/settings/" in "/" + path
        if not is_settings or not _DJANGO_MARKERS.search(content):
            return []
        dev = bool(_DEV_NAME_RE.search(path))
        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), 1):
            for rule, rx, desc, sev, dev_sev, cwe in _DJANGO_RULES:
                if rx.search(line):
                    findings.append(self._make(path, lineno, line, rule, desc, dev_sev if dev else sev, repo_url, cwe))
        return findings

    def _laravel(self, path: str, name: str, content: str, repo_url: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        def scan(rx: re.Pattern, rule: str, desc: str, sev: Severity, cwe: int) -> None:
            for lineno, line in enumerate(lines, 1):
                if not line.lstrip().startswith(("//", "*", "#", "/*")) and rx.search(line):
                    findings.append(self._make(path, lineno, line, rule, desc, sev, repo_url, cwe))

        if name == "app.php":
            scan(_LV_DEBUG_RE, "CFG-LV-001",
                 "Debug mode is on by default (a missing APP_DEBUG turns it on): error pages show environment values and "
                 "stack traces. Use env('APP_DEBUG', false)", Severity.MEDIUM, 489)
            for lineno, line in enumerate(lines, 1):
                m = _LV_KEY_RE.search(line)
                if not m or line.lstrip().startswith(("//", "*", "#", "/*")):
                    continue
                usable = bool(_LV_VALID_KEY_RE.match(m.group(1)))
                findings.append(self._make(
                    path, lineno, line, "CFG-LV-002",
                    "APP_KEY has a hardcoded fallback value: anyone who has this source can forge or decrypt sessions and "
                    "encrypted cookies. Remove the fallback and generate the key per environment"
                    + ("" if usable else " [placeholder: not a valid Laravel key length, so the app will not start with it]"),
                    Severity.HIGH if usable else Severity.MEDIUM, repo_url, 798))
        elif name == "session.php":
            scan(_LV_HTTPONLY_RE, "CFG-LV-003",
                 "Session cookie http_only is false: page scripts can read the session cookie", Severity.MEDIUM, 1004)
            scan(_LV_SECURE_RE, "CFG-LV-004",
                 "Session cookie secure is false: the cookie is also sent over plain HTTP", Severity.LOW, 614)
            scan(_LV_SAMESITE_RE, "CFG-LV-009",
                 "Session cookie same_site is off (null or 'none'): the cookie is sent on cross-site requests, so the "
                 "browser no longer helps against CSRF. Use 'lax' or 'strict'", Severity.LOW, 1275)
        elif name == "cors.php":
            if _LV_CREDENTIALS_RE.search(content):
                scan(_LV_WILDCARD_ORIGIN_RE, "CFG-LV-005",
                     "CORS allows every origin together with supports_credentials = true: any site can make "
                     "credentialed cross-origin requests. List the allowed origins", Severity.HIGH, 346)
        return findings
