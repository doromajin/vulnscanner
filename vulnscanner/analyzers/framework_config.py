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
    ("CFG-DJ-004", re.compile(r"^SESSION_COOKIE_HTTPONLY\s*=\s*False\b"),
     "SESSION_COOKIE_HTTPONLY = False lets page scripts read the session cookie (turns any XSS into session theft)",
     Severity.MEDIUM, Severity.LOW, 1004),
]

_LV_DEBUG_RE = re.compile(r"""['"]debug['"]\s*=>\s*(?:true\b|env\(\s*['"]APP_DEBUG['"]\s*,\s*true\s*\))""", re.IGNORECASE)
_LV_KEY_RE = re.compile(r"""['"]key['"]\s*=>\s*env\(\s*['"]APP_KEY['"]\s*,\s*['"]([^'"]+)['"]\s*\)""")
# A key Laravel accepts: 16 or 32 raw characters, or base64 of 16 / 32 bytes.
_LV_VALID_KEY_RE = re.compile(r"^(?:base64:[A-Za-z0-9+/]{22}={2}|base64:[A-Za-z0-9+/]{43}=|.{16}|.{32})$")
_LV_HTTPONLY_RE = re.compile(r"""['"]http_only['"]\s*=>\s*false\b""", re.IGNORECASE)
_LV_SECURE_RE = re.compile(r"""['"]secure['"]\s*=>\s*false\b""", re.IGNORECASE)
_LV_WILDCARD_ORIGIN_RE = re.compile(r"""['"]allowed_origins['"]\s*=>\s*\[\s*['"]\*['"]""")
_LV_CREDENTIALS_RE = re.compile(r"""['"]supports_credentials['"]\s*=>\s*true\b""", re.IGNORECASE)


class FrameworkConfigAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".php")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        norm = file_path.replace("\\", "/")
        name = norm.rsplit("/", 1)[-1]
        if norm.endswith(".py"):
            return self._django(norm, name, content, repo_url)
        if norm.endswith(".php") and "/config/" in "/" + norm:
            return self._laravel(norm, name, content, repo_url)
        return []

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
        elif name == "cors.php":
            if _LV_CREDENTIALS_RE.search(content):
                scan(_LV_WILDCARD_ORIGIN_RE, "CFG-LV-005",
                     "CORS allows every origin together with supports_credentials = true: any site can make "
                     "credentialed cross-origin requests. List the allowed origins", Severity.HIGH, 346)
        return findings
