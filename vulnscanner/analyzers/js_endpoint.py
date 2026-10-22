"""
JavaScript / TypeScript API endpoint extractor.

Extracts HTTP call URLs and server-side route definitions from JS/TS source.
Useful for bug bounty reconnaissance: surfaces undocumented or sensitive
endpoints that are not listed in public API documentation.

Rule IDs:
  JSEP-001  API endpoint or route definition (INFO)
  JSEP-002  Sensitive endpoint (admin / internal / debug / …) (MEDIUM)
  JSEP-003  Credential or token embedded directly in URL (HIGH)
"""
from __future__ import annotations

import os
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_SUPPORTED = frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue"})

# ── HTTP client call patterns (each captures the URL in group 1) ──────────────

_PATTERNS: list[re.Pattern[str]] = [
    # fetch('/path')
    re.compile(r'\bfetch\s*\(\s*["\']([^"\'#\s]{3,})["\']', re.IGNORECASE),
    # axios.get('/path')  axios.post('/path') …
    re.compile(
        r'\baxios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*["\']([^"\'#\s]{3,})["\']',
        re.IGNORECASE,
    ),
    # axios({url: '/path'})
    re.compile(
        r'\baxios\s*\(\s*\{[^}]{0,300}["\']?url["\']?\s*:\s*["\']([^"\'#\s]{3,})["\']',
        re.IGNORECASE | re.DOTALL,
    ),
    # $.get('/path')  $.post('/path')  $.getJSON('/path')
    re.compile(
        r'\$\s*\.\s*(?:get|post|getJSON|getScript|load)\s*\(\s*["\']([^"\'#\s]{3,})["\']',
        re.IGNORECASE,
    ),
    # $.ajax({url: '/path'})
    re.compile(
        r'\$\s*\.ajax\s*\([^)]{0,300}url\s*:\s*["\']([^"\'#\s]{3,})["\']',
        re.IGNORECASE | re.DOTALL,
    ),
    # xhr.open('GET', '/path')
    re.compile(
        r'\.open\s*\(\s*["\'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["\'],\s*["\']([^"\'#\s]{3,})["\']',
        re.IGNORECASE,
    ),
    # Express / Fastify routes:  app.get('/path', ...)  router.post('/path', ...)
    re.compile(
        r'\b(?:app|router|server|fastify|hapi)\s*\.\s*'
        r'(?:get|post|put|patch|delete|all|head|options|use)\s*\(\s*["\']([^"\'?\s]{2,})["\']',
        re.IGNORECASE,
    ),
    # URL constant: const API_URL = '/api/v1'
    re.compile(
        r'(?:const|let|var)\s+\w*(?:url|endpoint|path|route|api)\w*\s*=\s*'
        r'["\'](\/?(?:api|v\d+|admin|internal)[^"\'#\s]{2,})["\']',
        re.IGNORECASE,
    ),
    # Object field: baseURL: '/api'  endpoint: '/admin/api'
    re.compile(
        r'(?:baseURL|baseUrl|base_url|endpoint|apiPath|apiUrl)\s*:\s*["\']([^"\'#\s]{3,})["\']',
        re.IGNORECASE,
    ),
]

# Sensitive path keywords → JSEP-002 (MEDIUM)
_SENSITIVE_RE = re.compile(
    r'(?:^|/)'
    r'(?:admin|administrator|internal|debug|config|configuration|'
    r'secret|private|hidden|staging|backup|dump|management|'
    r'console|panel|dashboard|superuser|system|setup|install|'
    r'swagger|openapi|graphql|api-docs|wp-admin|phpmyadmin|'
    r'actuator|\.env|health|metrics)'
    r'(?:/|$|\?|\.)',
    re.IGNORECASE,
)

# Credential embedded in URL: https://user:pass@host → JSEP-003 (HIGH)
_CRED_URL_RE = re.compile(
    r'["\']https?://[A-Za-z0-9._%-]+:[A-Za-z0-9._@!%$&*()\[\]^~`=+,;]{3,}@',
    re.IGNORECASE,
)

# Skip well-known CDN/public domains and non-HTTP schemes
_SKIP_RE = re.compile(
    r'^(?:'
    r'https?://(?:[a-z0-9-]+\.)*(?:cdn\.|unpkg\.com|jsdelivr\.net|cloudflare\.com|'
    r'googleapis\.com|gstatic\.com|fontawesome\.com|bootstrapcdn\.com|'
    r'jquery\.com|angularjs\.org|reactjs\.org|vuejs\.org)'
    r'|//(?:cdn|unpkg|jsdelivr)'
    r'|(?:mailto|tel|data|javascript):'
    r'|#'
    r')',
    re.IGNORECASE,
)

# Fast file-level pre-filter
_GUARD_RE = re.compile(
    r'fetch\s*\(|axios|\bXMLHttpRequest\b|\$\s*\.\s*(?:get|post|ajax|getJSON)|'
    r'\.open\s*\(|(?:app|router|fastify)\s*\.\s*(?:get|post|put|patch|delete)|'
    r'baseURL|/api/',
    re.IGNORECASE,
)


class JSEndpointAnalyzer(BaseAnalyzer):
    """Extract API endpoints from JS/TS files for bug bounty reconnaissance."""

    def supports(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path.replace("\\", "/"))[-1].lower()
        return ext in _SUPPORTED

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        lines = content.splitlines()
        findings: list[Finding] = []
        seen_endpoints: set[str] = set()

        # JSEP-003: credential in URL — checked before the guard (can appear anywhere)
        for lineno, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            if _CRED_URL_RE.search(line):
                findings.append(Finding(
                    vuln_type=VulnType.EXPOSED_ENDPOINT,
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=lineno,
                    line_content=line.strip(),
                    description=(
                        "Credential or secret token embedded directly in a URL — "
                        "rotate the credential and use environment variables instead"
                    ),
                    rule_id="JSEP-003",
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, lineno),
                ))

        # JSEP-001 / JSEP-002: endpoint extraction (guarded to avoid scanning every JS file)
        if not _GUARD_RE.search(content):
            return findings

        for pattern in _PATTERNS:
            for m in pattern.finditer(content):
                url = m.group(1).strip()
                if not url or url in seen_endpoints:
                    continue
                if _SKIP_RE.match(url):
                    continue
                # Only report paths that look like real endpoints
                if not _looks_like_endpoint(url):
                    continue
                seen_endpoints.add(url)

                lineno = content[: m.start()].count("\n") + 1
                line_content = lines[lineno - 1].strip() if lineno <= len(lines) else url

                if _SENSITIVE_RE.search(url):
                    findings.append(Finding(
                        vuln_type=VulnType.EXPOSED_ENDPOINT,
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line_content,
                        description=(
                            f"Sensitive endpoint discovered: {url!r} — "
                            "verify authentication and authorization controls"
                        ),
                        rule_id="JSEP-002",
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))
                else:
                    findings.append(Finding(
                        vuln_type=VulnType.EXPOSED_ENDPOINT,
                        severity=Severity.INFO,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line_content,
                        description=f"API endpoint reference: {url!r}",
                        rule_id="JSEP-001",
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))

        return findings


def _looks_like_endpoint(url: str) -> bool:
    """Return True if the URL looks like a real API endpoint worth reporting."""
    # Must start with / or http(s):// to be a path-like reference
    if not (url.startswith("/") or url.startswith("http")):
        return False
    # Skip single-segment paths like '/' or '/foo' with no structure
    # (unless they match sensitive keywords handled separately)
    if url.count("/") < 2 and not _SENSITIVE_RE.search(url):
        return False
    # Skip file-extension assets (images, fonts, CSS, JS bundles)
    if re.search(r'\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|css|min\.js|bundle\.js)$', url, re.IGNORECASE):
        return False
    return True
