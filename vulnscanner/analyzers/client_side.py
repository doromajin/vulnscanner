"""
Client-side security analyzer for HTML and JavaScript/TypeScript files.

Rules
-----
CLIENT-CRED-001 : Sensitive credentials stored in localStorage / sessionStorage
CLIENT-SRI-001  : CDN <script>/<link> tag without Subresource Integrity (SRI)
CLIENT-SRI-002  : ESM import() from external CDN URL (no import-map integrity)
CLIENT-FETCH-001: fetch()/axios() URL derived from browser storage or URL params
CLIENT-MSG-001  : addEventListener('message') without event.origin validation
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# ── CLIENT-CRED-001 ────────────────────────────────────────────────────────────

# Match localStorage/sessionStorage.setItem() calls whose key name contains
# a credential-like term.  The key is inside the first string argument.
_CRED_KEY_RE = re.compile(
    r"""(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['"]"""
    r"""[^'"]*(?:api[_\-.]?key|api[_\-.]?token|access[_\-.]?token|"""
    r"""auth[_\-.]?token|bearer|password|passwd|secret|"""
    r"""private[_\-.]?key|credential|api[_\-.]?secret)[^'"]*['"]\s*,""",
    re.IGNORECASE,
)

# ── CLIENT-SRI-001 ─────────────────────────────────────────────────────────────

_CDN_TAG_START_RE = re.compile(r"<(?:script|link)\b", re.IGNORECASE)
_EXTERNAL_URL_RE = re.compile(r'(?:src|href)\s*=\s*["\']https?://', re.IGNORECASE)
_INTEGRITY_RE = re.compile(r'\bintegrity\s*=\s*["\']', re.IGNORECASE)

# ── CLIENT-SRI-002 ─────────────────────────────────────────────────────────────

# ESM static / dynamic import from an https:// URL
_ESM_CDN_RE = re.compile(
    r"""(?:^|[\s,{]|from\s+)import\s*(?:\(|[{*\w]).*?['"]https?://|"""
    r"""(?:^|\s)from\s+['"](https?://)""",
    re.IGNORECASE,
)
# Simpler fallback that also catches `from 'https://...'` patterns
_ESM_FROM_CDN_RE = re.compile(
    r"""(?:import\s+[^'";\n]*from\s+|import\s*\()\s*['"]https?://""",
    re.IGNORECASE,
)

# ── CLIENT-FETCH-001 ──────────────────────────────────────────────────────────

# Variables assigned directly from browser storage or URL params
_STORAGE_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*[^;\n]*"
    r"(?:localStorage|sessionStorage)\.getItem",
    re.IGNORECASE,
)
_URLPARAM_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*[^;\n]*"
    r"(?:location\.search|URLSearchParams|searchParams\.get\s*\(|"
    r"new\s+URL\s*\(\s*(?:location|window\.location))",
    re.IGNORECASE,
)
# Direct fetch/axios with localStorage in URL argument (same line)
_FETCH_DIRECT_RE = re.compile(
    r"(?:await\s+)?(?:fetch|axios)\s*\("
    r"[^)]*(?:localStorage|sessionStorage)\.getItem",
    re.IGNORECASE,
)
# fetch/axios call on this line (to check for tainted variable in template)
_FETCH_CALL_RE = re.compile(
    r"(?:await\s+)?(?:fetch|axios)\s*\(",
    re.IGNORECASE,
)

# ── CLIENT-MSG-001 ─────────────────────────────────────────────────────────────

_MSG_LISTENER_RE = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]\s*,""",
    re.IGNORECASE,
)
_ORIGIN_CHECK_RE = re.compile(
    r"(?:event|e|evt|msg)\s*\.\s*origin\b|\.source\s*[!=]=",
    re.IGNORECASE,
)


class ClientSideAnalyzer(BaseAnalyzer):
    """Detect browser-specific security patterns in HTML/JS/TS files."""

    supported_extensions = (".html", ".htm", ".js", ".ts", ".jsx", ".tsx")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        lines = content.splitlines()
        findings: list[Finding] = []
        findings.extend(self._check_cred_storage(file_path, lines, repo_url))
        findings.extend(self._check_sri_tags(file_path, lines, repo_url))
        findings.extend(self._check_esm_cdn(file_path, lines, repo_url))
        findings.extend(self._check_fetch_storage(file_path, content, lines, repo_url))
        findings.extend(self._check_postmessage(file_path, lines, repo_url))
        return findings

    # ── CLIENT-CRED-001 ────────────────────────────────────────────────────────

    def _check_cred_storage(
        self, file_path: str, lines: list[str], repo_url: str
    ) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines):
            if self._is_comment(line):
                continue
            if _CRED_KEY_RE.search(line):
                findings.append(Finding(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i + 1,
                    line_content=line.strip(),
                    description=(
                        "Sensitive credential stored in localStorage/sessionStorage - "
                        "accessible to any same-origin JavaScript; XSS can exfiltrate it"
                    ),
                    rule_id="CLIENT-CRED-001",
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, i + 1),
                ))
        return findings

    # ── CLIENT-SRI-001 ─────────────────────────────────────────────────────────

    def _check_sri_tags(
        self, file_path: str, lines: list[str], repo_url: str
    ) -> list[Finding]:
        findings = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if self._is_comment(line) or not _CDN_TAG_START_RE.search(line):
                i += 1
                continue

            # Collect the full tag (may span several lines)
            tag_text = line
            j = i + 1
            while j < min(i + 6, len(lines)) and ">" not in lines[j - 1]:
                tag_text += " " + lines[j]
                j += 1

            if _EXTERNAL_URL_RE.search(tag_text) and not _INTEGRITY_RE.search(tag_text):
                findings.append(Finding(
                    vuln_type=VulnType.VULNERABLE_DEPENDENCY,
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i + 1,
                    line_content=line.strip(),
                    description=(
                        "CDN resource loaded without Subresource Integrity (SRI) - "
                        "add integrity= and crossorigin= to guard against supply-chain injection"
                    ),
                    rule_id="CLIENT-SRI-001",
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, i + 1),
                ))
            i += 1
        return findings

    # ── CLIENT-SRI-002 ─────────────────────────────────────────────────────────

    def _check_esm_cdn(
        self, file_path: str, lines: list[str], repo_url: str
    ) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines):
            if self._is_comment(line):
                continue
            if _ESM_FROM_CDN_RE.search(line):
                findings.append(Finding(
                    vuln_type=VulnType.VULNERABLE_DEPENDENCY,
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i + 1,
                    line_content=line.strip(),
                    description=(
                        "ESM import from external CDN URL - no SRI integrity check possible "
                        "without an import map; consider vendoring or using import maps with "
                        "integrity hashes"
                    ),
                    rule_id="CLIENT-SRI-002",
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, i + 1),
                ))
        return findings

    # ── CLIENT-FETCH-001 ───────────────────────────────────────────────────────

    def _check_fetch_storage(
        self,
        file_path: str,
        content: str,
        lines: list[str],
        repo_url: str,
    ) -> list[Finding]:
        # Collect variables assigned from browser storage or URL params (1-hop)
        tainted: set[str] = set()
        for m in _STORAGE_ASSIGN_RE.finditer(content):
            tainted.add(m.group(1))
        for m in _URLPARAM_ASSIGN_RE.finditer(content):
            tainted.add(m.group(1))

        findings = []
        for i, line in enumerate(lines):
            if self._is_comment(line):
                continue

            # Direct: fetch(localStorage.getItem(...))
            if _FETCH_DIRECT_RE.search(line):
                findings.append(self._fetch_finding(file_path, lines, i, repo_url))
                continue

            # Indirect: fetch(`${storageVar}/path`) or fetch(storageVar)
            if tainted and _FETCH_CALL_RE.search(line):
                for var in tainted:
                    pat = rf"\$\{{{re.escape(var)}\}}|(?:fetch|axios)\s*\(\s*{re.escape(var)}\b"
                    if re.search(pat, line):
                        findings.append(self._fetch_finding(file_path, lines, i, repo_url))
                        break

        return findings

    def _fetch_finding(
        self, file_path: str, lines: list[str], i: int, repo_url: str
    ) -> Finding:
        return Finding(
            vuln_type=VulnType.SSRF,
            severity=Severity.MEDIUM,
            file_path=file_path,
            line_number=i + 1,
            line_content=lines[i].strip(),
            description=(
                "fetch()/axios() URL is derived from browser storage or URL parameters - "
                "if XSS is present an attacker can redirect API calls to an arbitrary server"
            ),
            rule_id="CLIENT-FETCH-001",
            repo_url=repo_url,
            snippet=self._extract_snippet(lines, i + 1),
        )

    # ── CLIENT-MSG-001 ─────────────────────────────────────────────────────────

    def _check_postmessage(
        self, file_path: str, lines: list[str], repo_url: str
    ) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines):
            if self._is_comment(line) or not _MSG_LISTENER_RE.search(line):
                continue

            # Inspect the handler body (up to 30 lines) for an origin check
            handler = "\n".join(lines[i: min(i + 30, len(lines))])
            if not _ORIGIN_CHECK_RE.search(handler):
                findings.append(Finding(
                    vuln_type=VulnType.XSS,
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i + 1,
                    line_content=line.strip(),
                    description=(
                        "postMessage listener without event.origin validation - "
                        "any window can send arbitrary messages; always check event.origin"
                    ),
                    rule_id="CLIENT-MSG-001",
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, i + 1),
                ))
        return findings
