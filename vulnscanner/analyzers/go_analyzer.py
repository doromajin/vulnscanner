"""Go-specific vulnerability analyzer.

Covers Go standard library and popular framework patterns.
All rules target .go files only.
"""
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_SI   = VulnType.SQL_INJECTION
_CI   = VulnType.COMMAND_INJECTION
_PT   = VulnType.PATH_TRAVERSAL
_SSRF = VulnType.SSRF
_SSTI = VulnType.SSTI

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "GO-SQL-001",
        re.compile(
            r'\.(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|fmt\.Errorf|[\w]+\s*\+)',
            re.IGNORECASE,
        ),
        "Go database/sql Query/Exec with fmt.Sprintf or concatenation — SQL injection risk",
        Severity.HIGH, _SI,
    ),
    (
        "GO-CMD-001",
        re.compile(
            r'exec\.Command\s*\(\s*(?:r\.|req\.|request\.|c\.Param|c\.Query|c\.PostForm'
            r'|r\.FormValue|r\.URL\.Query)',
            re.IGNORECASE,
        ),
        "Go exec.Command with request parameter — command injection risk",
        Severity.CRITICAL, _CI,
    ),
    (
        "GO-SSRF-001",
        re.compile(
            r'http\.(?:Get|Post|Head|Do)\s*\(\s*(?:r\.|req\.|request\.|c\.Param|c\.Query'
            r'|c\.PostForm|r\.FormValue|r\.URL\.Query|fmt\.Sprintf)',
            re.IGNORECASE,
        ),
        "Go http.Get/Post with user-controlled URL — SSRF risk",
        Severity.HIGH, _SSRF,
    ),
    (
        "GO-PATH-001",
        re.compile(
            r'(?:os\.Open|ioutil\.ReadFile|os\.ReadFile|filepath\.Join)\s*\('
            r'[^)]*(?:r\.|req\.|request\.|c\.Param|c\.Query|r\.FormValue)',
            re.IGNORECASE,
        ),
        "Go file access with request parameter — path traversal risk",
        Severity.HIGH, _PT,
    ),
    (
        "GO-SSTI-001",
        re.compile(
            r'template\.(?:HTML|JS|URL|CSS)?\(.*(?:r\.|req\.|request\.|c\.Param|c\.Query'
            r'|r\.FormValue)',
            re.IGNORECASE,
        ),
        "Go html/template with unescaped user input — XSS/SSTI risk",
        Severity.HIGH, _SSTI,
    ),
]

_GUARD = re.compile(
    r'exec\.Command|http\.Get|http\.Post|os\.Open|ioutil\.ReadFile|os\.ReadFile'
    r'|\.Query\s*\(|\.Exec\s*\(|\.QueryRow\s*\(|template\.',
    re.IGNORECASE,
)


class GoAnalyzer(BaseAnalyzer):
    supported_extensions = (".go",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        return self._scan_lines(file_path, content, repo_url, _RULES, guard=_GUARD)
