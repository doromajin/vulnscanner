"""Go-specific vulnerability analyzer.

Two detection layers:
  1. Regex rules (_RULES) — fast inline pattern matching
  2. Taint-lite — 2-pass variable-flow tracking (source -> sink across lines)

All rules target .go files only.
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_SI   = VulnType.SQL_INJECTION
_CI   = VulnType.COMMAND_INJECTION
_PT   = VulnType.PATH_TRAVERSAL
_SSRF = VulnType.SSRF
_SSTI = VulnType.SSTI
_OR   = VulnType.OPEN_REDIRECT

# ── Layer 1: regex rules (inline patterns) ─────────────────────────────────────

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
    r'|\.Query\s*\(|\.Exec\s*\(|\.QueryRow\s*\(|template\.|http\.Redirect',
    re.IGNORECASE,
)

# ── Layer 2: taint-lite (variable-flow) ────────────────────────────────────────

# Matches: varName := <request source expression>
_SOURCE_RE = re.compile(
    r'(?P<var>[A-Za-z_]\w*)\s*:=\s*'
    r'(?:'
    r'r\.FormValue\s*\('
    r'|r\.PostFormValue\s*\('
    r'|r\.PathValue\s*\('
    r'|r\.URL\.Query\(\)\.Get\s*\('
    r'|r\.Header\.Get\s*\('
    r'|r\.URL\.Path\b'
    r'|r\.URL\.RawQuery\b'
    r'|c\.Query\s*\('
    r'|c\.Param\s*\('
    r'|c\.PostForm\s*\('
    r'|c\.GetHeader\s*\('
    r'|ctx\.Query\s*\('
    r'|ctx\.Param\s*\('
    r'|ctx\.GetHeader\s*\('
    r'|chi\.URLParam\s*\('
    r'|mux\.Vars\s*\('
    r')',
)

# (sink_re, rule_id, description, severity, vuln_type)
_TAINT_SINKS: list[tuple] = [
    (
        re.compile(r'\bhttp\.Redirect\s*\('),
        "GO-REDIR-001",
        "Go http.Redirect with user-controlled URL variable — open redirect",
        Severity.HIGH, _OR,
    ),
    (
        re.compile(r'\bexec\.Command\s*\('),
        "GO-CMD-002",
        "Go exec.Command with user-controlled variable — command injection",
        Severity.CRITICAL, _CI,
    ),
    (
        re.compile(r'\bhttp\.(?:Get|Post|Head|NewRequest)\s*\('),
        "GO-SSRF-002",
        "Go HTTP client with user-controlled URL variable — SSRF",
        Severity.HIGH, _SSRF,
    ),
    (
        re.compile(r'\b(?:os\.Open|ioutil\.ReadFile|os\.ReadFile|os\.Create)\s*\('),
        "GO-PATH-002",
        "Go file access with user-controlled path variable — path traversal",
        Severity.HIGH, _PT,
    ),
    (
        re.compile(r'\b(?:db|tx|stmt)\.(?:Query|Exec|QueryRow|QueryContext|ExecContext)\s*\('),
        "GO-SQL-002",
        "Go database query with user-controlled variable — SQL injection",
        Severity.HIGH, _SI,
    ),
]


class GoAnalyzer(BaseAnalyzer):
    supported_extensions = (".go",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings = self._scan_lines(file_path, content, repo_url, _RULES, guard=_GUARD)
        findings.extend(self._taint_lite(file_path, content, repo_url))
        return findings

    def _taint_lite(self, file_path: str, content: str, repo_url: str) -> list[Finding]:
        lines = content.splitlines()

        # Pass 1: collect tainted variables (var := <request source>)
        tainted: dict[str, int] = {}  # var_name -> line number
        for i, line in enumerate(lines, 1):
            m = _SOURCE_RE.search(line)
            if m:
                var = m.group("var")
                if var not in ("_", "err"):
                    tainted[var] = i

        if not tainted:
            return []

        # Build combined word-boundary pattern for all tainted variable names
        var_pattern = re.compile(
            r'\b(?:' + "|".join(re.escape(v) for v in tainted) + r')\b'
        )

        # Pass 2: check sink lines for tainted variable usage
        findings: list[Finding] = []
        seen: set[tuple] = set()  # (line_number, rule_id) dedup

        for i, line in enumerate(lines, 1):
            if not var_pattern.search(line):
                continue
            # Don't re-flag the assignment line itself
            matched_var = var_pattern.search(line).group()
            if tainted.get(matched_var) == i:
                continue
            for sink_re, rule_id, desc, severity, vuln_type in _TAINT_SINKS:
                if not sink_re.search(line):
                    continue
                key = (i, rule_id)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.strip(),
                    description=desc,
                    rule_id=rule_id,
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, i),
                ))
        return findings
