"""Pattern-based analyzer that applies user-defined YAML rules."""
from __future__ import annotations

import re
import threading
from pathlib import Path

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.xss import (
    _BARE_IDENT_RE,
    _INTERP_RE,
    XSSAnalyzer,
    _concat_vars_are_i18n,
    _is_static_interpolation,
    _is_static_string_constant,
    _expr_is_inert,
    _scan_code,
    innerhtml_rhs_is_inert,
)
from vulnscanner.models import Finding
from vulnscanner.rules.loader import CustomRule

_INLINE_IGNORE = "vulnscanner: ignore"


def _innerhtml_is_i18n_concat(line: str, lines: list[str], idx: int) -> bool:
    """Same verdict as XSS-001: innerHTML built only from message-catalogue values."""
    m = re.search(r"\.innerHTML\s*=\s*([^\n]*)", line)
    return bool(m) and _concat_vars_are_i18n(m.group(1), lines, idx)


_joined_local = threading.local()
_XSS_ANALYZER = XSSAnalyzer()


def _joined(lines: list[str]) -> str:
    """"\\n".join(lines), built once per file: the same string object keeps downstream caches valid."""
    cached = getattr(_joined_local, "entry", None)
    if cached is None or cached[0] is not lines:
        cached = (lines, "\n".join(lines))
        _joined_local.entry = cached
    return cached[1]


_DOM_MARKUP_COPY_RE = re.compile(r"[\w$.\[\]'\"]+\.(?:innerHTML|outerHTML)")


def _innerhtml_is_static_text(line: str, lines: list[str], idx: int) -> bool:
    """`x.innerHTML = <rhs>` where rhs cannot carry data: a constant that is only ever a plain
    string literal, or a template literal whose `${}` are all such constants (or absent).  Unlike
    XSS-001 this stays strict about function-call results and other interpolations (JS-XSS-001 is
    the broader rule)."""
    m = re.search(r"\.innerHTML\s*=(?!=)\s*([^\n]*)", line)
    if not m:
        return False
    # The whole statement, which prettier may wrap onto the following lines
    text = "\n".join(lines[idx:idx + 40])
    start = re.search(r"\.innerHTML\s*=(?!=)\s*", text).end()
    end = _scan_code(text, start, ";")
    if 0 < end < len(text) and innerhtml_rhs_is_inert(text[start:end], _joined(lines)):
        return True
    rhs = m.group(1).strip().rstrip(";").strip()
    if _DOM_MARKUP_COPY_RE.fullmatch(rhs):
        return True     # `a.innerHTML = b.innerHTML`: markup already parsed into the DOM once
    if _BARE_IDENT_RE.match(rhs):
        return _is_static_string_constant(rhs, _joined(lines))
    if rhs.startswith("`"):
        block = _XSS_ANALYZER._collect_block(lines, idx)
        interpolations = _INTERP_RE.findall(block)
        if len(interpolations) != block.count("${"):
            return False  # nested braces: do not guess
        joined = _joined(lines)
        return all(_is_static_interpolation(e, joined) or _expr_is_inert(e, joined) for e in interpolations)
    return False


_LOCATION_ASSIGN_RE = re.compile(r"(?:window\.)?location(?:\.href)?\s*=(?!=)\s*([^\n]*)")
_URL_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")


def _location_has_fixed_prefix(line: str, lines: list[str], idx: int) -> bool:
    """`location = "<literal>" + x` where the literal pins the destination to the current origin.

    A prefix that is a relative path (`"orders/show/"`), a same-origin absolute path (`"/orders/"`),
    a query or a fragment cannot change the host whatever is appended.  `""`, `"/"`, `"//..."`,
    `"\\..."` and anything starting with a scheme (`"http:"`, `"javascript:"`) still can.  The
    right-hand side may continue on the following lines (prettier wraps `location =` this way)."""
    m = _LOCATION_ASSIGN_RE.search(line)
    if not m:
        return False
    rhs = m.group(1).strip()
    if not rhs:
        rhs = next((nxt.strip() for nxt in lines[idx + 1:idx + 3] if nxt.strip()), "")
    lit = re.match(r"(?:\"([^\"\\]*)\"|'([^'\\]*)')", rhs)
    if not lit:
        return False
    text = lit.group(1) if lit.group(1) is not None else lit.group(2)
    if not text or _URL_SCHEME_RE.match(text):
        return False
    if text[0] in "/\\":
        return len(text) > 1 and text[1] not in "/\\"
    return True


# Built-in rules whose regex alone cannot see that the matched value is safe.
# Each veto gets (line, all lines, 0-based line index); True drops the match.
_RULE_VETOES = {
    "JS-XSS-001": lambda line, lines, idx: (
        _innerhtml_is_i18n_concat(line, lines, idx) or _innerhtml_is_static_text(line, lines, idx)
    ),
    "JS-REDIR-001": _location_has_fixed_prefix,
}


class CustomRuleAnalyzer(BaseAnalyzer):
    """Applies a list of :class:`CustomRule` objects to source files.

    This analyzer is instantiated with a list of rules and re-used across
    all files in a scan. Rules are matched line-by-line using their compiled
    regex (converted from $X wildcard patterns or raw regex strings).
    """

    supported_extensions = ()  # handled dynamically per rule set
    runs_on_suppressed_paths = True  # a user rule may declare vuln_type MALWARE

    def __init__(self, rules: list[CustomRule]) -> None:
        self._rules = rules
        # Partition rules by extension for fast per-file lookup
        self._by_ext: dict[str, list[CustomRule]] = {}
        for rule in rules:
            for ext in rule.extensions:
                self._by_ext.setdefault(ext, []).append(rule)

    def supports(self, file_path: str) -> bool:
        ext = Path(file_path).suffix.lower()
        return ext in self._by_ext

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        ext = Path(file_path).suffix.lower()
        applicable = self._by_ext.get(ext)
        if not applicable:
            return []

        lines = content.splitlines()
        # For Python files, mask string literal interiors so that rule description
        # strings (e.g. "yaml.load()" or "exec(x)") don't match their own patterns.
        scan_lines = (
            self._mask_python_strings(content).splitlines()
            if file_path.endswith(".py")
            else lines
        )
        findings: list[Finding] = []
        seen: set[tuple] = set()
        # rule.id -> True when the file shows no evidence for a gated rule
        no_evidence = {
            r.id for r in applicable
            if r.evidence_regex and not re.search(r.evidence_regex, content)
        }

        for lineno, (line, scan_line) in enumerate(zip(lines, scan_lines), 1):
            stripped = line.strip()

            # Honour inline suppression annotation
            if _INLINE_IGNORE in line:
                continue

            # Skip pure comment lines
            if self._is_comment(stripped):
                continue

            for rule in applicable:
                if not rule.matches(scan_line):
                    continue
                key = (rule.id, lineno)
                if key in seen:
                    continue
                seen.add(key)
                veto = _RULE_VETOES.get(rule.id)
                if veto is not None and veto(line, lines, lineno - 1):
                    continue

                snippet = self._extract_snippet(lines, lineno)
                finding = Finding(
                    vuln_type=rule.vuln_type,
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=lineno,
                    line_content=stripped,
                    description=rule.message,
                    rule_id=rule.id,
                    repo_url=repo_url,
                    snippet=snippet,
                )
                if rule.cwe is not None:
                    finding.cwe_id = rule.cwe
                if rule.id in no_evidence and rule.no_evidence_severity is not None:
                    finding.severity = rule.no_evidence_severity
                    finding.taint_status = "unknown"
                    finding.confidence = 0.3
                    finding.description += " [low_reach: no browser-controlled input source in this file]"
                findings.append(finding)

        return findings
