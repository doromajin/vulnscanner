import io
import re
import tokenize
from abc import ABC, abstractmethod
from dataclasses import dataclass

from vulnscanner.models import Finding


@dataclass
class AnalyzerRule:
    rule_id: str
    pattern: str  # regex pattern
    description: str
    severity: str


class BaseAnalyzer(ABC):
    """Base class for all vulnerability analyzers."""

    # Subclasses declare which file extensions they handle
    supported_extensions: tuple[str, ...] = ()

    def supports(self, file_path: str) -> bool:
        return file_path.endswith(self.supported_extensions)

    @abstractmethod
    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        """Analyze file content and return a list of findings."""
        ...

    def _scan_lines(
        self,
        file_path: str,
        content: str,
        repo_url: str,
        rules: list[tuple],
        *,
        guard: re.Pattern | None = None,
    ) -> list[Finding]:
        """Single-pass optimized line scanner.

        *rules* is a list of ``(rule_id, compiled_re, description, severity, vuln_type)``
        tuples where ``compiled_re`` is a pre-compiled :class:`re.Pattern`.
        An optional 6th element may be a ``re.Pattern`` that, when it matches the
        same line, suppresses the finding (useful for excluding method definitions
        or other false-positive patterns that cannot be expressed as a lookbehind).

        The outer loop iterates lines once; every rule is tested per line so
        ``_is_comment`` is called exactly once per line (not once per rule per line)
        and the compiled-pattern cache-lookup overhead is paid once per match, not
        per rule×line.

        If *guard* is provided and does not match *content*, returns [] immediately —
        fast path for files that contain no keyword relevant to any rule in the set.
        """
        if guard is not None and not guard.search(content):
            return []
        lines = content.splitlines()
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            stripped = line.strip()
            for rule_tuple in rules:
                rule_id, pattern_re, description, severity, vuln_type = rule_tuple[:5]
                skip_re: re.Pattern | None = rule_tuple[5] if len(rule_tuple) > 5 else None
                if pattern_re.search(line):
                    if skip_re and skip_re.search(line):
                        continue
                    findings.append(Finding(
                        vuln_type=vuln_type,
                        severity=severity,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=stripped,
                        description=description,
                        rule_id=rule_id,
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))
        return findings

    def _extract_snippet(self, lines: list[str], line_number: int, context: int = 2) -> str:
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        numbered = [f"{i + start + 1:4d} | {lines[i + start]}" for i in range(end - start)]
        return "\n".join(numbered)

    @staticmethod
    def _is_comment(line: str) -> bool:
        """Return True if the line is purely a comment (not executable code)."""
        s = line.strip()
        return (
            s.startswith("//")
            or s.startswith("*")
            or s.startswith("/*")
            or s.startswith("#")
            or s.startswith("<!--")
            or s.startswith("--")   # SQL comment
        )

    @staticmethod
    def _mask_python_strings(content: str) -> str:
        """Replace Python string literal interiors with null bytes.

        Line count and column offsets are preserved (newlines kept intact),
        so line_number values remain correct after masking.  Used to prevent
        rule description strings from matching their own regex patterns.
        """
        result = list(content)
        src_lines = content.splitlines(keepends=True)
        # cumulative character offsets; offsets[n] = start of 1-indexed line n
        offsets: list[int] = [0]
        for ln in src_lines:
            offsets.append(offsets[-1] + len(ln))

        try:
            for tok in tokenize.generate_tokens(io.StringIO(content).readline):
                if tok.type != tokenize.STRING:
                    continue
                s_row, s_col = tok.start  # 1-indexed row, 0-indexed col
                e_row, e_col = tok.end
                s_abs = offsets[s_row - 1] + s_col
                e_abs = offsets[e_row - 1] + e_col
                # Strip string prefix chars (r, b, f, u, rb, …)
                raw = tok.string
                prefix_len = len(raw) - len(raw.lstrip("brBRuUfF"))
                inner = raw[prefix_len:]
                q_width = 3 if inner[:3] in ('"""', "'''") else 1
                # Mask interior, preserving newlines so line numbers stay valid
                for i in range(s_abs + prefix_len + q_width, e_abs - q_width):
                    if result[i] not in ('\n', '\r'):
                        result[i] = '\x00'
        except tokenize.TokenError:
            pass
        return ''.join(result)
