import io
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
