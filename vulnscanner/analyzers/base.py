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
