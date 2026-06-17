import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RULES = [
    (
        "PATH-001",
        # Python/Ruby open() with a request/param variable — language-specific
        r'(?<![\w.])open\s*\(\s*(?:request|req|args|params|data|input)',
        "open() with potentially user-controlled path",
        Severity.HIGH,
        (".py", ".rb"),
    ),
    (
        "PATH-002",
        # open() with string concatenation — Python/PHP/Ruby only;
        # JS 'open()' means XHR or window.open, so we exclude .js/.ts
        r'(?<![\w.])open\s*\(.*\+|(?<![\w.])open\s*\(.*f["\'].*\{',
        "open() with string concatenation — path may be user-controlled",
        Severity.MEDIUM,
        (".py", ".rb", ".php"),
    ),
    (
        "PATH-003",
        r'(?:send_file|send_from_directory|serve_file)\s*\(',
        "File-serving function — verify path is within expected root",
        Severity.MEDIUM,
        None,  # all supported extensions
    ),
    (
        "PATH-004",
        # PHP file functions with user input
        r'\b(?:file_get_contents|include|require|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST)',
        "PHP file function called with direct user input",
        Severity.CRITICAL,
        (".php",),
    ),
    (
        "PATH-005",
        # Literal path traversal sequence — report as INFO, skip test files
        r'\.\./|\.\.\\\\',
        "Literal path traversal sequence in source code",
        Severity.INFO,
        None,
    ),
]

# Path fragments that indicate test/fixture code — lower value, skip PATH-005 there
_TEST_PATH_MARKERS = ("/test/", "/tests/", "/spec/", "/it/", "/fixture", "/mock")


class PathTraversalAnalyzer(BaseAnalyzer):
    # .py is handled by PythonASTAnalyzer with higher precision
    supported_extensions = (".php", ".js", ".ts", ".java", ".rb")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fp_lower = file_path.replace("\\", "/").lower()

        for rule_id, pattern, description, severity, lang_filter in _RULES:
            # Respect per-rule language filter
            if lang_filter and not any(file_path.endswith(ext) for ext in lang_filter):
                continue

            # PATH-005 in test files is almost always intentional — skip
            if rule_id == "PATH-005" and any(m in fp_lower for m in _TEST_PATH_MARKERS):
                continue

            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            vuln_type=VulnType.PATH_TRAVERSAL,
                            severity=severity,
                            file_path=file_path,
                            line_number=lineno,
                            line_content=line.strip(),
                            description=description,
                            rule_id=rule_id,
                            repo_url=repo_url,
                            snippet=self._extract_snippet(lines, lineno),
                        )
                    )

        return findings
