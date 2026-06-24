import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RULES = [
    (
        "CMD-001",
        r'(?<![\w.])os\.system\s*\(',
        "os.system() executes a shell command - avoid with user input",
        Severity.HIGH,
    ),
    (
        "CMD-002",
        # subprocess with shell=True
        r'subprocess\.\w+\s*\(.*shell\s*=\s*True',
        "subprocess called with shell=True - susceptible to injection",
        Severity.HIGH,
    ),
    (
        "CMD-003",
        r'(?<![\w.])os\.popen\s*\(',
        "os.popen() - prefer subprocess with a list of args",
        Severity.HIGH,
    ),
    (
        "CMD-004",
        # Standalone eval()/exec() - NOT preceded by a dot (excludes JS .exec(), Java .exec())
        # and NOT called on a literal string argument
        r'(?<![\w.])eval\s*\(\s*(?![\'\"]\s*[\'\"]\s*\))|'
        r'(?<![\w.])exec\s*\(\s*(?![\'\"#])',
        "eval()/exec() with non-literal argument",
        Severity.CRITICAL,
    ),
    (
        "CMD-005",
        # PHP shell execution functions
        r'\b(?:shell_exec|passthru|proc_open|popen|system)\s*\(\s*\$',
        "PHP shell execution function with variable argument",
        Severity.CRITICAL,
    ),
    (
        "CMD-006",
        # PHP backtick operator
        r'`\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        "PHP backtick operator with user-supplied input",
        Severity.CRITICAL,
    ),
    (
        "CMD-007",
        r'Runtime\.getRuntime\(\)\.exec\s*\(',
        "Java Runtime.exec() - verify arguments are not user-controlled",
        Severity.HIGH,
    ),
]


class CommandInjectionAnalyzer(BaseAnalyzer):
    # .py is handled by PythonASTAnalyzer with higher precision
    supported_extensions = (".php", ".js", ".ts", ".java", ".rb", ".sh")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule_id, pattern, description, severity in _RULES:
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            vuln_type=VulnType.COMMAND_INJECTION,
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
