import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_CI = VulnType.COMMAND_INJECTION

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "CMD-001",
        re.compile(r'(?<![\w.])os\.system\s*\(', re.IGNORECASE),
        "os.system() executes a shell command - avoid with user input",
        Severity.HIGH, _CI,
    ),
    (
        "CMD-002",
        re.compile(r'subprocess\.\w+\s*\(.*shell\s*=\s*True', re.IGNORECASE),
        "subprocess called with shell=True - susceptible to injection",
        Severity.HIGH, _CI,
    ),
    (
        "CMD-003",
        re.compile(r'(?<![\w.])os\.popen\s*\(', re.IGNORECASE),
        "os.popen() - prefer subprocess with a list of args",
        Severity.HIGH, _CI,
    ),
    (
        "CMD-004",
        re.compile(
            # Exclude ->eval()/::eval() and string-prefixed 'eval(
            r"(?<![\w.>:'\"])eval\s*\(\s*(?![\'\"]\s*[\'\"]\s*\))"
            # Exclude ->exec()/::exec() and string-prefixed 'exec(
            r"|(?<![\w.>:'\"])exec\s*\(\s*(?![\'\"#])",
            re.IGNORECASE,
        ),
        "eval()/exec() with non-literal argument",
        Severity.CRITICAL, _CI,
        # Skip method definitions (`function exec(`) and class instantiations (`new Exec(`)
        re.compile(r'\bfunction\s+(?:exec|eval)\s*\(|\bnew\s+\w*(?:exec|eval)\w*\s*\(', re.IGNORECASE),
    ),
    (
        "CMD-005",
        re.compile(r'\b(?:shell_exec|passthru|proc_open|popen|system)\s*\(\s*\$', re.IGNORECASE),
        "PHP shell execution function with variable argument",
        Severity.CRITICAL, _CI,
    ),
    (
        "CMD-006",
        re.compile(r'`\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)', re.IGNORECASE),
        "PHP backtick operator with user-supplied input",
        Severity.CRITICAL, _CI,
    ),
    (
        "CMD-007",
        re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(', re.IGNORECASE),
        "Java Runtime.exec() - verify arguments are not user-controlled",
        Severity.HIGH, _CI,
    ),
    (
        "CMD-009",
        re.compile(
            r'\b(?:system|exec|spawn|IO\.popen|Open3\.popen3?|Open3\.capture[23]?|Kernel\.system)\s*\('
            r'[^)]*params\s*\[',
            re.IGNORECASE,
        ),
        "Ruby shell execution with user-controlled params[] argument — command injection risk",
        Severity.CRITICAL, _CI,
    ),
    (
        "CMD-010",
        re.compile(r'`[^`]*#\{[^`]*params\s*\[', re.IGNORECASE),
        "Ruby backtick shell execution with params[] interpolation — command injection risk",
        Severity.CRITICAL, _CI,
    ),
]

_GUARD = re.compile(
    r'os\.system|os\.popen|subprocess\.|shell_exec|passthru|proc_open'
    r'|eval\s*\(|exec\s*\(|Runtime\.getRuntime'
    r'|IO\.popen|Open3\.|spawn\s*\(|system\s*\(',
    re.IGNORECASE,
)


class CommandInjectionAnalyzer(BaseAnalyzer):
    # .py is handled by PythonASTAnalyzer with higher precision
    supported_extensions = (".php", ".js", ".ts", ".java", ".rb", ".sh")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        return self._scan_lines(file_path, content, repo_url, _RULES, guard=_GUARD)
