import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.php_input import has_request_input
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
    (
        "CMD-011",
        re.compile(
            r'\b(?:exec|execSync|execFile|execFileSync|spawnSync)\s*\('
            r'[^)]*req\s*\.\s*(?:query|body|params)',
            re.IGNORECASE,
        ),
        "Node.js child_process with request-derived command — command injection allows arbitrary OS execution",
        Severity.CRITICAL, _CI,
    ),
    (
        "CMD-012",
        re.compile(
            r'\b(?:exec|execSync|execFile|execFileSync)\s*\('
            r'[^)]*`[^`]*\$\{req\s*\.',
            re.IGNORECASE,
        ),
        "Node.js child_process with template literal containing request data — command injection risk",
        Severity.CRITICAL, _CI,
    ),
]

_GUARD = re.compile(
    r'os\.system|os\.popen|subprocess\.|shell_exec|passthru|proc_open'
    r'|eval\s*\(|exec\s*\(|execSync\s*\(|execFile\s*\(|spawnSync\s*\('
    r'|Runtime\.getRuntime|IO\.popen|Open3\.|spawn\s*\(|system\s*\(',
    re.IGNORECASE,
)


class CommandInjectionAnalyzer(BaseAnalyzer):
    # .py is handled by PythonASTAnalyzer with higher precision
    supported_extensions = (".php", ".js", ".ts", ".java", ".rb", ".sh")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings = self._scan_lines(file_path, content, repo_url, _RULES, guard=_GUARD)
        findings = [f for f in findings if f.rule_id != "CMD-004" or _call_outside_string(f.line_content)]
        if file_path.endswith(".php") and findings and not has_request_input(content):
            for f in findings:
                if f.rule_id == "CMD-004":
                    # exec() in a file that never touches request data: still worth a look
                    # (unquoted interpolation), but not an exploitable-by-default CRITICAL.
                    f.severity = Severity.MEDIUM
                    f.taint_status = "unknown"
                    f.confidence = 0.3
                    f.description += " [low_reach: no request-derived input in this file]"
        return findings


_CMD004_RE = _RULES[3][1]



def _mask_quoted(line: str) -> str | None:
    """Blank out single-line quoted string interiors; None if a quote is left open."""
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and i + 1 < len(line):
                out.append("  ")
                i += 2
                continue
            if ch == quote:
                quote = ""
                out.append(ch)
            else:
                out.append(" ")
        else:
            if ch in ("'", '"'):
                quote = ch
            out.append(ch)
        i += 1
    return None if quote else "".join(out)


def _call_outside_string(line: str) -> bool:
    """CMD-004 must match real code, not an 'exec() is disabled' message or label."""
    masked = _mask_quoted(line)
    return True if masked is None else bool(_CMD004_RE.search(masked))
