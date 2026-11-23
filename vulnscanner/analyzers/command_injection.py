import re
import threading

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
            # Exclude ->eval()/::eval(), string-prefixed 'eval( and an empty `eval()`: a call with
            # no argument executes nothing, so it is prose ("eval() must be enabled"), not code.
            r"(?<![\w.>:'\"])eval\s*\(\s*(?![\'\"]\s*[\'\"]\s*\)|\))"
            # Exclude ->exec()/::exec(), string-prefixed 'exec( and an empty `exec()`
            r"|(?<![\w.>:'\"])exec\s*\(\s*(?![\'\"#)])",
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
        if file_path.endswith((".js", ".ts")):
            lines = content.splitlines()
            findings = [f for f in findings
                        if f.rule_id != "CMD-004" or not _exec_param_only_gets_literals(lines, f.line_number)]
        if file_path.endswith(".php"):
            findings = [f for f in findings
                        if f.rule_id not in ("CMD-004", "CMD-005")
                        or not _php_cmd_arg_is_constant(f.line_content, content)]
        if file_path.endswith(".php") and findings and not has_request_input(content):
            for f in findings:
                if f.rule_id in ("CMD-004", "CMD-005"):
                    # exec()/shell_exec($x) in a file that never touches request data: still worth a look
                    # (unquoted interpolation), but not an exploitable-by-default CRITICAL.
                    f.severity = Severity.MEDIUM
                    f.taint_status = "unknown"
                    f.confidence = 0.3
                    f.description += " [low_reach: no request-derived input in this file]"
        return findings


_CMD004_RE = _RULES[3][1]


# ── PHP: a variable that only ever holds string literals is a constant ────────
# `$cmd = $mode === 'a' ? 'npm run prod' : 'npm run dev'; passthru($cmd);` runs one of two fixed
# commands.  The proof is deliberately narrow: every write to the variable in the file is a plain
# `=` of a literal (or a ternary / `.` chain of literals), and nothing in the file can write to it
# another way (by reference, as a parameter, a loop variable, extract(), `$$`).

_PHP_SQ = r"'(?:[^'\\]|\\.)*'"
_PHP_DQ = r'"(?:[^"\\$]|\\.)*"'          # no `$`: neither `$x` nor `{$x}` interpolation
_PHP_LITERAL_RE = re.compile(rf"(?:{_PHP_SQ}|{_PHP_DQ})")
_PHP_FIRST_ARG_RE = re.compile(
    r"(?<![\w.>:'\"])(?:shell_exec|passthru|proc_open|popen|system|exec|eval)\s*\(\s*\$([A-Za-z_]\w*)\s*[,)]",
    re.IGNORECASE,
)
_PHP_MAX_RHS = 600


def _php_scan(s: str, i: int, stops: str) -> int:
    """Index of the first char of *stops* at bracket depth 0 outside quotes; len(s) if none, -1 if odd."""
    depth, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in "'\"":
            j = i + 1
            while j < n and s[j] != c:
                j += 2 if s[j] == "\\" else 1
            if j >= n:
                return -1
            i = j + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i if c in stops else -1
            depth -= 1
        elif depth == 0 and c in stops:
            return i
        i += 1
    return n


def _php_split(expr: str, ch: str) -> list[str]:
    parts, start, i = [], 0, 0
    while True:
        i = _php_scan(expr, i, ch)
        if i < 0:
            return [expr]
        if i >= len(expr):
            parts.append(expr[start:])
            return parts
        parts.append(expr[start:i])
        start = i = i + 1


def _php_expr_is_literal(expr: str, depth: int = 0) -> bool:
    expr = expr.strip()
    if not expr or depth > 4 or len(expr) > _PHP_MAX_RHS:
        return False
    q = _php_scan(expr, 0, "?")
    while 0 <= q < len(expr) and (expr[q + 1:q + 3] == "->" or expr[q + 1:q + 2] == "?" or expr[q - 1:q] == "?"):
        q = _php_scan(expr, q + 1, "?")      # `?->` (nullsafe) and `??` are not a ternary
    if 0 <= q < len(expr):
        c = _php_scan(expr, q + 1, ":")
        if 0 <= c < len(expr):
            return (_php_expr_is_literal(expr[q + 1:c], depth + 1)
                    and _php_expr_is_literal(expr[c + 1:], depth + 1))
        return False
    if expr.startswith("(") and expr.endswith(")") and _php_scan(expr, 1, ")") == len(expr) - 1:
        return _php_expr_is_literal(expr[1:-1], depth + 1)
    terms = _php_split(expr, ".")
    return all(_PHP_LITERAL_RE.fullmatch(t.strip()) for t in terms)


_PHP_VAR = r"\$([A-Za-z_]\w*)"
_PHP_ASSIGN_RE = re.compile(r"(?<![\w$>:])" + _PHP_VAR + r"\s*((?:[-+*/.%&|^]|\?\?)?)=(?![=>])\s*")
# One pattern per way a variable can be written without a plain `$v = <expr>;`.  Group 1 holds the
# variable name, or a text span whose `$names` are all affected.
_PHP_WRITE_RES = (
    re.compile(r"&\s*" + _PHP_VAR + r"\b"),                              # by reference
    re.compile(r"\$\$" + r"([A-Za-z_]\w*)"),                              # variable variables
    re.compile(_PHP_VAR + r"\s*\["),                                       # element write
    re.compile(r"\b(?:global|static)\b([^;]*)"),
    re.compile(r"\bas\s+((?:[^)]*=>\s*)?&?\s*\$\w+)"),                      # foreach
    re.compile(r"\b(?:function|fn)\b[^(;{]*\(([^)]*)\)"),                  # parameters
    re.compile(r"\bcatch\s*\(([^)]*)\)"),
    re.compile(r"\blist\s*\(([^)]*)\)\s*=(?!=)"),
    re.compile(r"\[([^\]]*)\]\s*=(?![=>])"),                               # [$a, $b] = ...
    re.compile(r",\s*" + _PHP_VAR + r"\s*(?=[,)])"),                       # a later argument may be by-reference
    re.compile(r"(?:\+\+|--)\s*" + _PHP_VAR + r"\b"),
    re.compile(_PHP_VAR + r"\s*(?:\+\+|--)"),
)
_PHP_NAME_RE = re.compile(r"\$([A-Za-z_]\w*)")
_php_local = threading.local()


class _PhpIndex:
    """One pass per pattern over a file: the right-hand sides assigned to each variable and the set
    of variables that can be written some other way.  Asking per finding would be quadratic."""

    __slots__ = ("rhs", "unsafe", "all_unsafe")

    def __init__(self, content: str) -> None:
        self.rhs: dict[str, list[str] | None] = {}
        self.unsafe: set[str] = set()
        self.all_unsafe = bool(re.search(r"\b(?:extract|parse_str)\s*\(", content))
        for m in _PHP_ASSIGN_RE.finditer(content):
            name = m.group(1)
            if m.group(2):
                self.unsafe.add(name)        # `.=`, `+=`, `??=` ...
                continue
            end = _php_scan(content, m.end(), ";")
            entry = self.rhs.setdefault(name, [])
            if entry is None:
                continue
            if end < 0 or end >= len(content) or len(entry) >= 20:
                self.rhs[name] = None
            else:
                entry.append(content[m.end():end])
        for rx in _PHP_WRITE_RES:
            for m in rx.finditer(content):
                self.unsafe.update(_PHP_NAME_RE.findall(m.group(0)))


def _php_var_only_holds_literals(content: str, name: str) -> bool:
    if len(content) > 400_000:
        return False
    cache = getattr(_php_local, "entry", None)
    if cache is None or cache[0] is not content:
        cache = (content, _PhpIndex(content), {})
        _php_local.entry = cache
    idx, verdicts = cache[1], cache[2]
    if name not in verdicts:
        rhs = idx.rhs.get(name)
        verdicts[name] = (not idx.all_unsafe and name not in idx.unsafe and bool(rhs)
                          and all(_php_expr_is_literal(r) for r in rhs))
    return verdicts[name]


def _php_cmd_arg_is_constant(line: str, content: str) -> bool:
    m = _PHP_FIRST_ARG_RE.search(line)
    return bool(m) and _php_var_only_holds_literals(content, m.group(1))



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


_EXEC_PARAM_RE = re.compile(r"(?<![\w.>:'\"])exec\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]")
_FUNC_DEF_RE = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)")
_LITERAL_ARG_RE = re.compile(r"\(\s*(?:'[^']*'|\"[^\"]*\"|`[^`$]*`)\s*[,)]")


def _exec_param_only_gets_literals(lines: list[str], lineno: int) -> bool:
    """`function get(cmd, cb) { exec(cmd, cb) }` is a command sink only if some caller passes
    data.  When the helper (or its util.promisify alias) is called in this file and every call
    passes a plain string literal, nothing variable reaches exec()."""
    if not 1 <= lineno <= len(lines):
        return False
    m = _EXEC_PARAM_RE.search(lines[lineno - 1])
    if not m:
        return False
    param = m.group(1)
    func = None
    for i in range(lineno - 2, max(-1, lineno - 40), -1):
        d = _FUNC_DEF_RE.search(lines[i])
        if d and d.group(2) == param:
            func = d.group(1)
            break
    if func is None:
        return False
    aliases = {func}
    alias_re = re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*[^;]*\bpromisify\(\s*" + re.escape(func) + r"\s*\)")
    for line in lines:
        am = alias_re.search(line)
        if am:
            aliases.add(am.group(1))
    calls = 0
    for line in lines:
        for name in aliases:
            for cm in re.finditer(r"(?<![\w$.])" + re.escape(name) + r"\s*\(", line):
                if re.match(r"\s*(?:async\s+)?function\b", line) or "promisify(" in line:
                    continue
                calls += 1
                if not _LITERAL_ARG_RE.match(line[cm.end() - 1:]):
                    return False
    return calls > 0
