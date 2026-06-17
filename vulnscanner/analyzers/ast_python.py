"""
High-precision Python vulnerability analyzer using the built-in `ast` module.

Advantages over regex:
  - Ignores string literals and comments containing dangerous-looking text
  - Detects argument types (literal vs variable vs f-string vs concatenation)
  - Recognizes safe parameterized queries (execute("...", (params,)))
  - Distinguishes .exec() method calls from standalone exec()
  - Validates subprocess shell=True with literal vs variable commands
"""

from __future__ import annotations

import ast
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# ── constants ──────────────────────────────────────────────────────────────────

_SQL_CALL_NAMES = frozenset({"execute", "executemany", "executescript", "query"})

_SUBPROCESS_NAMES = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
})

# Names that suggest a variable holds user-supplied data
_USER_INPUT_NAMES = frozenset({
    "request", "args", "form", "json", "data", "params",
    "query_params", "GET", "POST", "REQUEST", "COOKIE", "FILES",
    "environ", "stdin", "input",
})

_SECRET_NAME_RE = re.compile(
    r"password|passwd|pwd|secret|api_key|apikey|api_secret|"
    r"access_token|auth_token|private_key|secret_key|token",
    re.IGNORECASE,
)

_SECRET_SKIP_RE = re.compile(
    r"example|sample|placeholder|your[_\-]|<[^>]+>|\*{2,}|"
    r"xxx|dummy|fake|change[_\-]?me|todo|test|mock",
    re.IGNORECASE,
)

# Django / Jinja2 unsafe template helpers
_UNSAFE_TEMPLATE_FUNCS = frozenset({"mark_safe", "format_html"})


# ── public analyzer ────────────────────────────────────────────────────────────

class PythonASTAnalyzer(BaseAnalyzer):
    """AST-based analyzer for .py files.

    Replaces regex-based SQL/CMD/PATH rules for Python, eliminating false
    positives that come from matching inside string literals and docstrings.
    """

    supported_extensions = (".py",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            return []  # Let regex analyzers handle unparseable files

        lines = content.splitlines()
        visitor = _VulnVisitor(file_path, lines, repo_url, self)
        visitor.visit(tree)
        return visitor.findings


# ── AST visitor ────────────────────────────────────────────────────────────────

class _VulnVisitor(ast.NodeVisitor):
    def __init__(
        self,
        file_path: str,
        lines: list[str],
        repo_url: str,
        analyzer: PythonASTAnalyzer,
    ) -> None:
        self.file_path = file_path
        self.lines = lines
        self.repo_url = repo_url
        self.analyzer = analyzer
        self.findings: list[Finding] = []

    # ── dispatch ───────────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql(node)
        self._check_command(node)
        self._check_path(node)
        self._check_xss(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_secret(target, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_secret(node.target, node.value, node)
        self.generic_visit(node)

    # ── SQL injection ──────────────────────────────────────────────────────────

    def _check_sql(self, node: ast.Call) -> None:
        # Match obj.execute(...) / obj.query(...) — not standalone execute()
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr not in _SQL_CALL_NAMES:
            return
        if not node.args:
            return

        first = node.args[0]

        # Safe: literal string  +  params as second positional or keyword arg
        if _is_str_const(first):
            has_params = (
                len(node.args) > 1
                or any(kw.arg in ("parameters", "params") for kw in node.keywords)
            )
            if has_params:
                return  # parameterized query — safe
            # Literal with no params: could still be safe (no user data injected)
            return

        func = node.func.attr
        if isinstance(first, ast.JoinedStr):
            self._add(node, VulnType.SQL_INJECTION, Severity.HIGH, "AST-SQL-001",
                      f"{func}() receives an f-string — user data may be interpolated directly")
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            self._add(node, VulnType.SQL_INJECTION, Severity.HIGH, "AST-SQL-002",
                      f"{func}() receives a + concatenation — use parameterized queries")
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Mod):
            self._add(node, VulnType.SQL_INJECTION, Severity.HIGH, "AST-SQL-003",
                      f"{func}() receives a %%-formatted string — use parameterized queries")
        elif _is_format_call(first):
            self._add(node, VulnType.SQL_INJECTION, Severity.HIGH, "AST-SQL-004",
                      f"{func}() receives a .format() string — use parameterized queries")
        elif isinstance(first, ast.Name):
            self._add(node, VulnType.SQL_INJECTION, Severity.MEDIUM, "AST-SQL-005",
                      f"{func}() receives a variable — verify it is not user-controlled")

    # ── command injection ──────────────────────────────────────────────────────

    def _check_command(self, node: ast.Call) -> None:
        full = _full_name(node.func)
        attr = _attr_name(node.func)

        # os.system / os.popen — only flag when argument is not a literal
        if full in ("os.system", "os.popen"):
            if node.args and not _is_const(node.args[0]):
                self._add(node, VulnType.COMMAND_INJECTION, Severity.HIGH, "AST-CMD-001",
                          f"{full}() called with non-literal argument — prefer subprocess list form")

        # subprocess.* with shell=True
        elif full in _SUBPROCESS_NAMES:
            if _kwarg_is_true(node, "shell"):
                cmd = node.args[0] if node.args else None
                if cmd is None:
                    pass
                elif _is_const(cmd):
                    pass  # literal command with shell=True: lower risk, still note it
                elif isinstance(cmd, ast.List) and all(_is_const(e) for e in cmd.elts):
                    self._add(node, VulnType.COMMAND_INJECTION, Severity.LOW, "AST-CMD-002",
                              f"{full}() uses shell=True with a literal list — remove shell=True")
                else:
                    self._add(node, VulnType.COMMAND_INJECTION, Severity.HIGH, "AST-CMD-002",
                              f"{full}() uses shell=True with a non-literal command — injection risk")

        # standalone eval(expr) — NOT a method call (attr check would be None for builtins)
        elif attr == "eval" and not isinstance(node.func, ast.Attribute):
            if node.args and not _is_const(node.args[0]):
                self._add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "AST-CMD-003",
                          "eval() called with non-literal — arbitrary code execution risk")

        # standalone exec(expr)
        elif attr == "exec" and not isinstance(node.func, ast.Attribute):
            if node.args and not _is_const(node.args[0]):
                self._add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "AST-CMD-004",
                          "exec() called with non-literal — arbitrary code execution risk")

    # ── path traversal ─────────────────────────────────────────────────────────

    def _check_path(self, node: ast.Call) -> None:
        # Only match standalone open() (builtins), not obj.open()
        if not (isinstance(node.func, ast.Name) and node.func.id == "open"):
            return
        if not node.args:
            return

        path = node.args[0]

        if _is_const(path):
            return  # literal path — safe

        if _touches_user_input(path):
            self._add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "AST-PATH-001",
                      "open() receives a path derived from user input — path traversal risk")
        elif isinstance(path, ast.JoinedStr):
            self._add(node, VulnType.PATH_TRAVERSAL, Severity.MEDIUM, "AST-PATH-002",
                      "open() receives an f-string path — verify it cannot escape the intended directory")
        elif isinstance(path, ast.BinOp) and isinstance(path.op, ast.Add):
            self._add(node, VulnType.PATH_TRAVERSAL, Severity.MEDIUM, "AST-PATH-002",
                      "open() receives a concatenated path — verify it cannot escape the intended directory")
        elif isinstance(path, ast.Name):
            self._add(node, VulnType.PATH_TRAVERSAL, Severity.LOW, "AST-PATH-003",
                      "open() receives a variable path — verify the value is validated and sanitized")

    # ── XSS (Python template helpers) ─────────────────────────────────────────

    def _check_xss(self, node: ast.Call) -> None:
        name = _attr_name(node.func) or _full_name(node.func)
        if name not in _UNSAFE_TEMPLATE_FUNCS:
            return
        if not node.args:
            return
        if not _is_const(node.args[0]):
            self._add(node, VulnType.XSS, Severity.MEDIUM, "AST-XSS-001",
                      f"{name}() called with a non-literal value — verify no user input reaches this")

    # ── hardcoded secrets ──────────────────────────────────────────────────────

    def _check_secret(
        self,
        target: ast.expr,
        value: ast.expr,
        node: ast.AST,
    ) -> None:
        name = _assign_name(target)
        if not name or not _SECRET_NAME_RE.search(name):
            return

        # Value must be a non-empty string literal
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        secret = value.value
        if len(secret) < 4:
            return
        if _SECRET_SKIP_RE.search(secret):
            return

        self._add(
            node, VulnType.HARDCODED_SECRET, Severity.HIGH, "AST-SEC-001",
            f"Hardcoded string assigned to '{name}' — use environment variables or a secrets manager",
        )

    # ── helper ─────────────────────────────────────────────────────────────────

    def _add(
        self,
        node: ast.AST,
        vuln_type: VulnType,
        severity: Severity,
        rule_id: str,
        description: str,
    ) -> None:
        lineno: int = getattr(node, "lineno", 0)
        self.findings.append(
            Finding(
                vuln_type=vuln_type,
                severity=severity,
                file_path=self.file_path,
                line_number=lineno,
                line_content=(
                    self.lines[lineno - 1].strip()
                    if 0 < lineno <= len(self.lines)
                    else ""
                ),
                description=description,
                rule_id=rule_id,
                repo_url=self.repo_url,
                snippet=self.analyzer._extract_snippet(self.lines, lineno),
            )
        )


# ── module-level helpers ───────────────────────────────────────────────────────

def _full_name(node: ast.expr) -> str | None:
    """Return dotted name: 'os.system', 'subprocess.run', etc."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _full_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _attr_name(node: ast.expr) -> str | None:
    """Return just the attribute/function name without the object prefix."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _assign_name(target: ast.expr) -> str | None:
    """Return name from a simple assignment target (Name or Attribute)."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _is_const(node: ast.expr) -> bool:
    """True if node is any compile-time constant (str, int, bytes, None, bool)."""
    return isinstance(node, ast.Constant)


def _is_str_const(node: ast.expr) -> bool:
    """True if node is a string literal."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_format_call(node: ast.expr) -> bool:
    """True if node is a str.format() call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def _kwarg_is_true(node: ast.Call, name: str) -> bool:
    """True if keyword argument `name` is the literal True."""
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value is True
    return False


def _touches_user_input(node: ast.expr) -> bool:
    """
    Heuristic: walk the expression tree and check whether any Name or
    Attribute node uses a name commonly associated with user-supplied data.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in _USER_INPUT_NAMES:
            return True
        if isinstance(child, ast.Attribute) and child.attr in _USER_INPUT_NAMES:
            return True
    return False
