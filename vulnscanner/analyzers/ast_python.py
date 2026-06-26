"""
High-precision Python vulnerability analyzer using the built-in `ast` module.

Advantages over regex:
  - Ignores string literals and comments containing dangerous-looking text
  - Three-state taint tracking: TAINTED / UNKNOWN / CLEAN
  - Class-attribute tracking: self.placeholder = "?" → CLEAN
  - Function-scope constant propagation
  - Sink-specific sanitizer recognition
"""

from __future__ import annotations

import ast
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType
from vulnscanner.taint import (
    TaintInfo, TaintStatus,
    CLEAN_LITERAL, CLEAN_BUILTIN, UNKNOWN_UNRESOLVED,
)

# ── SQL ────────────────────────────────────────────────────────────────────────

_SQL_CALL_NAMES = frozenset({"execute", "executemany", "executescript", "query"})

# ── Command ────────────────────────────────────────────────────────────────────

_SUBPROCESS_NAMES = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
})

# ── Deserialization ────────────────────────────────────────────────────────────

_PICKLE_FUNCS = frozenset({
    "pickle.loads", "pickle.load", "pickle.Unpickler",
    "cPickle.loads", "cPickle.load",
})
_MARSHAL_FUNCS = frozenset({"marshal.loads", "marshal.load"})

_YAML_SAFE_LOADERS = frozenset({
    "SafeLoader", "CSafeLoader",
    "yaml.SafeLoader", "yaml.CSafeLoader",
})
_YAML_LOAD_FUNCS = frozenset({"yaml.load", "yaml.full_load"})
_YAML_UNSAFE_FUNCS = frozenset({"yaml.unsafe_load"})

# ── SSRF ──────────────────────────────────────────────────────────────────────

_HTTP_CLIENT_FUNCS = frozenset({
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.options", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch",
    "httpx.delete", "httpx.request",
    "urllib.request.urlopen", "urlopen", "urllib2.urlopen",
})

# ── Open Redirect ─────────────────────────────────────────────────────────────

_REDIRECT_FUNCS = frozenset({
    "redirect",
    "HttpResponseRedirect",
    "HttpResponsePermanentRedirect",
    "RedirectResponse",
})

# ── SSTI ──────────────────────────────────────────────────────────────────────

_TEMPLATE_RENDER_FUNCS = frozenset({"render_template_string"})

# ── Secrets ────────────────────────────────────────────────────────────────────

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

# ── XSS ───────────────────────────────────────────────────────────────────────

_UNSAFE_TEMPLATE_FUNCS = frozenset({"mark_safe", "format_html"})

# ── Taint sources and sinks ────────────────────────────────────────────────────

# Variable names that are inherently user-controlled when used as standalone names.
_TAINTED_NAME_SOURCES = frozenset({
    "request",     # Flask / Django / FastAPI / WSGI request object
    "user_input",  # explicit user input variable
    "stdin",       # sys.stdin reading
})

# Attribute names that indicate user-supplied data, regardless of the object.
_TAINTED_ATTR_NAMES = frozenset({
    "args",         # request.args (GET params, Flask)
    "form",         # request.form (POST params)
    "json",         # request.json
    "params",       # request.params (ASGI / SQLAlchemy)
    "query_params", # ASGI request.query_params
    "GET", "POST", "REQUEST", "COOKIE", "FILES",  # Django / PHP-style
    "cookies",      # request.cookies
    "headers",      # request.headers
    "body",         # request.body (raw body)
    "payload",      # webhook payload
    "data",         # request.data (some frameworks)
    "META",         # Django request.META
    # "environ" intentionally excluded: os.environ is server-set, not user input.
    # WSGI environ is covered via request object (request is in _TAINTED_NAME_SOURCES).
})

# Getter methods on a TAINTED object — result is also TAINTED.
_GETTER_METHODS = frozenset({
    "get", "getlist", "getall", "get_json",
    "read", "readline", "readlines",
    "decode",
    "__getitem__", "pop", "values", "items", "keys",
})

# String template/format methods: taint is propagated from both object and args.
_STRING_TEMPLATE_METHODS = frozenset({
    "format", "format_map", "join", "replace",
})

# Type-coercion sanitizers: safe against ALL sink types (SQL, CMD, PATH, XSS).
# int/float/bool produce non-string values that cannot carry injection payloads.
_UNIVERSAL_SANITIZER_FUNCS = frozenset({"int", "float", "bool"})

# Context-specific sanitizers: protect ONLY their own sink context.
# Using these in an unrelated sink (e.g. html.escape in a SQL query) does NOT
# prevent injection — they must NOT mark the result CLEAN for every sink type.
_HTML_SANITIZER_FUNCS = frozenset({
    "html.escape", "cgi.escape", "bleach.clean", "markupsafe.escape",
})
_HTML_SANITIZER_METHODS = frozenset({"escape", "html_escape", "sanitize", "bleach_clean"})
_URL_SANITIZER_FUNCS = frozenset({
    "urllib.parse.quote", "urllib.parse.quote_plus", "urllib.parse.urlencode",
})
_URL_SANITIZER_METHODS = frozenset({"quote", "quote_plus", "urlencode"})


# ── public analyzer ────────────────────────────────────────────────────────────

class PythonASTAnalyzer(BaseAnalyzer):
    """AST-based analyzer for .py files.

    Replaces regex-based SQL/CMD/PATH rules for Python, eliminating false
    positives that come from matching inside string literals and docstrings.
    Uses three-state taint tracking (TAINTED / UNKNOWN / CLEAN) to distinguish
    confirmed user-input flows from unresolvable and provably-safe ones.
    """

    supported_extensions = (".py",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            return []

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
        self._assignments: dict[str, ast.expr] = {}
        self._class_attrs: dict[str, ast.expr] = {}
        self._in_enum_class: bool = False

    # ── scope tracking ─────────────────────────────────────────────────────────

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        saved_attrs = self._class_attrs
        saved_enum = self._in_enum_class
        self._class_attrs = _collect_class_attrs(node)
        # Enum member assignments look like secrets (HARDCODED_SECRET = "Hardcoded Secret")
        # but are type labels, not credentials.  Suppress AST-SEC-001 inside Enum subclasses.
        _ENUM_BASES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}
        self._in_enum_class = any(
            (isinstance(b, ast.Name) and b.id in _ENUM_BASES)
            or (isinstance(b, ast.Attribute) and b.attr in _ENUM_BASES)
            for b in node.bases
        )
        self.generic_visit(node)
        self._class_attrs = saved_attrs
        self._in_enum_class = saved_enum

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved = self._assignments
        self._assignments = _collect_scope_assignments(node)
        self.generic_visit(node)
        self._assignments = saved

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # ── dispatch ───────────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql(node)
        self._check_command(node)
        self._check_path(node)
        self._check_xss(node)
        self._check_deserialization(node)
        self._check_ssrf(node)
        self._check_open_redirect(node)
        self._check_ssti(node)
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
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr not in _SQL_CALL_NAMES:
            return
        if not node.args:
            return

        first = node.args[0]
        func = node.func.attr

        # Literal string: safe if parameterized, also safe even without params
        if _is_str_const(first):
            return

        # Determine rule_id and pattern label from AST structure
        if isinstance(first, ast.JoinedStr):
            rule_id, label = "AST-SQL-001", "f-string"
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            rule_id, label = "AST-SQL-002", "concatenation"
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Mod):
            rule_id, label = "AST-SQL-003", "%-format"
        elif _is_format_call(first):
            rule_id, label = "AST-SQL-004", ".format()"
        else:
            rule_id, label = "AST-SQL-005", "variable"

        taint = _taint_of(first, self._assignments, self._class_attrs)

        if taint.status == TaintStatus.CLEAN:
            self._add_suppressed(node, VulnType.SQL_INJECTION, rule_id, "clean_taint_source", taint)
            return

        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.SQL_INJECTION, Severity.HIGH, rule_id,
                      f"{func}() receives a tainted {label} - SQL injection risk: {taint.reason}",
                      taint)
        else:  # UNKNOWN
            self._add(node, VulnType.SQL_INJECTION, Severity.MEDIUM, rule_id,
                      f"[needs_review] {func}() receives a {label} - verify not user-controlled:"
                      f" {taint.reason}",
                      taint)

    # ── command injection ──────────────────────────────────────────────────────

    def _check_command(self, node: ast.Call) -> None:
        full = _full_name(node.func)
        attr = _attr_name(node.func)

        # os.system / os.popen
        if full in ("os.system", "os.popen"):
            if not node.args:
                return
            taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            qualifier = "tainted" if taint.status == TaintStatus.TAINTED else "non-literal"
            self._add(node, VulnType.COMMAND_INJECTION, Severity.HIGH, "AST-CMD-001",
                      f"{full}() called with {qualifier} argument - prefer subprocess list form:"
                      f" {taint.reason}",
                      taint)

        # subprocess.* with shell=True
        elif full in _SUBPROCESS_NAMES:
            if not _kwarg_is_true(node, "shell"):
                return
            cmd = node.args[0] if node.args else None
            if cmd is None:
                return
            taint = _taint_of(cmd, self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                # Literal list with shell=True: still warn (remove shell=True)
                if isinstance(cmd, ast.List) and all(_is_const(e) for e in cmd.elts):
                    self._add(node, VulnType.COMMAND_INJECTION, Severity.LOW, "AST-CMD-002",
                              f"{full}() uses shell=True with literal list - remove shell=True",
                              taint)
                return
            qualifier = "tainted" if taint.status == TaintStatus.TAINTED else "non-literal"
            self._add(node, VulnType.COMMAND_INJECTION, Severity.HIGH, "AST-CMD-002",
                      f"{full}() uses shell=True with {qualifier} command - injection risk:"
                      f" {taint.reason}",
                      taint)

        # standalone eval(expr) — NOT a method call
        elif attr == "eval" and not isinstance(node.func, ast.Attribute):
            if node.args and not _is_const(node.args[0]):
                self._add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "AST-CMD-003",
                          "eval() called with non-literal - arbitrary code execution risk")

        # standalone exec(expr)
        elif attr == "exec" and not isinstance(node.func, ast.Attribute):
            if node.args and not _is_const(node.args[0]):
                self._add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "AST-CMD-004",
                          "exec() called with non-literal - arbitrary code execution risk")

    # ── path traversal ─────────────────────────────────────────────────────────

    def _check_path(self, node: ast.Call) -> None:
        if not (isinstance(node.func, ast.Name) and node.func.id == "open"):
            return
        if not node.args:
            return

        path = node.args[0]
        if _is_const(path):
            return

        taint = _taint_of(path, self._assignments, self._class_attrs)

        if taint.status == TaintStatus.CLEAN:
            self._add_suppressed(node, VulnType.PATH_TRAVERSAL, "AST-PATH-001",
                                 "clean_taint_source", taint)
            return

        if taint.status == TaintStatus.TAINTED:
            if isinstance(path, (ast.JoinedStr, ast.BinOp)):
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "AST-PATH-002",
                          f"open() receives a tainted {'f-string' if isinstance(path, ast.JoinedStr) else 'concatenated'}"
                          f" path - traversal risk: {taint.reason}",
                          taint)
            else:
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "AST-PATH-001",
                          f"open() receives a tainted path - traversal risk: {taint.reason}",
                          taint)
        else:  # UNKNOWN
            if isinstance(path, ast.JoinedStr):
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.MEDIUM, "AST-PATH-002",
                          f"[needs_review] open() receives an f-string path - verify cannot escape"
                          f" directory: {taint.reason}",
                          taint)
            elif isinstance(path, ast.BinOp) and isinstance(path.op, ast.Add):
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.MEDIUM, "AST-PATH-002",
                          f"[needs_review] open() receives a concatenated path - verify cannot"
                          f" escape directory: {taint.reason}",
                          taint)
            else:
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.LOW, "AST-PATH-003",
                          f"[needs_review] open() receives a variable path - verify not"
                          f" user-controlled: {taint.reason}",
                          taint)

    # ── XSS (Python template helpers) ─────────────────────────────────────────

    def _check_xss(self, node: ast.Call) -> None:
        name = _attr_name(node.func) or _full_name(node.func)
        if name not in _UNSAFE_TEMPLATE_FUNCS:
            return
        if not node.args:
            return
        if not _is_const(node.args[0]):
            self._add(node, VulnType.XSS, Severity.MEDIUM, "AST-XSS-001",
                      f"{name}() called with a non-literal value - verify no user input reaches this")

    # ── insecure deserialization ───────────────────────────────────────────────

    def _check_deserialization(self, node: ast.Call) -> None:
        full = _full_name(node.func)

        if full in _PICKLE_FUNCS:
            self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                      "AST-DESER-001",
                      f"{full}() deserializes arbitrary Python objects - never use on "
                      "untrusted data; an attacker can achieve RCE via a crafted payload")

        elif full in _MARSHAL_FUNCS:
            self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                      "AST-DESER-002",
                      f"{full}() is not designed to be safe against malicious data")

        elif full in _YAML_UNSAFE_FUNCS:
            self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                      "AST-DESER-003",
                      "yaml.unsafe_load() allows execution of arbitrary Python - use yaml.safe_load()")

        elif full in _YAML_LOAD_FUNCS:
            loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
            if loader_kw is None:
                self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.HIGH,
                          "AST-DESER-004",
                          f"{full}() without Loader= is unsafe - use yaml.safe_load() "
                          "or pass Loader=yaml.SafeLoader")
            else:
                loader_name = _full_name(loader_kw.value) or _attr_name(loader_kw.value) or ""
                if loader_name not in _YAML_SAFE_LOADERS:
                    self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.HIGH,
                              "AST-DESER-004",
                              f"{full}() with Loader={loader_name} is not fully safe - "
                              "use Loader=yaml.SafeLoader")

    # ── SSRF ───────────────────────────────────────────────────────────────────

    def _check_ssrf(self, node: ast.Call) -> None:
        full = _full_name(node.func)
        if full not in _HTTP_CLIENT_FUNCS:
            return

        url_arg: ast.expr | None = node.args[0] if node.args else None
        if url_arg is None:
            url_arg = next(
                (kw.value for kw in node.keywords if kw.arg == "url"), None
            )
        if url_arg is None:
            return

        taint = _taint_of(url_arg, self._assignments, self._class_attrs)

        if taint.status == TaintStatus.CLEAN:
            return

        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.SSRF, Severity.HIGH, "AST-SSRF-001",
                      f"{full}() called with URL from user input - SSRF allows requests to "
                      f"internal services or cloud metadata endpoints: {taint.reason}",
                      taint)
        else:  # UNKNOWN
            self._add(node, VulnType.SSRF, Severity.MEDIUM, "AST-SSRF-002",
                      f"[needs_review] {full}() called with dynamic URL - verify not "
                      f"user-controlled: {taint.reason}",
                      taint)

    # ── open redirect ──────────────────────────────────────────────────────────

    def _check_open_redirect(self, node: ast.Call) -> None:
        name = _attr_name(node.func) or _full_name(node.func)
        if name not in _REDIRECT_FUNCS:
            return
        if not node.args:
            return

        url_arg = node.args[0]
        if _is_const(url_arg):
            return

        taint = _taint_of(url_arg, self._assignments, self._class_attrs)

        if taint.status == TaintStatus.CLEAN:
            return

        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.OPEN_REDIRECT, Severity.HIGH, "AST-REDIR-001",
                      f"{name}() redirects to URL from user input - attackers can redirect "
                      f"victims to malicious sites (phishing): {taint.reason}",
                      taint)
        else:  # UNKNOWN
            self._add(node, VulnType.OPEN_REDIRECT, Severity.MEDIUM, "AST-REDIR-002",
                      f"[needs_review] {name}() redirects to dynamic URL - validate against "
                      f"allowlist before redirecting: {taint.reason}",
                      taint)

    # ── server-side template injection (SSTI) ─────────────────────────────────

    def _check_ssti(self, node: ast.Call) -> None:
        name = _attr_name(node.func) or _full_name(node.func)

        if name in _TEMPLATE_RENDER_FUNCS:
            if not node.args or _is_const(node.args[0]):
                return
            self._add(node, VulnType.SSTI, Severity.CRITICAL, "AST-SSTI-001",
                      f"{name}() renders a non-literal template string - "
                      "user-controlled template content leads to RCE via SSTI")

        elif name == "from_string":
            if not node.args or _is_const(node.args[0]):
                return
            self._add(node, VulnType.SSTI, Severity.HIGH, "AST-SSTI-002",
                      "Environment.from_string() with non-literal template - "
                      "verify the template source is not user-controlled")

    # ── hardcoded secrets ──────────────────────────────────────────────────────

    def _check_secret(
        self,
        target: ast.expr,
        value: ast.expr,
        node: ast.AST,
    ) -> None:
        if self._in_enum_class:
            return
        name = _assign_name(target)
        if not name or not _SECRET_NAME_RE.search(name):
            return
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        secret = value.value
        if len(secret) < 4:
            return
        if _SECRET_SKIP_RE.search(secret):
            return
        self._add(
            node, VulnType.HARDCODED_SECRET, Severity.HIGH, "AST-SEC-001",
            f"Hardcoded string assigned to '{name}' - use environment variables or a secrets manager",
        )

    # ── helpers ────────────────────────────────────────────────────────────────

    def _add(
        self,
        node: ast.AST,
        vuln_type: VulnType,
        severity: Severity,
        rule_id: str,
        description: str,
        taint_info: TaintInfo | None = None,
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
                    if 0 < lineno <= len(self.lines) else ""
                ),
                description=description,
                rule_id=rule_id,
                repo_url=self.repo_url,
                snippet=self.analyzer._extract_snippet(self.lines, lineno),
                taint_status=taint_info.status.value if taint_info else None,
                taint_reason=taint_info.reason if taint_info else None,
                taint_source=taint_info.source if taint_info else None,
                confidence=taint_info.confidence if taint_info else 1.0,
            )
        )

    def _add_suppressed(
        self,
        node: ast.AST,
        vuln_type: VulnType,
        rule_id: str,
        suppression_reason: str,
        taint_info: TaintInfo | None = None,
    ) -> None:
        lineno: int = getattr(node, "lineno", 0)
        self.findings.append(
            Finding(
                vuln_type=vuln_type,
                severity=Severity.INFO,
                file_path=self.file_path,
                line_number=lineno,
                line_content=(
                    self.lines[lineno - 1].strip()
                    if 0 < lineno <= len(self.lines) else ""
                ),
                description="",
                rule_id=rule_id,
                repo_url=self.repo_url,
                suppression_reason=suppression_reason,
                taint_status=taint_info.status.value if taint_info else "clean",
                taint_reason=taint_info.reason if taint_info else "",
                confidence=0.0,
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


def _collect_scope_assignments(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.expr]:
    """Return {name: rhs} for simple name assignments inside a function body."""
    result: dict[str, ast.expr] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            result[node.target.id] = node.value
    return result


def _collect_class_attrs(cls: ast.ClassDef) -> dict[str, ast.expr]:
    """Return {attr: rhs} for class-level assignments and self.xxx = ... in __init__."""
    result: dict[str, ast.expr] = {}
    for item in cls.body:
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = item.value
        elif (isinstance(item, ast.AnnAssign)
              and isinstance(item.target, ast.Name)
              and item.value is not None):
            result[item.target.id] = item.value
        elif (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
              and item.name == "__init__"):
            for stmt in ast.walk(item):
                if (isinstance(stmt, ast.Assign)
                        and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Attribute)
                        and isinstance(stmt.targets[0].value, ast.Name)
                        and stmt.targets[0].value.id == "self"):
                    result[stmt.targets[0].attr] = stmt.value
    return result


# ── 3-state taint analysis ─────────────────────────────────────────────────────

def _taint_of(
    node: ast.expr,
    assignments: dict[str, ast.expr] | None = None,
    class_attrs: dict[str, ast.expr] | None = None,
    _depth: int = 0,
) -> TaintInfo:
    """
    Determine the taint state of an AST expression node.

    Returns TaintInfo with status TAINTED, UNKNOWN, or CLEAN:
      TAINTED  — provably derived from user-controlled input
      UNKNOWN  — cannot determine; emit finding at lower severity (needs_review)
      CLEAN    — literal, constant, or provably sanitized; suppress the finding
    """
    if _depth > 4:
        return UNKNOWN_UNRESOLVED

    # ── Literal constant ────────────────────────────────────────────────────────
    if isinstance(node, ast.Constant):
        return CLEAN_LITERAL

    # ── Variable name ───────────────────────────────────────────────────────────
    if isinstance(node, ast.Name):
        name = node.id
        if name in _TAINTED_NAME_SOURCES:
            return TaintInfo(TaintStatus.TAINTED,
                             f"known user-input source '{name}'", source=name)
        if name in ("True", "False", "None"):
            return CLEAN_BUILTIN
        if assignments and name in assignments:
            val = assignments[name]
            if val is not node:
                return _taint_of(val, assignments, class_attrs, _depth + 1)
        return TaintInfo(TaintStatus.UNKNOWN,
                         f"untracked variable '{name}'", source=name)

    # ── Attribute access ────────────────────────────────────────────────────────
    if isinstance(node, ast.Attribute):
        attr = node.attr
        if attr in _TAINTED_ATTR_NAMES:
            return TaintInfo(TaintStatus.TAINTED,
                             f"user-input attribute '.{attr}'", source=f"*.{attr}")
        # self.attr → look up class attributes
        if isinstance(node.value, ast.Name) and node.value.id == "self":
            if class_attrs and attr in class_attrs:
                return _taint_of(class_attrs[attr], assignments, class_attrs, _depth + 1)
            return TaintInfo(TaintStatus.UNKNOWN,
                             f"untracked class attr 'self.{attr}'", source=f"self.{attr}")
        obj_taint = _taint_of(node.value, assignments, class_attrs, _depth + 1)
        if obj_taint.status == TaintStatus.TAINTED:
            return TaintInfo(TaintStatus.TAINTED,
                             f"attribute of tainted object '.{attr}'",
                             source=obj_taint.source)
        return TaintInfo(TaintStatus.UNKNOWN,
                         f"attribute '.{attr}' on {obj_taint.status.value} object",
                         source=f"*.{attr}")

    # ── Function/method call ────────────────────────────────────────────────────
    if isinstance(node, ast.Call):
        full = _full_name(node.func) or ""
        attr = (node.func.attr
                if isinstance(node.func, ast.Attribute) else "") or ""

        # Built-in user-input sources
        if full == "input":
            return TaintInfo(TaintStatus.TAINTED, "Python input() function", source="input()")

        # Universal sanitizers (type coercion): safe for every sink
        if full in _UNIVERSAL_SANITIZER_FUNCS:
            return TaintInfo(TaintStatus.CLEAN, f"sanitized by {full}()", sanitizers=[full])

        # Context-specific sanitizers: record the sanitizer in metadata but
        # preserve the argument's taint status unchanged.
        # html.escape / bleach.clean protect HTML/XSS sinks only.
        # urllib.parse.quote protects URL encoding only.
        # Neither prevents SQL/CMD/PATH/SSRF injection — do NOT downgrade a
        # TAINTED argument to UNKNOWN or CLEAN; that would suppress HIGH findings
        # at those sinks.  CLEAN arguments stay CLEAN (sanitizer is a no-op here).
        _is_ctx = (
            full in _HTML_SANITIZER_FUNCS | _URL_SANITIZER_FUNCS
            or attr in _HTML_SANITIZER_METHODS | _URL_SANITIZER_METHODS
        )
        if _is_ctx:
            arg_taint = (
                _taint_of(node.args[0], assignments, class_attrs, _depth + 1)
                if node.args
                else TaintInfo(TaintStatus.UNKNOWN, "no argument")
            )
            if arg_taint.status == TaintStatus.CLEAN:
                return arg_taint
            # TAINTED or UNKNOWN: propagate status, record sanitizer as metadata.
            # The sink-side checker (e.g. _check_sql) will determine severity.
            sanitizer_name = full or f".{attr}"
            return TaintInfo(
                arg_taint.status,
                f"{sanitizer_name}() applied but protects HTML/URL context only;"
                f" ineffective at this sink: {arg_taint.reason}",
                source=arg_taint.source,
                sanitizers=[sanitizer_name] + (arg_taint.sanitizers or []),
            )

        if isinstance(node.func, ast.Attribute):
            obj_taint = _taint_of(node.func.value, assignments, class_attrs, _depth + 1)

            # Getter methods on tainted objects propagate taint
            if obj_taint.status == TaintStatus.TAINTED and attr in _GETTER_METHODS:
                return TaintInfo(TaintStatus.TAINTED,
                                 f"tainted object getter .{attr}()",
                                 source=obj_taint.source)

            # String template methods: propagate worst taint from object + args
            if attr in _STRING_TEMPLATE_METHODS:
                arg_taints = [
                    _taint_of(a, assignments, class_attrs, _depth + 1)
                    for a in node.args
                ]
                return _taint_worst([obj_taint] + arg_taints)

        return TaintInfo(TaintStatus.UNKNOWN,
                         f"return of {full or attr or '<call>'}()",
                         source=full or attr or "<call>")

    # ── BinOp ───────────────────────────────────────────────────────────────────
    if isinstance(node, ast.BinOp):
        return _taint_merge(
            _taint_of(node.left, assignments, class_attrs, _depth + 1),
            _taint_of(node.right, assignments, class_attrs, _depth + 1),
        )

    # ── F-string ────────────────────────────────────────────────────────────────
    if isinstance(node, ast.JoinedStr):
        parts = [
            _taint_of(v.value, assignments, class_attrs, _depth + 1)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        ]
        return _taint_worst(parts) if parts else CLEAN_LITERAL

    # ── Subscript ───────────────────────────────────────────────────────────────
    if isinstance(node, ast.Subscript):
        obj_taint = _taint_of(node.value, assignments, class_attrs, _depth + 1)
        if obj_taint.status == TaintStatus.TAINTED:
            return TaintInfo(TaintStatus.TAINTED,
                             "subscript of tainted value", source=obj_taint.source)
        return TaintInfo(TaintStatus.UNKNOWN,
                         f"subscript of {obj_taint.status.value} value",
                         source=obj_taint.source)

    # ── Container literals (tuple / list / set) ─────────────────────────────────
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        if not node.elts:
            return CLEAN_LITERAL
        return _taint_worst([
            _taint_of(e, assignments, class_attrs, _depth + 1)
            for e in node.elts
        ])

    # ── Conditional expression ───────────────────────────────────────────────────
    if isinstance(node, ast.IfExp):
        return _taint_merge(
            _taint_of(node.body, assignments, class_attrs, _depth + 1),
            _taint_of(node.orelse, assignments, class_attrs, _depth + 1),
        )

    return TaintInfo(TaintStatus.UNKNOWN,
                     f"unanalyzed expr ({type(node).__name__})", source="<expr>")


_TAINT_ORDER = {TaintStatus.TAINTED: 2, TaintStatus.UNKNOWN: 1, TaintStatus.CLEAN: 0}


def _taint_merge(a: TaintInfo, b: TaintInfo) -> TaintInfo:
    """Return the more severe of two TaintInfo values."""
    return a if _TAINT_ORDER[a.status] >= _TAINT_ORDER[b.status] else b


def _taint_worst(infos: list[TaintInfo]) -> TaintInfo:
    """Return the most severe TaintInfo from a non-empty list."""
    result = infos[0]
    for t in infos[1:]:
        result = _taint_merge(result, t)
    return result
