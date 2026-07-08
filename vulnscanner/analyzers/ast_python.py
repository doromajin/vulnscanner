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
    "decode", "encode",
    "__getitem__", "pop", "values", "items", "keys",
    # str transformations: taint passes through unchanged (digits/alpha still injectable)
    "strip", "lstrip", "rstrip",
    "lower", "upper", "title", "capitalize", "swapcase",
    "split", "rsplit", "splitlines",
    "zfill", "ljust", "rjust", "center",
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

# if-condition guards: when these string methods return True, the receiver only
# contains chars with no syntactic meaning in SQL/CMD/URL — injection-safe.
_GUARD_VALIDATION_METHODS = frozenset({
    "isdigit", "isnumeric", "isalpha", "isalnum", "isidentifier",
})
# isinstance() target types that produce non-string values — cannot carry injection payloads.
_SAFE_ISINSTANCE_TYPES = frozenset({"int", "float", "bool", "Decimal"})

# Django ORM raw-SQL sinks: methods that accept raw SQL fragments bypassing parameterisation.
_DJANGO_RAW_SQL_METHODS = frozenset({"raw", "extra"})
_DJANGO_ORM_RAW_FUNCS = frozenset({"RawSQL"})

# SQLAlchemy raw-SQL wrapper: text() explicitly opts out of ORM parameterisation.
_SQLALCHEMY_TEXT_FUNCS = frozenset({"text", "sqlalchemy.text"})

# Path construction functions: taint from any argument flows to the result path.
_PATH_CONSTRUCTION_FUNCS = frozenset({
    "os.path.join", "os.path.abspath", "os.path.realpath",
    "os.path.normpath", "os.path.expanduser",
    "pathlib.Path", "Path",
})

# CMD-specific sanitizer: shlex.quote() correctly escapes shell metacharacters.
# Safe for subprocess shell=True but NOT for SQL/PATH/XSS — preserve taint, add metadata.
_CMD_SANITIZER_FUNCS = frozenset({"shlex.quote", "pipes.quote"})

# Dynamic import sinks: load arbitrary code from user-supplied module names.
_DYNAMIC_IMPORT_FUNCS = frozenset({"__import__", "importlib.import_module"})

# os.* path sinks with a single path argument.
_OS_PATH_SINKS_SINGLE = frozenset({
    "os.makedirs", "os.mkdir", "os.remove", "os.unlink",
    "os.chmod", "os.stat", "os.listdir", "os.scandir",
    "os.rmdir", "os.removedirs", "os.chown",
})
# os.* / shutil.* path sinks with (src, dst) — both arguments are checked.
_OS_PATH_SINKS_DUAL = frozenset({
    "os.rename", "os.replace",
    "shutil.copy", "shutil.copy2", "shutil.move", "shutil.rmtree", "shutil.copytree",
})
# pathlib methods that perform IO on the path object — fire when receiver is TAINTED.
_PATHLIB_IO_METHODS = frozenset({
    "read_text", "read_bytes", "write_text", "write_bytes",
    "iterdir", "glob", "rglob",
})

# Weak hash algorithms — fast enough for GPU brute-force; broken for cryptographic use.
_WEAK_HASH_FUNCS = frozenset({
    "hashlib.md5", "hashlib.sha1", "md5", "sha1",
})
# Python stdlib RNG — not cryptographically secure; predictable from seed.
_INSECURE_RNG_FUNCS = frozenset({
    "random.random", "random.randint", "random.choice", "random.choices",
    "random.sample", "random.shuffle", "random.randrange", "random.uniform",
})
# Variable names that suggest security-sensitive random values.
_SECURITY_SENSITIVE_RNG_RE = re.compile(
    r"token|secret|key|nonce|salt|otp|csrf|session|password|passwd|pwd",
    re.IGNORECASE,
)

# ── interprocedural taint (per-file, single-threaded) ─────────────────────────
# Updated by PythonASTAnalyzer.analyze() before each file visit.
_interprocedural_taint_sources: frozenset[str] = frozenset()


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
        global _interprocedural_taint_sources
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            return []

        lines = content.splitlines()
        _interprocedural_taint_sources = _find_taint_source_funcs(tree)
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
        self._visit_stmts(node.body)
        self._assignments = saved

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # ── dispatch ───────────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql(node)
        self._check_django_orm_sql(node)
        self._check_sqlalchemy_text(node)
        self._check_command(node)
        self._check_path(node)
        self._check_xss(node)
        self._check_deserialization(node)
        self._check_ssrf(node)
        self._check_open_redirect(node)
        self._check_ssti(node)
        self._check_weak_crypto(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_secret(target, node.value, node)
            self._check_insecure_rng(target, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_secret(node.target, node.value, node)
            self._check_insecure_rng(node.target, node.value, node)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        guarded_vars = _extract_guard_vars(node.test)
        if guarded_vars:
            saved = self._assignments
            patched = dict(saved)
            for v in guarded_vars:
                patched[v] = ast.Constant(value=0)
            self._assignments = patched
            self._visit_stmts(node.body)
            self._assignments = saved
            self._visit_stmts(node.orelse)
        else:
            self._visit_stmts(node.body)
            self._visit_stmts(node.orelse)

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

    # ── Django ORM raw-SQL sinks ───────────────────────────────────────────────

    def _check_django_orm_sql(self, node: ast.Call) -> None:
        """Detect .raw(sql), .extra(where=[sql]), and RawSQL(sql) with tainted arguments."""
        sql_arg: ast.expr | None = None
        rule_label: str = ""

        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr == "raw":
                sql_arg = (node.args[0] if node.args else None) or next(
                    (kw.value for kw in node.keywords if kw.arg in ("raw_query", "query")),
                    None,
                )
                rule_label = ".raw()"
            elif attr == "extra":
                sql_arg = next(
                    (kw.value for kw in node.keywords if kw.arg == "where"), None
                )
                if sql_arg is None and node.args:
                    sql_arg = node.args[0]
                rule_label = ".extra()"
            elif attr == "RawSQL":
                sql_arg = node.args[0] if node.args else None
                rule_label = "RawSQL()"
        elif isinstance(node.func, ast.Name) and node.func.id in _DJANGO_ORM_RAW_FUNCS:
            sql_arg = node.args[0] if node.args else None
            rule_label = f"{node.func.id}()"

        if sql_arg is None or _is_const(sql_arg):
            return

        taint = _taint_of(sql_arg, self._assignments, self._class_attrs)
        if taint.status == TaintStatus.CLEAN:
            return

        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.SQL_INJECTION, Severity.HIGH, "AST-SQL-006",
                      f"{rule_label} receives tainted SQL — Django ORM raw SQL injection: {taint.reason}",
                      taint)
        else:
            self._add(node, VulnType.SQL_INJECTION, Severity.MEDIUM, "AST-SQL-006",
                      f"[needs_review] {rule_label} receives dynamic SQL — verify not user-controlled:"
                      f" {taint.reason}",
                      taint)

    # ── SQLAlchemy text() sink ─────────────────────────────────────────────────

    def _check_sqlalchemy_text(self, node: ast.Call) -> None:
        """Detect sqlalchemy.text(tainted_sql) — the ORM raw-SQL escape hatch."""
        full = _full_name(node.func)
        if full not in _SQLALCHEMY_TEXT_FUNCS:
            return
        if not node.args:
            return

        sql_arg = node.args[0]
        if _is_const(sql_arg):
            return

        taint = _taint_of(sql_arg, self._assignments, self._class_attrs)
        if taint.status == TaintStatus.CLEAN:
            return

        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.SQL_INJECTION, Severity.HIGH, "AST-SQL-007",
                      f"sqlalchemy text() receives tainted SQL — raw SQL injection risk: {taint.reason}",
                      taint)
        else:
            self._add(node, VulnType.SQL_INJECTION, Severity.MEDIUM, "AST-SQL-007",
                      f"[needs_review] sqlalchemy text() receives dynamic SQL — verify not"
                      f" user-controlled: {taint.reason}",
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
            if any(s in _CMD_SANITIZER_FUNCS for s in taint.sanitizers):
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
                if isinstance(cmd, ast.List) and all(_is_const(e) for e in cmd.elts):
                    self._add(node, VulnType.COMMAND_INJECTION, Severity.LOW, "AST-CMD-002",
                              f"{full}() uses shell=True with literal list - remove shell=True",
                              taint)
                return
            if any(s in _CMD_SANITIZER_FUNCS for s in taint.sanitizers):
                return
            qualifier = "tainted" if taint.status == TaintStatus.TAINTED else "non-literal"
            self._add(node, VulnType.COMMAND_INJECTION, Severity.HIGH, "AST-CMD-002",
                      f"{full}() uses shell=True with {qualifier} command - injection risk:"
                      f" {taint.reason}",
                      taint)

        # standalone eval(expr) — NOT a method call
        elif attr == "eval" and not isinstance(node.func, ast.Attribute):
            if node.args and not _is_const(node.args[0]):
                taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
                if taint.status == TaintStatus.CLEAN:
                    return
                sev = Severity.CRITICAL if taint.status == TaintStatus.TAINTED else Severity.HIGH
                label = "tainted" if taint.status == TaintStatus.TAINTED else "non-literal"
                self._add(node, VulnType.COMMAND_INJECTION, sev, "AST-CMD-003",
                          f"eval() called with {label} argument - arbitrary code execution risk:"
                          f" {taint.reason}",
                          taint)

        # standalone exec(expr)
        elif attr == "exec" and not isinstance(node.func, ast.Attribute):
            if node.args and not _is_const(node.args[0]):
                taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
                if taint.status == TaintStatus.CLEAN:
                    return
                sev = Severity.CRITICAL if taint.status == TaintStatus.TAINTED else Severity.HIGH
                label = "tainted" if taint.status == TaintStatus.TAINTED else "non-literal"
                self._add(node, VulnType.COMMAND_INJECTION, sev, "AST-CMD-004",
                          f"exec() called with {label} argument - arbitrary code execution risk:"
                          f" {taint.reason}",
                          taint)

        # dynamic import — arbitrary module loading from user input
        elif full in _DYNAMIC_IMPORT_FUNCS:
            if not node.args:
                return
            module_arg = node.args[0]
            if _is_const(module_arg):
                return
            taint = _taint_of(module_arg, self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            sev = Severity.CRITICAL if taint.status == TaintStatus.TAINTED else Severity.HIGH
            label = "tainted" if taint.status == TaintStatus.TAINTED else "dynamic"
            self._add(node, VulnType.COMMAND_INJECTION, sev, "AST-CMD-005",
                      f"{full}() with {label} module name — allows loading arbitrary code:"
                      f" {taint.reason}",
                      taint)

    # ── path traversal ─────────────────────────────────────────────────────────

    def _check_path(self, node: ast.Call) -> None:
        full = _full_name(node.func)
        attr = _attr_name(node.func)

        # open(path) — standalone built-in
        if isinstance(node.func, ast.Name) and node.func.id == "open":
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
                rule = "AST-PATH-002" if isinstance(path, (ast.JoinedStr, ast.BinOp)) else "AST-PATH-001"
                label = ("f-string" if isinstance(path, ast.JoinedStr)
                         else "concatenated" if isinstance(path, ast.BinOp) else "")
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, rule,
                          f"open() receives a tainted {label + ' ' if label else ''}path"
                          f" - traversal risk: {taint.reason}",
                          taint)
            else:
                rule = "AST-PATH-002" if isinstance(path, (ast.JoinedStr, ast.BinOp)) else "AST-PATH-003"
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.MEDIUM, rule,
                          f"[needs_review] open() receives a dynamic path - verify cannot escape"
                          f" directory: {taint.reason}",
                          taint)

        # os.makedirs / os.remove / os.stat / etc.
        elif full in _OS_PATH_SINKS_SINGLE:
            if node.args:
                self._check_path_arg(node, node.args[0], full)

        # os.rename / shutil.copy / shutil.move / etc. — check src and dst
        elif full in _OS_PATH_SINKS_DUAL:
            for path_arg in node.args[:2]:
                self._check_path_arg(node, path_arg, full)

        # pathlib IO methods on a potentially-tainted path object
        elif attr in _PATHLIB_IO_METHODS and isinstance(node.func, ast.Attribute):
            obj_taint = _taint_of(node.func.value, self._assignments, self._class_attrs)
            if obj_taint.status == TaintStatus.CLEAN:
                return
            sev = Severity.HIGH if obj_taint.status == TaintStatus.TAINTED else Severity.MEDIUM
            prefix = "" if obj_taint.status == TaintStatus.TAINTED else "[needs_review] "
            self._add(node, VulnType.PATH_TRAVERSAL, sev, "AST-PATH-004",
                      f"{prefix}.{attr}() on {'tainted' if obj_taint.status == TaintStatus.TAINTED else 'dynamic'}"
                      f" path — traversal risk: {obj_taint.reason}",
                      obj_taint)

    def _check_path_arg(self, node: ast.Call, path: ast.expr, func_name: str) -> None:
        if _is_const(path):
            return
        taint = _taint_of(path, self._assignments, self._class_attrs)
        if taint.status == TaintStatus.CLEAN:
            return
        sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
        prefix = "" if taint.status == TaintStatus.TAINTED else "[needs_review] "
        self._add(node, VulnType.PATH_TRAVERSAL, sev, "AST-PATH-005",
                  f"{prefix}{func_name}() receives {'tainted' if taint.status == TaintStatus.TAINTED else 'dynamic'}"
                  f" path — traversal risk: {taint.reason}",
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

    # ── weak cryptography ──────────────────────────────────────────────────────

    def _check_weak_crypto(self, node: ast.Call) -> None:
        full = _full_name(node.func)
        if full in _WEAK_HASH_FUNCS:
            self._add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.LOW, "AST-CRYPTO-001",
                      f"{full}() uses a weak hash algorithm — MD5/SHA-1 are broken for "
                      "cryptographic use; use hashlib.sha256() or stronger")

    def _check_insecure_rng(
        self,
        target: ast.expr,
        value: ast.expr,
        node: ast.AST,
    ) -> None:
        if not isinstance(value, ast.Call):
            return
        full = _full_name(value.func)
        if full not in _INSECURE_RNG_FUNCS:
            return
        name = _assign_name(target)
        if not name or not _SECURITY_SENSITIVE_RNG_RE.search(name):
            return
        self._add(
            node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "AST-CRYPTO-002",
            f"Security-sensitive '{name}' generated with {full}() — "
            "use secrets.token_bytes() or secrets.token_hex() for cryptographic randomness",
        )

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

    def _visit_stmts(self, stmts: list[ast.stmt]) -> None:
        """Visit a statement list, detecting early-return guards for taint suppression.

        When `if not guard(x): return/raise` is detected, subsequent statements in
        the same block treat `x` as CLEAN — matching real-world input-validation patterns.
        """
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            if (isinstance(stmt, ast.If)
                    and not stmt.orelse
                    and _is_always_exit(stmt.body)):
                neg_vars = _extract_negated_guard_vars(stmt.test)
                self.visit(stmt)
                if neg_vars:
                    saved = self._assignments
                    patched = dict(saved)
                    for v in neg_vars:
                        patched[v] = ast.Constant(value=0)
                    self._assignments = patched
                    self._visit_stmts(stmts[i + 1:])
                    self._assignments = saved
                    return
            else:
                self.visit(stmt)
            i += 1


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
    if _depth > 6:
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

        # Interprocedural taint: call to a function identified as a taint source in pre-pass.
        if full in _interprocedural_taint_sources:
            return TaintInfo(TaintStatus.TAINTED,
                             f"return of taint-source function '{full}'", source=full)

        # Context-specific sanitizers: record sanitizer in metadata, preserve taint status.
        # html.escape / bleach.clean  → protects HTML/XSS only
        # urllib.parse.quote          → protects URL encoding only
        # shlex.quote / pipes.quote   → protects CMD/shell only
        # None of these prevent injection at other sink types — do NOT mark CLEAN globally.
        _is_ctx = (
            full in _HTML_SANITIZER_FUNCS | _URL_SANITIZER_FUNCS | _CMD_SANITIZER_FUNCS
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
            sanitizer_name = full or f".{attr}"
            ctx_label = ("CMD" if full in _CMD_SANITIZER_FUNCS
                         else "HTML/URL")
            return TaintInfo(
                arg_taint.status,
                f"{sanitizer_name}() applied — protects {ctx_label} context only;"
                f" ineffective at other sinks: {arg_taint.reason}",
                source=arg_taint.source,
                sanitizers=[sanitizer_name] + (arg_taint.sanitizers or []),
            )

        # Path construction: taint propagates from any argument to the resulting path.
        # os.path.join(safe_base, user_input) must remain TAINTED for open() to fire HIGH.
        if full in _PATH_CONSTRUCTION_FUNCS:
            arg_taints = [
                _taint_of(a, assignments, class_attrs, _depth + 1)
                for a in node.args
            ]
            return _taint_worst(arg_taints) if arg_taints else CLEAN_LITERAL

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


def _extract_guard_var(test: ast.expr) -> str | None:
    """Return the name of the variable validated by a safe guard condition, or None.

    Recognized patterns:
      isinstance(var, int | float | bool | Decimal)   — numeric type check
      var.isdigit() / var.isnumeric() / var.isalpha() / var.isalnum()
    """
    if (isinstance(test, ast.Call)
            and isinstance(test.func, ast.Name)
            and test.func.id == "isinstance"
            and len(test.args) == 2
            and isinstance(test.args[0], ast.Name)
            and _is_safe_type_check(test.args[1])):
        return test.args[0].id
    if (isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr in _GUARD_VALIDATION_METHODS
            and isinstance(test.func.value, ast.Name)):
        return test.func.value.id
    return None


def _is_safe_type_check(types_node: ast.expr) -> bool:
    """True if types_node names a type that guarantees non-string, injection-safe values."""
    if isinstance(types_node, ast.Name):
        return types_node.id in _SAFE_ISINSTANCE_TYPES
    if isinstance(types_node, ast.Tuple):
        return any(
            isinstance(e, ast.Name) and e.id in _SAFE_ISINSTANCE_TYPES
            for e in types_node.elts
        )
    return False


def _extract_guard_vars(test: ast.expr) -> frozenset[str]:
    """Return all variable names validated by the if-condition.

    Handles single guards and `and`-chained guards:
      if x.isdigit() and y.isalpha():  →  {'x', 'y'}
    """
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        result: set[str] = set()
        for value in test.values:
            var = _extract_guard_var(value)
            if var:
                result.add(var)
        return frozenset(result)
    var = _extract_guard_var(test)
    return frozenset({var}) if var else frozenset()


def _extract_negated_guard_vars(test: ast.expr) -> frozenset[str]:
    """Return guarded vars from a negated guard: `not x.isdigit()` → {'x'}."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _extract_guard_vars(test.operand)
    return frozenset()


def _is_always_exit(stmts: list[ast.stmt]) -> bool:
    """True if the last statement in the block always exits the current scope."""
    return bool(stmts) and isinstance(
        stmts[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break)
    )


def _find_taint_source_funcs(tree: ast.AST) -> frozenset[str]:
    """Pre-pass: find names of functions that always return a tainted value.

    Handles simple wrappers like:
      def get_user_id():
          return request.GET.get("id")
    """
    sources: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Collect only non-docstring, non-pass statements
        body = [s for s in node.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        assignments = _collect_scope_assignments(node)
        # Single return statement
        if (len(body) == 1
                and isinstance(body[0], ast.Return)
                and body[0].value is not None):
            if _taint_of(body[0].value, assignments, {}).status == TaintStatus.TAINTED:
                sources.add(node.name)
        # Assignment then return
        elif (len(body) == 2
                and isinstance(body[0], ast.Assign)
                and isinstance(body[1], ast.Return)
                and body[1].value is not None):
            if _taint_of(body[1].value, assignments, {}).status == TaintStatus.TAINTED:
                sources.add(node.name)
    return frozenset(sources)
