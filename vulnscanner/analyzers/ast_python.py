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
import copy
import json
import re
import threading as _threading
from collections.abc import Iterator
from pathlib import Path

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType
from vulnscanner.taint import (
    TaintInfo, TaintStatus,
    CLEAN_LITERAL, CLEAN_BUILTIN, UNKNOWN_UNRESOLVED,
)

def _load_python_taint_methods() -> frozenset[str]:
    """Load user-defined Python taint-source method names from custom_taint_sources.json."""
    config_path = Path(__file__).parent.parent.parent / "custom_taint_sources.json"
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        return frozenset(
            entry["method"]
            for entry in data.get("python_any_qualifier_taint_methods", [])
            if isinstance(entry.get("method"), str)
        )
    except Exception:
        return frozenset()

# Method names that always return TAINTED regardless of the object they're called on.
# These represent request-parameter getters on wrapper objects. Loaded from
# custom_taint_sources.json so project teams can extend without touching analyzer code.
_PY_ANY_QUALIFIER_TAINT_METHODS: frozenset[str] = _load_python_taint_methods()

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

# Decode/transform functions that are NOT sanitizers — they propagate taint from
# their first argument.  URL-decoding (unquote*) makes encoded input *more* raw,
# not safer.  JSON parsing preserves any injection payload in the underlying string.
_TAINT_PASSTHROUGH_FUNCS = frozenset({
    "urllib.parse.unquote",
    "urllib.parse.unquote_plus",
    "urllib.parse.unquote_to_bytes",
    "json.loads",
    "json.load",
    "base64.b64decode",
    "base64.b64encode",
    "base64.decodebytes",
    "base64.encodebytes",
    "base64.urlsafe_b64decode",
    "base64.urlsafe_b64encode",
    "base64.b16decode",
    "base64.b32decode",
})

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
    # Filesystem probing with user-controlled path is path traversal (info disclosure).
    "os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.getsize",
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
    # Existence/stat checks on a tainted path → filesystem probing (info disclosure).
    "exists", "stat", "is_file", "is_dir", "is_symlink", "open",
})


def _find_canonicalized_paths(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    """Return variable names that have been canonicalized via .resolve() + .startswith().

    Detects the standard Python path-traversal mitigation pattern:
        p = (base_dir / user_input).resolve()
        if not str(p).startswith(str(base_dir)):
            return ...

    Variables satisfying both conditions are treated as safe to use in path sinks.
    This pattern is recommended by the OWASP Python Cheat Sheet and widely used in
    Flask/Django applications.
    """
    resolve_vars: set[str] = set()
    startswith_vars: set[str] = set()

    for node in ast.walk(func):
        # Detect: p = expr.resolve()
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "resolve"
        ):
            resolve_vars.add(node.targets[0].id)

        # Detect: str(p).startswith(...) or p.startswith(...)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "startswith"
        ):
            obj = node.func.value
            if isinstance(obj, ast.Name):
                startswith_vars.add(obj.id)
            elif (
                isinstance(obj, ast.Call)
                and isinstance(obj.func, ast.Name)
                and obj.func.id == "str"
                and obj.args
                and isinstance(obj.args[0], ast.Name)
            ):
                startswith_vars.add(obj.args[0].id)

    return frozenset(resolve_vars & startswith_vars)

# Weak hash algorithms — fast enough for GPU brute-force; broken for cryptographic use.
_WEAK_HASH_FUNCS = frozenset({
    "hashlib.md5", "hashlib.sha1", "md5", "sha1",
})
_WEAK_HASH_ALGOS = frozenset({"md5", "sha1", "sha-1", "md-5"})

# Flask/Django request attributes that reflect routing metadata, not user-submitted data.
# These are set by the framework based on the route definition, not form or query input.
_CLEAN_REQUEST_ATTRS = frozenset({
    "path", "url", "base_url", "host", "host_url",
    "root_url", "root_path", "script_root", "method",
})
# Python stdlib RNG — not cryptographically secure; predictable from seed.
_INSECURE_RNG_FUNCS = frozenset({
    "random.random", "random.randint", "random.choice", "random.choices",
    "random.sample", "random.shuffle", "random.randrange", "random.uniform",
})
# Direct random.xxx() method attrs — fire unconditionally (context-unaware, like Bandit B311).
# Excludes random.SystemRandom which uses os.urandom() and IS cryptographically secure.
_INSECURE_RNG_ATTRS = frozenset({
    "random", "randint", "choice", "choices", "sample", "shuffle",
    "randrange", "uniform", "normalvariate", "gauss", "lognormvariate",
    "expovariate", "vonmisesvariate", "gammavariate", "betavariate",
    "paretovariate", "weibullvariate", "triangular", "randbytes", "getrandbits",
})
# Variable names that suggest security-sensitive random values.
_SECURITY_SENSITIVE_RNG_RE = re.compile(
    r"token|secret|key|nonce|salt|otp|csrf|session|password|passwd|pwd",
    re.IGNORECASE,
)

# ── XXE ───────────────────────────────────────────────────────────────────────
# xml.dom.minidom / xml.etree.ElementTree parse functions that accept a custom
# parser object.  XXE is only exploitable when external entity expansion is
# explicitly enabled (feature_external_ges=True on the SAX parser).
_XXE_PARSE_FUNCS = frozenset({
    "xml.dom.minidom.parseString", "xml.dom.minidom.parse",
    "minidom.parseString", "minidom.parse",
    "parseString", "parse",
})

# ── LDAP injection ────────────────────────────────────────────────────────────
# ldap3 conn.search() — first positional arg is base, second is the filter.
# We detect taint in the variable used as the filter argument.
_LDAP3_SEARCH_METHODS = frozenset({"search"})

# ── interprocedural taint (per-file, single-threaded) ─────────────────────────
# Both globals are updated by PythonASTAnalyzer.analyze() before each file visit.
_interprocedural_taint_sources: frozenset[str] = frozenset()
_local_func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

# ── cross-file taint context (thread-local) ────────────────────────────────────
# Set once per file analysis via set_cross_file_context(); read in analyze() and _taint_of().
_cross_file_local = _threading.local()


def set_cross_file_context(all_contents: dict[str, str]) -> None:
    """Register the full {relative_path: content} map for cross-file taint resolution.

    Uses thread-local storage so parallel scan workers don't interfere with each other.
    Call this once per scan before submitting analysis jobs.
    """
    _cross_file_local.all_contents = all_contents


def _resolve_module_to_file(
    module_name: str,
    current_file: str,
    all_contents: dict[str, str],
) -> str | None:
    """Resolve a dotted Python module name to a relative file path in all_contents.

    Tries both ``module/path.py`` and ``module/path/__init__.py`` forms,
    first relative to the project root, then relative to the importing file's directory.
    """
    current_dir = current_file.rsplit("/", 1)[0] if "/" in current_file else ""
    bases = [
        module_name.replace(".", "/") + ".py",
        module_name.replace(".", "/") + "/__init__.py",
    ]
    candidates = list(bases)
    if current_dir:
        candidates += [f"{current_dir}/{b}" for b in bases]
    for cand in candidates:
        if cand in all_contents:
            return cand
    return None


def _build_remote_func_defs(
    file_path: str,
    content: str,
    all_contents: dict[str, str],
) -> dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]]:
    """Parse import statements in *content* and return a map of imported project-local
    functions: ``{imported_name: (FunctionDef_node, source_file_path)}``.

    Handles:
    - ``from utils import process`` → key ``"process"``
    - ``from utils import process as p`` → key ``"p"``
    - ``import utils`` → keys ``"utils.func_name"``
    - ``from utils import *`` → all public functions

    Only resolves to files that exist in *all_contents* (project-local);
    third-party packages (e.g. ``import requests``) are silently skipped.
    """
    remote: dict[str, tuple] = {}
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return remote

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            module_file = _resolve_module_to_file(node.module, file_path, all_contents)
            if not module_file:
                continue
            module_content = all_contents.get(module_file, "")
            try:
                module_tree = ast.parse(module_content)
            except SyntaxError:
                continue
            module_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
                n.name: n
                for n in ast.walk(module_tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for alias in node.names:
                name, as_name = alias.name, alias.asname or alias.name
                if name == "*":
                    for fn, fn_node in module_funcs.items():
                        if not fn.startswith("_"):
                            remote[fn] = (fn_node, module_file)
                elif name in module_funcs:
                    remote[as_name] = (module_funcs[name], module_file)

        elif isinstance(node, ast.Import):
            for alias in node.names:
                module_file = _resolve_module_to_file(alias.name, file_path, all_contents)
                if not module_file:
                    continue
                module_content = all_contents.get(module_file, "")
                try:
                    module_tree = ast.parse(module_content)
                except SyntaxError:
                    continue
                as_name = alias.asname or alias.name
                for n in ast.walk(module_tree):
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if not n.name.startswith("_"):
                            remote[f"{as_name}.{n.name}"] = (n, module_file)

    return remote


def _callee_returns_tainted(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    param_assignments: dict[str, ast.expr],
    _depth: int,
) -> bool:
    """Return True if any return path of func_def yields a TAINTED value given param_assignments."""
    if _depth > 14:
        return False
    merged = {**_collect_scope_assignments(func_def), **param_assignments}
    for ret in _iter_func_returns(func_def):
        if ret.value is not None:
            if _taint_of(ret.value, merged, {}, _depth).status == TaintStatus.TAINTED:
                return True
    return False


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
        global _interprocedural_taint_sources, _local_func_defs
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            return []

        lines = content.splitlines()
        # Build per-file function definition map for interprocedural call-site injection.
        _local_func_defs = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        _interprocedural_taint_sources = _find_taint_source_funcs(tree)

        # Cross-file taint: build remote function defs from thread-local context.
        # set_cross_file_context() is called by the scanner before parallel analysis.
        _all = getattr(_cross_file_local, "all_contents", None)
        if _all:
            _rfd = _build_remote_func_defs(file_path, content, _all)
            _cross_file_local.remote_func_defs = _rfd
            # Extend taint sources with remote functions that themselves return tainted data
            # (e.g. utils.get_user_input() defined in utils.py that reads request.args).
            _extra: set[str] = set()
            for _fn_name, (_fn_node, _) in _rfd.items():
                _fake = ast.Module(body=[_fn_node], type_ignores=[])
                if _fn_name in _find_taint_source_funcs(_fake):
                    _extra.add(_fn_name)
            if _extra:
                _interprocedural_taint_sources = _interprocedural_taint_sources | frozenset(_extra)
        else:
            _cross_file_local.remote_func_defs = {}

        visitor = _VulnVisitor(file_path, lines, repo_url, self, content)
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
        content: str = "",
    ) -> None:
        self.file_path = file_path
        self.lines = lines
        self.repo_url = repo_url
        self.analyzer = analyzer
        self.content = content
        self.findings: list[Finding] = []
        self._assignments: dict[str, ast.expr] = {}
        self._class_attrs: dict[str, ast.expr] = {}
        self._canonicalized_paths: frozenset[str] = frozenset()
        self._in_enum_class: bool = False
        self._call_stack: set[str] = set()  # recursion guard for interprocedural re-analysis

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
        saved_canon = self._canonicalized_paths
        self._assignments = _collect_scope_assignments(node)
        self._canonicalized_paths = _find_canonicalized_paths(node)
        self._visit_stmts(node.body)
        self._assignments = saved
        self._canonicalized_paths = saved_canon

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
        self._check_insecure_rng_call(node)
        self._check_xxe(node)
        self._check_ldap_injection(node)
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

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_xss_response(node)
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

        # subprocess.* — shell=True (HIGH) or shell=False with tainted list (MEDIUM)
        elif full in _SUBPROCESS_NAMES:
            cmd = node.args[0] if node.args else None
            if cmd is None:
                return
            taint = _taint_of(cmd, self._assignments, self._class_attrs)
            if not _kwarg_is_true(node, "shell"):
                # shell=False: only fire when the argument list itself is TAINTED
                # (e.g. user input appended to list → command/argument injection risk).
                if taint.status == TaintStatus.TAINTED:
                    if not any(s in _CMD_SANITIZER_FUNCS for s in (taint.sanitizers or [])):
                        self._add(node, VulnType.COMMAND_INJECTION, Severity.MEDIUM, "AST-CMD-005",
                                  f"{full}() receives tainted argument list without shell=True"
                                  f" — command/argument injection risk: {taint.reason}",
                                  taint)
                return
            # shell=True below
            if taint.status == TaintStatus.CLEAN:
                if isinstance(cmd, ast.List) and all(_is_const(e) for e in cmd.elts):
                    self._add(node, VulnType.COMMAND_INJECTION, Severity.LOW, "AST-CMD-002",
                              f"{full}() uses shell=True with literal list - remove shell=True",
                              taint)
                return
            if any(s in _CMD_SANITIZER_FUNCS for s in (taint.sanitizers or [])):
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

        # open(path) / codecs.open(path, …) / io.open(path, …) — file-open sinks
        _is_open = (
            (isinstance(node.func, ast.Name) and node.func.id == "open")
            or full in ("codecs.open", "io.open")
        )
        if _is_open:
            if not node.args:
                return
            path = node.args[0]
            if _is_const(path):
                return
            taint = _taint_of(path, self._assignments, self._class_attrs)
            func_label = node.func.id if isinstance(node.func, ast.Name) else full
            if taint.status == TaintStatus.CLEAN:
                self._add_suppressed(node, VulnType.PATH_TRAVERSAL, "AST-PATH-001",
                                     "clean_taint_source", taint)
                return
            if taint.status == TaintStatus.TAINTED:
                rule = "AST-PATH-002" if isinstance(path, (ast.JoinedStr, ast.BinOp)) else "AST-PATH-001"
                label = ("f-string" if isinstance(path, ast.JoinedStr)
                         else "concatenated" if isinstance(path, ast.BinOp) else "")
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, rule,
                          f"{func_label}() receives a tainted {label + ' ' if label else ''}path"
                          f" - traversal risk: {taint.reason}",
                          taint)
            else:
                rule = "AST-PATH-002" if isinstance(path, (ast.JoinedStr, ast.BinOp)) else "AST-PATH-003"
                self._add(node, VulnType.PATH_TRAVERSAL, Severity.MEDIUM, rule,
                          f"[needs_review] {func_label}() receives a dynamic path - verify cannot"
                          f" escape directory: {taint.reason}",
                          taint)

        # os.makedirs / os.remove / os.stat / etc.
        elif full in _OS_PATH_SINKS_SINGLE:
            if node.args:
                self._check_path_arg(node, node.args[0], full)

        # os.rename / shutil.copy / shutil.move / etc. — check src and dst
        elif full in _OS_PATH_SINKS_DUAL:
            for path_arg in node.args[:2]:
                self._check_path_arg(node, path_arg, full)

        # pathlib IO methods on a potentially-tainted path object.
        # If the path variable was produced by .resolve() and guarded by .startswith(),
        # it is treated as canonicalized and therefore safe (OWASP recommended pattern).
        elif attr in _PATHLIB_IO_METHODS and isinstance(node.func, ast.Attribute):
            path_obj = node.func.value
            if (isinstance(path_obj, ast.Name)
                    and path_obj.id in self._canonicalized_paths):
                return
            obj_taint = _taint_of(path_obj, self._assignments, self._class_attrs)
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

        if full in _PICKLE_FUNCS or full in _MARSHAL_FUNCS:
            rule = "AST-DESER-001" if full in _PICKLE_FUNCS else "AST-DESER-002"
            desc = (f"{full}() deserializes arbitrary Python objects - never use on "
                    "untrusted data; an attacker can achieve RCE via a crafted payload"
                    if full in _PICKLE_FUNCS else
                    f"{full}() is not designed to be safe against malicious data")
            if node.args:
                taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
                if taint.status == TaintStatus.CLEAN:
                    self._add_suppressed(node, VulnType.INSECURE_DESERIALIZATION,
                                         rule, "clean_taint_source", taint)
                    return
                self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                          rule, desc, taint)
            else:
                # pickle/marshal is CRITICAL regardless of whether arg is TAINTED or UNKNOWN:
                # even unknown-origin data must never be passed to pickle.
                self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL, rule, desc)

        elif full in _YAML_UNSAFE_FUNCS:
            self._add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                      "AST-DESER-003",
                      "yaml.unsafe_load() allows execution of arbitrary Python - use yaml.safe_load()")

        elif full in _YAML_LOAD_FUNCS:
            # Taint-aware: suppress when YAML content is provably clean (not user input).
            # Only unsafe Loader variants with user-controlled content are runtime risks.
            if node.args:
                yaml_content_taint = _taint_of(
                    node.args[0], self._assignments, self._class_attrs
                )
                if yaml_content_taint.status == TaintStatus.CLEAN:
                    self._add_suppressed(node, VulnType.INSECURE_DESERIALIZATION,
                                         "AST-DESER-004", "clean_taint_source",
                                         yaml_content_taint)
                    return
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
            # Suppress when the redirect URL was passed through urllib.parse.urlparse()
            # in the same function scope — strong evidence of netloc/scheme validation.
            # Real-world pattern: url = urlparse(bar); if url.netloc not in whitelist: return
            if (isinstance(url_arg, ast.Name)
                    and any(
                        isinstance(v, ast.Call)
                        and _full_name(v.func) in {"urllib.parse.urlparse", "urlparse"}
                        and v.args
                        and isinstance(v.args[0], ast.Name)
                        and v.args[0].id == url_arg.id
                        for v in self._assignments.values()
                        if isinstance(v, ast.Call)
                    )):
                self._add_suppressed(node, VulnType.OPEN_REDIRECT,
                                     "AST-REDIR-001", "url_whitelist_validation", taint)
                return
            self._add(node, VulnType.OPEN_REDIRECT, Severity.HIGH, "AST-REDIR-001",
                      f"{name}() redirects to URL from user input - attackers can redirect "
                      f"victims to malicious sites (phishing): {taint.reason}",
                      taint)
        else:  # UNKNOWN
            self._add(node, VulnType.OPEN_REDIRECT, Severity.MEDIUM, "AST-REDIR-002",
                      f"[needs_review] {name}() receives a dynamic URL argument - verify "
                      f"the value cannot be controlled by user input: {taint.reason}",
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
            return
        # hashlib.new('md5') / hashlib.new('sha1') pattern
        if full == "hashlib.new" and node.args:
            algo_node = node.args[0]
            if isinstance(algo_node, ast.Constant) and isinstance(algo_node.value, str):
                if algo_node.value.lower() in _WEAK_HASH_ALGOS:
                    self._add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.LOW, "AST-CRYPTO-001",
                              f"hashlib.new('{algo_node.value}') uses a weak hash algorithm — "
                              "MD5/SHA-1 are broken for cryptographic use; use sha256 or stronger")

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

    def _check_insecure_rng_call(self, node: ast.Call) -> None:
        """Detect random.xxx() direct calls (excludes random.SystemRandom() which is secure).

        Fires unconditionally for any call to the standard random module's PRNG functions.
        random.SystemRandom() uses os.urandom() and is NOT flagged.
        """
        if not isinstance(node.func, ast.Attribute):
            return
        attr = node.func.attr
        if attr not in _INSECURE_RNG_ATTRS:
            return
        # Must be random.xxx() — qualifier must be the 'random' module Name, not a Call
        # (random.SystemRandom().xxx() has a Call as qualifier, not a Name)
        qualifier = node.func.value
        if not isinstance(qualifier, ast.Name) or qualifier.id != "random":
            return
        self._add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "AST-CRYPTO-003",
                  f"random.{attr}() is not cryptographically secure — "
                  "use secrets.token_bytes() or secrets.token_hex() for session tokens and nonces")

    # ── XXE ───────────────────────────────────────────────────────────────────

    def _check_xxe(self, node: ast.Call) -> None:
        """Detect XXE via xml.dom.minidom.parseString/parse with external entity expansion.

        Only fires when xml.sax.handler.feature_external_ges is explicitly enabled in the
        same file — that is the only way Python's xml.dom.minidom becomes vulnerable to XXE.
        """
        full = _full_name(node.func) or ""
        attr = _attr_name(node.func) or ""
        if full not in _XXE_PARSE_FUNCS and attr not in {"parseString", "parse"}:
            return
        if not node.args:
            return
        # Guard: only fire when external entity expansion is explicitly enabled.
        if "feature_external_ges" not in self.content:
            return
        xml_arg = node.args[0]
        if _is_const(xml_arg):
            return
        taint = _taint_of(xml_arg, self._assignments, self._class_attrs)
        if taint.status == TaintStatus.CLEAN:
            return
        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.XXE, Severity.HIGH, "AST-XXE-001",
                      f"XML parsed with external entity expansion enabled and tainted input — "
                      f"XXE allows reading local files and SSRF: {taint.reason}",
                      taint)
        else:
            self._add(node, VulnType.XXE, Severity.MEDIUM, "AST-XXE-002",
                      "[needs_review] XML parsed with external entity expansion enabled and "
                      f"dynamic input — verify input is not user-controlled: {taint.reason}",
                      taint)

    # ── LDAP injection ─────────────────────────────────────────────────────────

    def _check_ldap_injection(self, node: ast.Call) -> None:
        """Detect ldap3 conn.search() with a tainted filter argument.

        The filter is typically built as an f-string and passed as the second
        positional argument: conn.search(base, filter, attributes=...).
        """
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr not in _LDAP3_SEARCH_METHODS:
            return
        # Need at least 2 positional args: base + filter
        if len(node.args) < 2:
            return
        filter_arg = node.args[1]
        if _is_const(filter_arg):
            return
        taint = _taint_of(filter_arg, self._assignments, self._class_attrs)
        if taint.status == TaintStatus.CLEAN:
            return
        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.LDAP_INJECTION, Severity.HIGH, "AST-LDAP-001",
                      f"ldap3 conn.search() filter built with user input — "
                      f"LDAP injection allows authentication bypass: {taint.reason}",
                      taint)

    # ── XSS: Flask/Django response body accumulation ───────────────────────────

    def _check_xss_response(self, node: ast.AugAssign) -> None:
        """Detect XSS via `RESPONSE += f'...{tainted_var}...'` in Flask route handlers.

        Fires only when the augmented value is provably TAINTED (not merely UNKNOWN),
        avoiding false positives on string accumulation patterns with unresolved variables.
        """
        if not isinstance(node.op, ast.Add):
            return
        if not isinstance(node.target, ast.Name):
            return
        # Check taint of the value being appended
        taint = _taint_of(node.value, self._assignments, self._class_attrs)
        if taint.status != TaintStatus.TAINTED:
            return
        # Suppress if an HTML-specific sanitizer (markupsafe.escape, html.escape, etc.) was applied
        if any(s in _HTML_SANITIZER_FUNCS or s in _HTML_SANITIZER_METHODS
               for s in (taint.sanitizers or [])):
            return
        self._add(node, VulnType.XSS, Severity.HIGH, "AST-XSS-002",
                  f"Tainted user input appended to response string without HTML encoding — "
                  f"reflected XSS risk: {taint.reason}",
                  taint)

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
        new_finding = Finding(
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
        # Deduplicate: if a lower-severity finding exists at the same location,
        # upgrade it rather than appending a duplicate.
        _sev = list(Severity)
        key = (self.file_path, lineno, vuln_type)
        for i, existing in enumerate(self.findings):
            if (existing.file_path, existing.line_number, existing.vuln_type) == key:
                if _sev.index(severity) < _sev.index(existing.severity):
                    self.findings[i] = new_finding
                return
        self.findings.append(new_finding)

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

    def _analyze_with_tainted_params(
        self,
        func_def: ast.FunctionDef | ast.AsyncFunctionDef,
        arg_taints: list[TaintInfo],
    ) -> None:
        """Re-analyze func_def's body with tainted call arguments injected as params.

        For each positional parameter whose corresponding argument is TAINTED, a
        synthetic ``ast.Name(id='request')`` is injected into the scope assignments
        so that ``_taint_of`` propagates TAINTED through the function body.
        The call stack guard prevents infinite recursion on recursive functions.
        """
        param_assignments: dict[str, ast.expr] = {}
        for i, param in enumerate(func_def.args.args):
            if i < len(arg_taints) and arg_taints[i].status == TaintStatus.TAINTED:
                param_assignments[param.arg] = ast.Name(id="request", ctx=ast.Load())
        if not param_assignments:
            return
        saved_assignments = self._assignments
        saved_stack = self._call_stack
        self._call_stack = self._call_stack | {func_def.name}
        self._assignments = {**_collect_scope_assignments(func_def), **param_assignments}
        self._visit_stmts(func_def.body)
        self._assignments = saved_assignments
        self._call_stack = saved_stack

    def _check_interprocedural_calls(self, stmt: ast.stmt) -> None:
        """Walk stmt for calls to local functions that receive ≥1 tainted argument.

        When found, re-analyse the callee's body with those params marked as tainted
        so that sink checks inside the callee fire at the correct (higher) severity.
        Skips functions already on the call stack to prevent infinite recursion.
        """
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            func_name = _full_name(node.func)
            if not func_name or func_name not in _local_func_defs:
                continue
            if func_name in self._call_stack:
                continue
            arg_taints = [
                _taint_of(arg, self._assignments, self._class_attrs)
                for arg in node.args
            ]
            if any(t.status == TaintStatus.TAINTED for t in arg_taints):
                self._analyze_with_tainted_params(
                    _local_func_defs[func_name], arg_taints
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
            self._check_interprocedural_calls(stmt)
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


def _resolve_self_ref(rhs: ast.expr, name: str, prev: ast.expr) -> ast.expr:
    """Return a copy of *rhs* with every ``Name(name)`` replaced by *prev*.

    Used to break self-referential assignments like ``x = f(x)`` so that the
    resulting node chain can be evaluated without circular depth exhaustion.
    Only called when *rhs* actually references *name* (callers check first).
    """
    class _Subst(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.expr:
            return prev if node.id == name else node
    return _Subst().visit(copy.deepcopy(rhs))


def _collect_scope_assignments(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.expr]:
    """Return {name: rhs} for simple name assignments inside a function body.

    Also stores dict-subscript assignments as tuple keys ``(dict_name, key_str)``
    so that ``_taint_of`` can resolve ``map['keyA']`` to its assigned value.

    Null-guard default assignments (``if not X: X = <constant>``) are skipped so
    that an original tainted assignment to X is not overwritten by the empty-string
    default; e.g. ``param = request.form.get(...); if not param: param = ""``.
    """
    # First pass: identify null-guard assignment node ids to skip.
    null_guard_ids: set[int] = set()
    for node in ast.walk(func):
        if not (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.UnaryOp)
            and isinstance(node.test.op, ast.Not)
            and isinstance(node.test.operand, ast.Name)
            and not node.orelse
        ):
            continue
        guarded = node.test.operand.id
        for stmt in node.body:
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == guarded
                and _is_const(stmt.value)
            ):
                null_guard_ids.add(id(stmt))

    # Collect simple scalar constants for const-folding dead-branch detection.
    # Includes int/float (for if/else) and strings (for match-case).
    # Also evaluates one-level constant-string subscripts: "ABC"[0] → 'A'.
    simple_consts: dict[str, ast.expr] = {}
    for node in ast.walk(func):
        if (isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            val = node.value
            if isinstance(val, ast.Constant) and isinstance(val.value, (int, float, str)):
                simple_consts[node.targets[0].id] = val
            elif (isinstance(val, ast.Subscript)
                    and isinstance(val.value, ast.Name)
                    and val.value.id in simple_consts
                    and isinstance(val.slice, ast.Constant)
                    and isinstance(val.slice.value, int)):
                base = simple_consts[val.value.id]
                if isinstance(base.value, str):
                    idx = val.slice.value
                    if 0 <= idx < len(base.value):
                        simple_consts[node.targets[0].id] = ast.Constant(
                            value=base.value[idx]
                        )

    # Identify assignments in dead branches of constant if/else, so they do not
    # overwrite live-branch assignments via the BFS last-write-wins rule.
    dead_assign_ids: set[int] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.If):
            branch = _eval_const_branch(node.test, simple_consts)
            if branch is True and node.orelse:
                dead_stmts = node.orelse
            elif branch is False:
                dead_stmts = node.body
            else:
                continue
            for dead_stmt in dead_stmts:
                for sub in ast.walk(dead_stmt):
                    if isinstance(sub, (ast.Assign, ast.AnnAssign)):
                        dead_assign_ids.add(id(sub))

    # Dead-branch detection for match-case with a constant subject.
    # Pattern: match <const_var>: case 'A': ... case 'B': ...
    # When the subject evaluates to a compile-time constant, only the matching
    # case branch is live; all others are dead.
    if hasattr(ast, "Match"):
        for node in ast.walk(func):
            if not isinstance(node, ast.Match):
                continue
            subject_val: object = None
            if (isinstance(node.subject, ast.Name)
                    and node.subject.id in simple_consts):
                subject_val = simple_consts[node.subject.id].value
            elif isinstance(node.subject, ast.Constant):
                subject_val = node.subject.value
            if subject_val is None:
                continue
            # Find the first matching case and mark all others dead.
            matched = False
            for case in node.cases:
                pat = case.pattern
                if matched:
                    # Already found the live branch — this case is dead.
                    for stmt in case.body:
                        for sub in ast.walk(stmt):
                            if isinstance(sub, (ast.Assign, ast.AnnAssign)):
                                dead_assign_ids.add(id(sub))
                    continue
                # Check whether this case pattern matches subject_val.
                if isinstance(pat, ast.MatchValue):
                    if (isinstance(pat.value, ast.Constant)
                            and pat.value.value == subject_val):
                        matched = True
                elif isinstance(pat, ast.MatchOr):
                    if any(
                        isinstance(p, ast.MatchValue)
                        and isinstance(p.value, ast.Constant)
                        and p.value.value == subject_val
                        for p in pat.patterns
                    ):
                        matched = True
                elif isinstance(pat, ast.MatchAs) and pat.pattern is None:
                    # Default/wildcard — always matches, marks this as the live case.
                    matched = True
                if not matched:
                    # This case does not match — mark it dead.
                    for stmt in case.body:
                        for sub in ast.walk(stmt):
                            if isinstance(sub, (ast.Assign, ast.AnnAssign)):
                                dead_assign_ids.add(id(sub))

    # Treat imported module names as CLEAN server-defined values (not user input).
    # This prevents false positives from module constants like helpers.utils.TESTFILES_DIR.
    # Names in _TAINTED_NAME_SOURCES (e.g. 'request') are intentionally excluded.
    result: dict[str, ast.expr] = {}
    _CLEAN_NODE = ast.Constant(value=0)
    for node in ast.walk(func):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = (alias.asname or alias.name.split('.')[0])
                if top not in _TAINTED_NAME_SOURCES and top not in result:
                    result[top] = _CLEAN_NODE
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                if name not in _TAINTED_NAME_SOURCES and name not in result:
                    result[name] = _CLEAN_NODE

    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            if id(node) in null_guard_ids or id(node) in dead_assign_ids:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    rhs = node.value
                    # Break self-referential cycles (x = f(x)) by substituting
                    # the previous value of x so taint chains remain evaluable.
                    prev = result.get(name)
                    if (prev is not None
                            and any(isinstance(n, ast.Name) and n.id == name
                                    for n in ast.walk(rhs))):
                        rhs = _resolve_self_ref(rhs, name, prev)
                    result[name] = rhs
                elif (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and isinstance(target.slice, ast.Constant)
                ):
                    result[(target.value.id, str(target.slice.value))] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            if id(node) not in dead_assign_ids:
                result[node.target.id] = node.value

    # Second pass: AugAssign (x += expr) — synthesise BinOp so taint propagates
    # from the augmented operand even when the prior assignment was CLEAN.
    for node in ast.walk(func):
        if (isinstance(node, ast.AugAssign)
                and isinstance(node.target, ast.Name)):
            var = node.target.id
            prev = result.get(var)
            if prev is not None:
                result[var] = ast.BinOp(left=prev, op=node.op, right=node.value)
            else:
                result[var] = node.value

    # Third pass: list.append/pop tracking.
    # Tracks per-index element content (for precise lst[n] taint) and maintains
    # a BinOp aggregate for unknown-index subscript fallback.
    # Also models lst.pop(0) so index-shifted accesses resolve correctly.
    _list_contents: dict[str, list[ast.expr]] = {}
    for node in ast.walk(func):
        if not (isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and isinstance(node.value.func.value, ast.Name)):
            continue
        call = node.value
        var = call.func.value.id
        attr = call.func.attr
        if attr == "append" and call.args:
            arg = call.args[0]
            _list_contents.setdefault(var, []).append(arg)
            prev = result.get(var)
            if prev is not None:
                result[var] = ast.BinOp(left=prev, op=ast.Add(), right=arg)
            else:
                result[var] = arg
        elif (attr == "pop"
              and call.args
              and isinstance(call.args[0], ast.Constant)
              and call.args[0].value == 0
              and _list_contents.get(var)):
            _list_contents[var].pop(0)
    # Store per-index content and length sentinel for OOB detection.
    for var, contents in _list_contents.items():
        for i, elem in enumerate(contents):
            result[(var, str(i))] = elem
        result[(var, "__len__")] = ast.Constant(value=len(contents))

    # Fourth pass: for-loop target variables inherit taint from the iterable.
    # Pattern: `for var in expr` — var is an element of expr, so it carries the same taint.
    # Real-world: `for name in request.form.keys()` → name is user-controlled (TAINTED).
    for node in ast.walk(func):
        if isinstance(node, ast.For):
            iter_expr = node.iter
            if isinstance(node.target, ast.Name):
                result[node.target.id] = iter_expr
            elif isinstance(node.target, ast.Tuple):
                for elt in node.target.elts:
                    if isinstance(elt, ast.Name):
                        result[elt.id] = iter_expr

    # Fifth pass: configparser conf.set(section, key, value) — track key-level taint
    # so conf.get(section, key) can resolve to TAINTED or CLEAN instead of UNKNOWN.
    for node in ast.walk(func):
        if (isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "set"
                and isinstance(node.value.func.value, ast.Name)
                and len(node.value.args) >= 3):
            conf_name = node.value.func.value.id
            section_arg = node.value.args[0]
            key_arg = node.value.args[1]
            val_arg = node.value.args[2]
            if (isinstance(section_arg, ast.Constant)
                    and isinstance(key_arg, ast.Constant)):
                lookup_key = (conf_name, str(section_arg.value), str(key_arg.value))
                result[lookup_key] = val_arg

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

def _eval_const_num(
    node: ast.expr,
    _vars: dict[str, ast.expr] | None = None,
) -> int | float | None:
    """Evaluate a compile-time numeric expression, or return None if not constant.

    *_vars* maps variable names to their AST nodes for one level of substitution —
    used to evaluate conditions like ``7 * 42 - num > 200`` where ``num = 86``.
    """
    if isinstance(node, ast.Name) and _vars and node.id in _vars:
        val = _vars[node.id]
        if isinstance(val, ast.Constant) and isinstance(val.value, (int, float)):
            return val.value
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _eval_const_num(node.operand, _vars)
        return -v if v is not None else None
    if isinstance(node, ast.BinOp):
        left = _eval_const_num(node.left, _vars)
        right = _eval_const_num(node.right, _vars)
        if left is None or right is None:
            return None
        op = node.op
        if isinstance(op, ast.Add):
            return left + right
        if isinstance(op, ast.Sub):
            return left - right
        if isinstance(op, ast.Mult):
            return left * right
        if isinstance(op, ast.Div):
            return left / right if right != 0 else None
        if isinstance(op, ast.Mod):
            return left % right if right != 0 else None
    return None


def _eval_const_branch(
    test: ast.expr,
    _vars: dict[str, ast.expr] | None = None,
) -> bool | None:
    """Return True/False if the if-expression test is a compile-time constant, else None.

    *_vars* is forwarded to ``_eval_const_num`` for variable substitution.
    """
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        left = _eval_const_num(test.left, _vars)
        right = _eval_const_num(test.comparators[0], _vars)
        if left is not None and right is not None:
            op = test.ops[0]
            if isinstance(op, ast.Gt):
                return left > right
            if isinstance(op, ast.GtE):
                return left >= right
            if isinstance(op, ast.Lt):
                return left < right
            if isinstance(op, ast.LtE):
                return left <= right
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
    return None


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
    if _depth > 14:
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
        base_taint: TaintInfo | None = None
        if assignments and name in assignments:
            val = assignments[name]
            if val is not node:
                base_taint = _taint_of(val, assignments, class_attrs, _depth + 1)
        # Also propagate taint from subscript-assignments: dict['key'] = tainted_val.
        # Enables `'{0[key]}'.format(dict)` to detect taint flowing through dict values.
        # Only 2-tuple keys are subscript assignments; 3-tuples are configparser entries.
        if assignments:
            sub_taints = [
                _taint_of(v, assignments, class_attrs, _depth + 1)
                for k, v in assignments.items()
                if isinstance(k, tuple) and len(k) == 2 and k[0] == name
            ]
            if sub_taints:
                return _taint_worst(
                    ([base_taint] if base_taint is not None else []) + sub_taints
                )
        if base_taint is not None:
            return base_taint
        return TaintInfo(TaintStatus.UNKNOWN,
                         f"untracked variable '{name}'", source=name)

    # ── Attribute access ────────────────────────────────────────────────────────
    if isinstance(node, ast.Attribute):
        attr = node.attr
        if attr in _TAINTED_ATTR_NAMES:
            return TaintInfo(TaintStatus.TAINTED,
                             f"user-input attribute '.{attr}'", source=f"*.{attr}")
        # request.path, request.url etc. are framework routing attributes, not user-submitted.
        if (isinstance(node.value, ast.Name) and node.value.id == "request"
                and attr in _CLEAN_REQUEST_ATTRS):
            return CLEAN_LITERAL
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
        # Attribute of a clean object (e.g. imported module constant) stays clean.
        if obj_taint.status == TaintStatus.CLEAN:
            return CLEAN_LITERAL
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

        # Decode/transform functions that propagate taint unchanged (not sanitizers).
        if full in _TAINT_PASSTHROUGH_FUNCS:
            if node.args:
                return _taint_of(node.args[0], assignments, class_attrs, _depth + 1)
            return UNKNOWN_UNRESOLVED

        # Interprocedural taint: call to a function identified as a taint source in pre-pass.
        if full in _interprocedural_taint_sources:
            return TaintInfo(TaintStatus.TAINTED,
                             f"return of taint-source function '{full}'", source=full)

        # Phase 3: tainted arg → return propagation.
        # If the callee is a local function and any arg is TAINTED, check whether the tainted
        # parameter flows to a return value inside the callee. If so, the call expression itself
        # is TAINTED in the caller's context (e.g. val = process(request.args.get('q'))).
        if full and full in _local_func_defs and _depth <= 12:
            _arg_taints = [
                _taint_of(a, assignments, class_attrs, _depth + 1) for a in node.args
            ]
            if any(t.status == TaintStatus.TAINTED for t in _arg_taints):
                _fd = _local_func_defs[full]
                _param_assigns: dict[str, ast.expr] = {}
                for _i, _param in enumerate(_fd.args.args):
                    if _i < len(_arg_taints) and _arg_taints[_i].status == TaintStatus.TAINTED:
                        _param_assigns[_param.arg] = ast.Name(id="request", ctx=ast.Load())
                if _param_assigns and _callee_returns_tainted(_fd, _param_assigns, _depth + 1):
                    return TaintInfo(TaintStatus.TAINTED,
                                     f"tainted arg flows through '{full}' return", source=full)

        # Phase 4: cross-file taint propagation.
        # If the called function is imported from another project-local file, check
        # whether a tainted argument flows through its return value.
        # (Remote taint-source functions — those that read request data directly —
        # are already merged into _interprocedural_taint_sources in analyze(), so the
        # check above at line ~1786 handles them. Phase 4 only needs to cover
        # the passthrough case: remote func receives a tainted arg and returns it.)
        if full and full not in _local_func_defs and _depth <= 11:
            _rfd_x = getattr(_cross_file_local, "remote_func_defs", {})
            if full in _rfd_x:
                _rfn, _rsrc = _rfd_x[full]
                _arg_taints_x = [
                    _taint_of(a, assignments, class_attrs, _depth + 1) for a in node.args
                ]
                if any(t.status == TaintStatus.TAINTED for t in _arg_taints_x):
                    _pm: dict[str, ast.expr] = {}
                    for _i, _p in enumerate(_rfn.args.args):
                        if _i < len(_arg_taints_x) and _arg_taints_x[_i].status == TaintStatus.TAINTED:
                            _pm[_p.arg] = ast.Name(id="request", ctx=ast.Load())
                    if _pm and _callee_returns_tainted(_rfn, _pm, _depth + 1):
                        return TaintInfo(
                            TaintStatus.TAINTED,
                            f"tainted arg flows through '{full}' (from {_rsrc}) return",
                            source=f"{_rsrc}:{full}",
                        )

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

            # Custom request-wrapper getters: always TAINTED regardless of object taint.
            if attr in _PY_ANY_QUALIFIER_TAINT_METHODS:
                return TaintInfo(TaintStatus.TAINTED,
                                 f"user-input getter .{attr}() on request wrapper",
                                 source=f"*.{attr}()")

            # Getter/transform methods on clean objects remain clean (e.g. CLEAN.split("/"))
            if obj_taint.status == TaintStatus.CLEAN and attr in _GETTER_METHODS:
                return CLEAN_LITERAL

            # String template methods: propagate worst taint from object + args
            if attr in _STRING_TEMPLATE_METHODS:
                arg_taints = [
                    _taint_of(a, assignments, class_attrs, _depth + 1)
                    for a in node.args
                ]
                return _taint_worst([obj_taint] + arg_taints)

            # ConfigParser.get/getboolean/getint/getfloat(section, key):
            # resolve from conf.set() tracking recorded in the assignments dict.
            # TAINTED conf is already caught by the GETTER_METHODS TAINTED check above;
            # CLEAN conf by the CLEAN getter check — so this branch handles UNKNOWN conf only.
            if (attr in {"get", "getboolean", "getint", "getfloat"}
                    and isinstance(node.func.value, ast.Name)
                    and len(node.args) >= 2
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[1], ast.Constant)
                    and assignments is not None):
                lookup = (node.func.value.id,
                          str(node.args[0].value),
                          str(node.args[1].value))
                if lookup in assignments:
                    return _taint_of(assignments[lookup], assignments, class_attrs, _depth + 1)
                # Key was never stored via conf.set() in this scope → not user-controlled
                return CLEAN_LITERAL

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
        # Dict/list key tracking: resolve container[key] to assigned value when known.
        if (
            assignments is not None
            and isinstance(node.value, ast.Name)
            and isinstance(node.slice, ast.Constant)
        ):
            name_id = node.value.id
            slice_val = node.slice.value
            lookup = (name_id, str(slice_val))
            if lookup in assignments:
                return _taint_of(assignments[lookup], assignments, class_attrs, _depth + 1)
            # OOB detection for tracked lists: integer index beyond known length → CLEAN.
            # lst.pop(0) shifts indices; the third pass computes the final length.
            # If index is guaranteed OOB the line would raise IndexError at runtime,
            # so the subsequent assignment (bar = lst[n]) is never reached.
            if isinstance(slice_val, int) and slice_val >= 0:
                len_key = (name_id, "__len__")
                if len_key in assignments:
                    tracked_len = assignments[len_key].value
                    if isinstance(tracked_len, int) and slice_val >= tracked_len:
                        return CLEAN_LITERAL
        obj_taint = _taint_of(node.value, assignments, class_attrs, _depth + 1)
        if obj_taint.status == TaintStatus.TAINTED:
            return TaintInfo(TaintStatus.TAINTED,
                             "subscript of tainted value", source=obj_taint.source)
        if obj_taint.status == TaintStatus.CLEAN:
            return CLEAN_LITERAL
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

    # ── Dict literal ─────────────────────────────────────────────────────────────
    if isinstance(node, ast.Dict):
        if not node.keys:
            return CLEAN_LITERAL  # empty dict {} is a constant
        all_nodes = [v for v in node.keys + node.values if v is not None]
        return _taint_worst([
            _taint_of(n, assignments, class_attrs, _depth + 1)
            for n in all_nodes
        ])

    # ── Conditional expression ───────────────────────────────────────────────────
    if isinstance(node, ast.IfExp):
        branch = _eval_const_branch(node.test, assignments)
        if branch is True:
            return _taint_of(node.body, assignments, class_attrs, _depth + 1)
        if branch is False:
            return _taint_of(node.orelse, assignments, class_attrs, _depth + 1)
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
      re.match/fullmatch/search(pattern, var)          — regex validation
      var in [allowlist]                               — allowlist membership
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
    # re.match/fullmatch/search(pattern, var) — var is regex-validated inside the if body
    if (isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr in ("match", "fullmatch", "search")
            and isinstance(test.func.value, ast.Name)
            and test.func.value.id == "re"
            and len(test.args) >= 2
            and isinstance(test.args[1], ast.Name)):
        return test.args[1].id
    # var in [literal_list / tuple / set / named_constant] — allowlist membership check
    if (isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and isinstance(test.left, ast.Name)
            and isinstance(test.comparators[0], (ast.List, ast.Tuple, ast.Set, ast.Name))):
        return test.left.id
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
    """Return vars made safe by an early-exit guard condition.

    Recognized patterns (all followed by return/raise in the if-body):
      not x.isdigit()             — negated type/format guard
      '../' in var                — dotdot traversal check: var is safe after exit
      BoolOp(Or) containing `not var.startswith(...)` / `not var.endswith(...)`
                                  — allowlist string-shape guard
    """
    result: set[str] = set()

    # Original: not guard(x) → x is safe
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        result.update(_extract_guard_vars(test.operand))

    # '../' in var_name → dotdot-traversal check; var is safe after early exit
    if (isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and isinstance(test.left, ast.Constant)
            and isinstance(test.left.value, str)
            and '..' in test.left.value
            and isinstance(test.comparators[0], ast.Name)):
        result.add(test.comparators[0].id)

    # var not in ALLOWED → var is allowlist-validated after early exit
    if (isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and isinstance(test.left, ast.Name)
            and isinstance(test.comparators[0], (ast.List, ast.Tuple, ast.Set, ast.Name))):
        result.add(test.left.id)

    # BoolOp(Or/And) containing `not var.startswith(...)` or `not var.endswith(...)`
    # → at least one arm validates the shape; var is treated as safe after exit
    if isinstance(test, ast.BoolOp):
        for operand in test.values:
            if (isinstance(operand, ast.UnaryOp)
                    and isinstance(operand.op, ast.Not)
                    and isinstance(operand.operand, ast.Call)
                    and isinstance(operand.operand.func, ast.Attribute)
                    and operand.operand.func.attr in ('startswith', 'endswith')
                    and isinstance(operand.operand.func.value, ast.Name)):
                result.add(operand.operand.func.value.id)

    return frozenset(result)


def _is_always_exit(stmts: list[ast.stmt]) -> bool:
    """True if the last statement in the block always exits the current scope."""
    return bool(stmts) and isinstance(
        stmts[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break)
    )


def _iter_func_returns(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.Return]:
    """Yield every Return node inside func without descending into nested definitions.

    Uses an explicit stack so that nested FunctionDef / AsyncFunctionDef / ClassDef
    subtrees are skipped entirely — their returns belong to a different scope.
    """
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Return):
            yield node
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            pass  # skip nested definitions — they have their own scope
        else:
            stack.extend(ast.iter_child_nodes(node))


def _find_taint_source_funcs(tree: ast.AST) -> frozenset[str]:
    """Pre-pass: collect function names whose bodies contain at least one tainted return.

    Handles arbitrary-length bodies including intermediate assignments, logging
    calls, if/else branches, try/except, and early-return guards.  Does not
    descend into nested function or class definitions.

    Security-first: if any code path can return a tainted value the function is
    marked as a taint source, even if other paths return a clean sentinel.  This
    avoids false negatives at the cost of a small number of additional MEDIUM
    findings when a caller always takes the clean branch.
    """
    sources: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assignments = _collect_scope_assignments(node)
        for ret in _iter_func_returns(node):
            if (ret.value is not None
                    and _taint_of(ret.value, assignments, {}).status == TaintStatus.TAINTED):
                sources.add(node.name)
                break  # one tainted return is sufficient
    return frozenset(sources)
