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
from dataclasses import dataclass, field
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

# ── Flask debug / insecure config ─────────────────────────────────────────────

# Flask class constructors
_FLASK_CTOR_NAMES = frozenset({"Flask"})
# SSL context attribute assignments that disable certificate validation
_SSL_DISABLE_ATTRS = frozenset({"check_hostname"})   # = False → disables
_SSL_CERT_NONE_NAMES = frozenset({"CERT_NONE", "ssl.CERT_NONE"})

# insecure tempfile functions
_INSECURE_TEMPFILE_FUNCS = frozenset({"tempfile.mktemp", "mktemp"})

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

# Template constructors that compile the template at construction time.
# Passing user input directly enables SSTI ({{7*7}} execution).
_TEMPLATE_CTOR_FUNCS = frozenset({
    "jinja2.Template", "Template",          # Jinja2
    "mako.template.Template",               # Mako
    "mako.Template",
})

# ── Exploitability ─────────────────────────────────────────────────────────────

# Decorator attribute names that identify a function as a web request handler.
# When a function carries one of these decorators, UNKNOWN-taint findings inside
# it are more likely reachable from real user input (confidence stays at 0.5).
# Functions with no such marker get confidence downgraded to 0.3 and their
# [needs_review] tag is replaced with [low_reach] to indicate lower exploitability.
_WEB_ROUTE_DECORATORS = frozenset({
    # Flask / Quart / FastAPI / Starlette
    "route", "get", "post", "put", "delete", "patch", "head", "options",
    # DRF / Flask-RESTful
    "api_view", "action", "endpoint",
    # Django view decorators
    "require_GET", "require_POST", "require_http_methods", "csrf_exempt",
    "login_required", "permission_required",
})

# FastAPI / Starlette dependency-injection parameter markers.
# When used as default values in route function signatures, parameters are
# user-controlled HTTP input (query string, path, request body, header, cookie).
_FASTAPI_REQUEST_PARAMS = frozenset({
    "Query", "Path", "Body", "Form", "Header", "Cookie",
    "fastapi.Query", "fastapi.Path", "fastapi.Body",
    "fastapi.Form", "fastapi.Header", "fastapi.Cookie",
})

# Decorator attribute names that identify a function as a CLI entry point.
# Parameters of CLI functions come from the operator command line, not from
# untrusted web input — treat them as CLEAN to avoid path-traversal FPs.
_CLI_ENTRY_DECORATORS = frozenset({
    # Click / Typer
    "command", "group", "argument", "option",
    "pass_context", "pass_obj",
})

# ── Secrets ────────────────────────────────────────────────────────────────────

_SECRET_NAME_RE = re.compile(
    r"password|passwd|pwd|secret|api_key|apikey|api_secret|"
    r"access_token|auth_token|private_key|secret_key|token",
    re.IGNORECASE,
)

# Variable names that look like they accumulate HTML response content.
# _check_xss_response only fires for AugAssign targets matching this pattern,
# to avoid FPs on intermediate variables like string59781 that are never rendered.
_RESPONSE_VAR_RE = re.compile(
    r"^(?:RESPONSE|response|html|body|output|result|page|content|markup|rendered?|buf(?:fer)?|template|text)",
    re.IGNORECASE,
)
_SECRET_SKIP_RE = re.compile(
    r"example|sample|placeholder|your[_\-]|<[^>]+>|\*{2,}|"
    r"xxx|dummy|fake|change[_\-]?me|todo|test|mock",
    re.IGNORECASE,
)

# ── XSS ───────────────────────────────────────────────────────────────────────

# Django: mark_safe() / format_html() — mark content as HTML-safe, bypassing escaping.
# Flask/Jinja2: Markup() — wraps string as safe HTML, bypasses Jinja2 auto-escaping.
_UNSAFE_TEMPLATE_FUNCS = frozenset({"mark_safe", "format_html", "Markup", "markupsafe.Markup", "flask.Markup"})

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
    # Type coercions: str/bytes/repr propagate taint so that str(CLEAN) → CLEAN
    # (enables isinstance/int() guard suppression) while str(TAINTED) → TAINTED.
    "str",
    "bytes",
    "repr",
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
    # urllib Request wrapper: taint flows from the URL argument (first positional arg).
    # urllib.request.Request("https://hardcoded_url", ...) → CLEAN (URL is literal).
    # urllib.request.Request(tainted_url, ...) → TAINTED (URL is user-controlled).
    "urllib.request.Request",
    "Request",
})

# Context-specific sanitizers: protect ONLY their own sink context.
# Using these in an unrelated sink (e.g. html.escape in a SQL query) does NOT
# prevent injection — they must NOT mark the result CLEAN for every sink type.
_HTML_SANITIZER_FUNCS = frozenset({
    "html.escape", "cgi.escape", "bleach.clean", "markupsafe.escape",
})
_HTML_SANITIZER_METHODS = frozenset({"escape", "html_escape", "sanitize", "bleach_clean", "escape_for_html"})
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

# Log injection sinks: stdlib logging module functions and common logger method names.
_LOG_MODULE_FUNCS = frozenset({
    "logging.debug", "logging.info", "logging.warning", "logging.error",
    "logging.critical", "logging.exception", "logging.log",
})
_LOG_INSTANCE_METHODS = frozenset({
    "debug", "info", "warning", "error", "critical", "exception", "log",
})

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

# Phase B sentinel: Name("request") is always in _TAINTED_NAME_SOURCES, so
# _taint_of(sentinel) returns TAINTED.  Used as a stand-in for "known-tainted
# value" when evaluating module-level assignments during cross-file global scanning.
_TAINTED_MODULE_SENTINEL: ast.expr = ast.Name(id="request", ctx=ast.Load())

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
# Python module-level dunders: set by the interpreter, not by web users.
_CLEAN_DUNDER_NAMES = frozenset({
    "__file__", "__name__", "__package__", "__module__",
    "__path__", "__spec__", "__doc__", "__all__", "__version__",
})
# Path navigation/canonicalization attributes on UNKNOWN objects.
# TAINTED objects are caught by obj_taint propagation upstream; here we handle the
# UNKNOWN case (untracked parameter or variable) where web injection is unlikely.
_CLEAN_PATH_ATTRS = frozenset({
    "parent", "stem", "name", "suffix", "parts", "drive", "root",
})
# CLI argument parsers: results are operator-controlled, not web user input.
_CLI_PARSE_METHODS = frozenset({
    "parse_args", "parse_known_args",
    "parse_known_intermixed_args", "parse_intermixed_args",
})
# Path canonicalization methods: only apply to UNKNOWN objects (TAINTED caught upstream).
_PATH_CANON_METHODS = frozenset({"resolve", "absolute"})
# Filesystem traversal: yields paths that exist on disk, not arbitrary user strings.
_PATH_ITER_METHODS = frozenset({"rglob", "glob", "iterdir"})
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

# Functions that return server-side or OS-controlled values — never user input.
# Covers datetime/time (server clock) and OS-path helpers (system dirs, PID, etc.)
_CLEAN_SERVER_FUNCS = frozenset({
    # datetime / date / time — system clock values
    "datetime.now", "datetime.utcnow", "datetime.today",
    "date.today",
    "time.time", "time.monotonic", "time.perf_counter",
    "time.monotonic_ns", "time.perf_counter_ns",
    # OS / tempfile — system-determined paths and identifiers
    "tempfile.gettempdir", "tempfile.mkdtemp", "tempfile.mkstemp",
    "os.getpid", "os.getuid", "os.getgid", "os.getcwd",
    "os.cpu_count",
})

# ── XXE ───────────────────────────────────────────────────────────────────────
# xml.dom.minidom / xml.etree.ElementTree parse functions that accept a custom
# parser object.  XXE is only exploitable when external entity expansion is
# explicitly enabled (feature_external_ges=True on the SAX parser).
_XXE_PARSE_FUNCS = frozenset({
    "xml.dom.minidom.parseString", "xml.dom.minidom.parse",
    "minidom.parseString", "minidom.parse",
    "parseString", "parse",
})

# Qualifiers whose .parse() method is NOT an XML parser — suppress XXE for these.
_XXE_SAFE_PARSE_QUALIFIERS = frozenset({
    "ast", "json", "re", "argparse", "shlex", "configparser", "dateutil.parser",
    "urllib.parse", "email", "html.parser", "toml", "yaml", "tomllib",
})

# ── LDAP injection ────────────────────────────────────────────────────────────
# ldap3 conn.search() — first positional arg is base, second is the filter.
# We detect taint in the variable used as the filter argument.
_LDAP3_SEARCH_METHODS = frozenset({"search"})

# ── NoSQL injection (MongoDB / pymongo) ────────────────────────────────────────
# Methods that accept a filter dict as first arg — used for $where detection.
_MONGO_FILTER_METHODS = frozenset({
    "find", "find_one", "aggregate",
    "find_one_and_update", "find_one_and_replace", "find_one_and_delete",
    "count_documents", "distinct", "delete_one", "delete_many",
    "update_one", "update_many",
})
# Subset of methods with unambiguously MongoDB-specific names (for tainted-filter detection).
_MONGO_SPECIFIC_METHODS = frozenset({
    "find_one_and_update", "find_one_and_replace", "find_one_and_delete",
    "count_documents",
})

# ── Email header injection (CWE-93) ───────────────────────────────────────────
# Low-level SMTP send functions where headers are embedded in the raw message.
_SMTP_SEND_FUNCS = frozenset({
    "sendmail", "send_message",                 # smtplib.SMTP
    "send_mail", "send_mass_mail",              # Django
})
# Header field names that an attacker can abuse with \r\n injection.
_DANGEROUS_HEADER_KEYS = frozenset({
    "subject", "to", "from", "cc", "bcc",
    "reply-to", "x-mailer", "content-type",
})

# ── cross-file pre-scan summary (Phase C) ─────────────────────────────────────

@dataclass
class CrossFileTaintSummary:
    """Global taint information built by build_cross_file_summary() before per-file analysis.

    Phase C improvement: _interprocedural_taint_sources is pre-seeded with
    global_taint_sources before Phase B (module-global scanning) runs, so
    function-call chains like ``config.HOST = get_host()`` are correctly resolved
    even when get_host() is defined in a transitively imported file.

    Phase E improvement: confirmed_tainted_params tracks function parameters that are
    confirmed to receive tainted input from callers, enabling HIGH-confidence findings
    in callee functions even when analyzed without their calling context.
    """
    global_taint_sources: frozenset[str] = field(default_factory=frozenset)
    tainted_globals: dict[str, frozenset[str]] = field(default_factory=dict)
    confirmed_tainted_params: dict[str, frozenset[int]] = field(default_factory=dict)
    confirmed_clean_params: dict[str, frozenset[int]] = field(default_factory=dict)


# ── interprocedural taint (per-file, single-threaded) ─────────────────────────
# Both globals are updated by PythonASTAnalyzer.analyze() before each file visit.
_interprocedural_taint_sources: frozenset[str] = frozenset()
_local_func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

# ── cross-file taint context (thread-local) ────────────────────────────────────
# Set once per file analysis via set_cross_file_context(); read in analyze() and _taint_of().
_cross_file_local = _threading.local()


def set_cross_file_context(
    all_contents: dict[str, str],
    summary: CrossFileTaintSummary | None = None,
) -> None:
    """Register the full {relative_path: content} map for cross-file taint resolution.

    *summary* is the optional Phase C pre-scan result from build_cross_file_summary().
    When provided, _interprocedural_taint_sources is pre-seeded with globally-known
    taint sources before per-file analysis, enabling resolution of function-call chains
    in module-level variable assignments (e.g. ``ALLOWED_HOST = get_host()``).

    Uses thread-local storage so parallel scan workers don't interfere with each other.
    """
    _cross_file_local.all_contents = all_contents
    _cross_file_local.cf_summary = summary


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
) -> tuple[
    dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]],
    dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]],
    dict[str, str],
]:
    """Parse import statements in *content* and return a 3-tuple:

    1. ``remote_funcs`` — ``{imported_name: (FunctionDef_node, source_file_path)}``
       for module-level functions.
    2. ``class_methods`` — ``{method_name: [FunctionDef_node, ...]}``
       for class methods found in imported project-local modules.
    3. ``remote_tainted_globals`` — ``{imported_alias: source_file_path}``
       Phase B: module-level variables that are assigned from taint sources.
       E.g. ``ALLOWED_HOST = request.META.get("HTTP_HOST")`` in config.py → the
       imported name is considered TAINTED in the importing file.

    Handles ``from X import Y``, ``from X import Y as Z``, ``import X``,
    ``from X import *``.  Only resolves project-local files (in *all_contents*).
    """
    remote: dict[str, tuple] = {}
    class_methods: dict[str, list] = {}
    remote_globals: dict[str, str] = {}      # Phase B: {imported_alias: source_file}
    module_tainted_globals: dict[str, set[str]] = {}  # {module_file: {tainted_var, ...}}
    seen_module_files: set[str] = set()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return remote, class_methods, remote_globals

    def _collect_module(module_file: str, depth: int = 1) -> None:
        """Collect class methods (all depths) and module-level functions (depth > 1)
        from *module_file*, then recursively follow its imports up to depth 4.

        Phase A — transitive resolution: depth > 1 functions are added to *remote*
        with their original names so that calls inside directly-imported functions
        can be resolved by Phase 4 (cross-file passthrough).

        Phase B — module global scanning: after recursion (DFS-first so sub-files'
        tainted globals are already known), evaluate module-level Assign statements
        with _taint_of to find variables assigned from taint sources.  Cross-file
        chains (HOST = imported_tainted_var) are handled via sentinel substitution.
        """
        if module_file in seen_module_files or depth > 4:
            return
        seen_module_files.add(module_file)
        module_content = all_contents.get(module_file, "")
        try:
            module_tree = ast.parse(module_content)
        except SyntaxError:
            return
        # Collect class methods into class_methods dict
        for class_node in module_tree.body:
            if not isinstance(class_node, ast.ClassDef):
                continue
            for item in class_node.body:
                if (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name != "__init__"
                        and not item.name.startswith("__")):
                    class_methods.setdefault(item.name, []).append(item)
        # Phase A: add module-level functions at depth > 1 so callee bodies can be
        # resolved when Phase 4 evaluates a directly-imported function's body.
        # Don't overwrite direct-import entries (they have correct alias keys).
        if depth > 1:
            for stmt in module_tree.body:
                if (isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and stmt.name not in remote):
                    remote[stmt.name] = (stmt, module_file)
        # Recursively follow this module's imports (DFS-first; cycle-safe via seen_module_files)
        if depth < 4:
            for imp in ast.walk(module_tree):
                if isinstance(imp, ast.ImportFrom) and imp.module:
                    sub = _resolve_module_to_file(imp.module, module_file, all_contents)
                    if sub:
                        _collect_module(sub, depth + 1)
                elif isinstance(imp, ast.Import):
                    for sub_alias in imp.names:
                        sub = _resolve_module_to_file(
                            sub_alias.name, module_file, all_contents
                        )
                        if sub:
                            _collect_module(sub, depth + 1)
        # Phase B: scan module-level variable assignments.
        # Sub-files have already been processed (DFS), so module_tainted_globals
        # for their files is populated — enabling cross-file variable chains.
        _import_taint: dict[str, ast.expr] = {}
        for _s in module_tree.body:
            if isinstance(_s, ast.ImportFrom) and _s.module:
                _sf = _resolve_module_to_file(_s.module, module_file, all_contents)
                if _sf and _sf in module_tainted_globals:
                    for _al in _s.names:
                        _as = _al.asname or _al.name
                        if _al.name in module_tainted_globals[_sf] or _al.name == "*":
                            _import_taint[_as] = _TAINTED_MODULE_SENTINEL
        _this_tainted: set[str] = set()
        for _s in module_tree.body:
            if isinstance(_s, ast.Assign):
                if _taint_of(_s.value, _import_taint, {}).status == TaintStatus.TAINTED:
                    for _t in _s.targets:
                        if isinstance(_t, ast.Name):
                            _this_tainted.add(_t.id)
            elif isinstance(_s, ast.AnnAssign) and _s.value is not None:
                if _taint_of(_s.value, _import_taint, {}).status == TaintStatus.TAINTED:
                    if isinstance(_s.target, ast.Name):
                        _this_tainted.add(_s.target.id)
        module_tainted_globals[module_file] = _this_tainted

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            module_file = _resolve_module_to_file(node.module, file_path, all_contents)
            if not module_file:
                continue
            _collect_module(module_file)
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
            # Phase B: map tainted module globals to imported aliases
            tainted_in_module = module_tainted_globals.get(module_file, set())
            for alias in node.names:
                name, as_name = alias.name, alias.asname or alias.name
                if name == "*":
                    for fn, fn_node in module_funcs.items():
                        if not fn.startswith("_"):
                            remote[fn] = (fn_node, module_file)
                    for tname in tainted_in_module:
                        if not tname.startswith("_"):
                            remote_globals[tname] = module_file
                elif name in module_funcs:
                    remote[as_name] = (module_funcs[name], module_file)
                if name != "*" and name in tainted_in_module:
                    remote_globals[as_name] = module_file

        elif isinstance(node, ast.Import):
            for alias in node.names:
                module_file = _resolve_module_to_file(alias.name, file_path, all_contents)
                if not module_file:
                    continue
                _collect_module(module_file)
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

    return remote, class_methods, remote_globals


def _callee_returns_tainted(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    param_assignments: dict[str, ast.expr],
    _depth: int,
) -> bool:
    """Return True if any return path of func_def yields a TAINTED value given param_assignments."""
    if _depth > 14:
        return False
    # Recursion guard: prevent exponential blow-up when a function appears in its own
    # return expressions (e.g. _taint_of calls itself → 51 returns × N depths).
    _guard = getattr(_cross_file_local, "_callee_analyzing", None)
    if _guard is None:
        _guard = set()
        _cross_file_local._callee_analyzing = _guard
    if func_def.name in _guard:
        return False
    _guard.add(func_def.name)
    try:
        merged = {**_collect_scope_assignments(func_def), **param_assignments}
        for ret in _iter_func_returns(func_def):
            if ret.value is not None:
                if _taint_of(ret.value, merged, {}, _depth).status == TaintStatus.TAINTED:
                    return True
        return False
    finally:
        _guard.discard(func_def.name)


def _callee_return_taint_status(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    param_assignments: dict[str, ast.expr],
    _depth: int,
) -> TaintStatus:
    """Return the worst-case TaintStatus across all return paths of func_def.

    Unlike _callee_returns_tainted (bool), this distinguishes CLEAN (provably
    safe constant return) from UNKNOWN (calls unresolved external APIs), which
    lets class-method resolution avoid the CLEAN-assumption FN where a method
    that wraps an opaque external call is incorrectly treated as safe.
    """
    if _depth > 14:
        return TaintStatus.UNKNOWN
    _guard = getattr(_cross_file_local, "_callee_analyzing", None)
    if _guard is None:
        _guard = set()
        _cross_file_local._callee_analyzing = _guard
    if func_def.name in _guard:
        return TaintStatus.UNKNOWN
    _guard.add(func_def.name)
    try:
        merged = {**_collect_scope_assignments(func_def), **param_assignments}
        worst = TaintStatus.CLEAN
        for ret in _iter_func_returns(func_def):
            if ret.value is not None:
                status = _taint_of(ret.value, merged, {}, _depth).status
                if _TAINT_ORDER[status] > _TAINT_ORDER[worst]:
                    worst = status
        return worst
    finally:
        _guard.discard(func_def.name)


def _func_is_web_entry(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if *node* is likely a web request handler.

    Checks two signals:
    - A decorator whose attribute/name is in _WEB_ROUTE_DECORATORS (e.g. @app.route, @login_required).
    - A parameter named 'request' (Django/DRF/Flask-class-based-views pattern).
    """
    for dec in node.decorator_list:
        name = ""
        if isinstance(dec, ast.Attribute):
            name = dec.attr
        elif isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Call):
            inner = dec.func
            if isinstance(inner, ast.Attribute):
                name = inner.attr
            elif isinstance(inner, ast.Name):
                name = inner.id
        if name in _WEB_ROUTE_DECORATORS:
            return True
    return any(a.arg == "request" for a in node.args.args)


def _func_is_cli_entry(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if *node* is a CLI entry point (Click/Typer decorated).

    Parameters of CLI functions come from the operator command line, not from
    untrusted web input, so they should be treated as CLEAN.
    """
    for dec in node.decorator_list:
        name = ""
        if isinstance(dec, ast.Attribute):
            name = dec.attr
        elif isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Call):
            inner = dec.func
            if isinstance(inner, ast.Attribute):
                name = inner.attr
            elif isinstance(inner, ast.Name):
                name = inner.id
        if name in _CLI_ENTRY_DECORATORS:
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

        # Phase C: pre-seed _interprocedural_taint_sources from global pre-scan summary.
        # This MUST happen before _build_remote_func_defs so Phase B (module-global
        # scanning inside _collect_module) can see globally-known taint source functions.
        # Without this, Phase B evaluates "ALLOWED_HOST = get_host()" but get_host is not
        # in _interprocedural_taint_sources yet → assignment falsely returns UNKNOWN.
        _cf_summary: CrossFileTaintSummary | None = getattr(
            _cross_file_local, "cf_summary", None
        )
        _global_sources: frozenset[str] = (
            _cf_summary.global_taint_sources if _cf_summary else frozenset()
        )
        _interprocedural_taint_sources = _global_sources

        # Cross-file taint: build remote function defs from thread-local context.
        # set_cross_file_context() is called by the scanner before parallel analysis.
        _all = getattr(_cross_file_local, "all_contents", None)
        if _all:
            _rfd, _rcm, _rtg = _build_remote_func_defs(file_path, content, _all)
            # Phase C safety-net: augment _rtg with summary's pre-computed tainted globals
            # for direct imports the current file makes from any source file.
            if _cf_summary and _cf_summary.tainted_globals:
                for _imp in tree.body:
                    if isinstance(_imp, ast.ImportFrom) and _imp.module:
                        _src_fp = _resolve_module_to_file(_imp.module, file_path, _all)
                        if _src_fp and _src_fp in _cf_summary.tainted_globals:
                            _src_tainted = _cf_summary.tainted_globals[_src_fp]
                            for _al in _imp.names:
                                _as = _al.asname or _al.name
                                if _al.name in _src_tainted and _as not in _rtg:
                                    _rtg[_as] = _src_fp
            _cross_file_local.remote_func_defs = _rfd
            _cross_file_local.remote_class_methods = _rcm
            _cross_file_local.remote_tainted_globals = _rtg
            if _rfd:
                # Phase A: run fixed-point on local + ALL transitively-reachable remote
                # functions together.  A single combined pass lets the fixed-point
                # iteration resolve multi-hop chains:
                #   Pass 1: utils.get_user_id() → request.args.get() → TAINTED
                #   Pass 2: helpers.fetch_user() → get_user_id() (now in sources) → TAINTED
                _all_func_nodes = (
                    list(_local_func_defs.values())
                    + [_n for _n, _ in _rfd.values()]
                )
                _fake_combined = ast.Module(body=_all_func_nodes, type_ignores=[])
                _per_file_sources = _find_taint_source_funcs(_fake_combined)
                _interprocedural_taint_sources = _global_sources | _per_file_sources
            else:
                _per_file_sources = _find_taint_source_funcs(tree)
                _interprocedural_taint_sources = _global_sources | _per_file_sources
        else:
            _per_file_sources = _find_taint_source_funcs(tree)
            _interprocedural_taint_sources = _global_sources | _per_file_sources
            _cross_file_local.remote_func_defs = {}
            _cross_file_local.remote_class_methods = {}
            _cross_file_local.remote_tainted_globals = {}

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
        self._interproc_visited: set[tuple] = set()  # dedup: (func_name, tainted_param_indices)
        self._current_func_is_web_entry: bool = False  # exploitability filter

    # ── scope tracking ─────────────────────────────────────────────────────────

    def visit_Module(self, node: ast.Module) -> None:
        assigns = _collect_module_level_assignments(node)
        # Store in thread-local so _taint_of can use it as fallback inside functions.
        _cross_file_local.module_level_assignments = assigns
        self._assignments = assigns
        self.generic_visit(node)

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
        saved_web = self._current_func_is_web_entry
        self._assignments = _collect_scope_assignments(node)
        # CLI entry functions: parameters come from the operator command line,
        # not from untrusted web input.  Inject CLEAN sentinels for any
        # parameter not already assigned in the body.
        if _func_is_cli_entry(node):
            _clean = ast.Constant(value=0)
            for arg in node.args.args:
                if arg.arg not in self._assignments and arg.arg != "self":
                    self._assignments[arg.arg] = _clean
        else:
            # FastAPI / Starlette: inject TAINTED sentinels for params that use
            # dependency-injection markers (Query(...), Path(...), Body(...), etc.).
            # These parameters are user-controlled HTTP input even though they don't
            # access `request.*` directly.
            if _func_is_web_entry(node):
                _defaults_map: dict[str, ast.expr | None] = {}
                _args = node.args
                # Positional args with defaults: last N args pair with last N defaults
                _all_args = [a for a in _args.args if a.arg != "self"]
                _n_defaults = len(_args.defaults)
                for _ai, _arg in enumerate(_all_args):
                    _def_idx = _ai - (len(_all_args) - _n_defaults)
                    if _def_idx >= 0:
                        _defaults_map[_arg.arg] = _args.defaults[_def_idx]
                # kwonly args
                for _kwa, _kwd in zip(_args.kwonlyargs, _args.kw_defaults):
                    _defaults_map[_kwa.arg] = _kwd

                for _pname, _default in _defaults_map.items():
                    if _default is None or _pname in self._assignments:
                        continue
                    _dn = _full_name(_default.func) if isinstance(_default, ast.Call) else None
                    if _dn in _FASTAPI_REQUEST_PARAMS:
                        self._assignments[_pname] = _TAINTED_MODULE_SENTINEL

            # Phase E: if cross-file summary confirms that this function's parameter(s)
            # receive tainted input from callers, inject TAINTED sentinels so the
            # standalone analysis of this function produces HIGH-confidence findings
            # instead of low_reach (0.3).  Only inject for params NOT already
            # assigned in the body (body assignments take precedence).
            _cf_sum = getattr(_cross_file_local, "cf_summary", None)
            if _cf_sum is not None:
                _conf = _cf_sum.confirmed_tainted_params.get(node.name, frozenset())
                if _conf:
                    _params = [a for a in node.args.args if a.arg != "self"]
                    for _idx in _conf:
                        if _idx < len(_params):
                            _pname = _params[_idx].arg
                            if _pname not in self._assignments:
                                self._assignments[_pname] = _TAINTED_MODULE_SENTINEL

                # Phase F: inject CLEAN sentinels for params confirmed to receive
                # only CLI-originated (operator-controlled) input.  TAINTED takes
                # precedence — only inject CLEAN if not already set to TAINTED.
                _conf_clean = _cf_sum.confirmed_clean_params.get(node.name, frozenset())
                if _conf_clean:
                    _params_f = [a for a in node.args.args if a.arg != "self"]
                    _clean_sentinel = ast.Constant(value=0)
                    for _idx in _conf_clean:
                        if _idx < len(_params_f):
                            _pname = _params_f[_idx].arg
                            if _pname not in self._assignments:
                                self._assignments[_pname] = _clean_sentinel

        _cf_sum_web = getattr(_cross_file_local, "cf_summary", None)
        _has_confirmed_params = bool(
            _cf_sum_web and _cf_sum_web.confirmed_tainted_params.get(node.name)
        )
        self._canonicalized_paths = _find_canonicalized_paths(node)
        self._current_func_is_web_entry = _func_is_web_entry(node) or _has_confirmed_params
        self._visit_stmts(node.body)
        self._assignments = saved
        self._canonicalized_paths = saved_canon
        self._current_func_is_web_entry = saved_web

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
        self._check_tls_verify(node)
        self._check_open_redirect(node)
        self._check_ssti(node)
        self._check_weak_crypto(node)
        self._check_insecure_rng_call(node)
        self._check_xxe(node)
        self._check_ldap_injection(node)
        self._check_xpath_injection(node)
        self._check_nosql_injection(node)
        self._check_email_header_injection(node)
        self._check_insecure_cookie(node)
        self._check_log_injection(node)
        self._check_flask_debug(node)
        self._check_jinja_autoescape(node)
        self._check_insecure_tempfile(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_secret(target, node.value, node)
            self._check_insecure_rng(target, node.value, node)
            self._check_ssl_ctx_assign(target, node.value, node)
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

        # paramiko/fabric ssh.exec_command(tainted_cmd) — remote SSH command injection
        elif attr == "exec_command" and isinstance(node.func, ast.Attribute):
            if not node.args:
                return
            taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            if any(s in _CMD_SANITIZER_FUNCS for s in (taint.sanitizers or [])):
                return
            sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
            label = "tainted" if taint.status == TaintStatus.TAINTED else "non-literal"
            self._add(node, VulnType.COMMAND_INJECTION, sev, "AST-CMD-006",
                      f"exec_command() called with {label} command — SSH remote command injection"
                      f" risk: {taint.reason}",
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

        # open(path) / codecs.open(path, …) / io.open(path, …) / flask.send_file(path) — file-open sinks
        # send_from_directory(dir, file) is safe (uses werkzeug safe_join internally) — excluded.
        _is_open = (
            (isinstance(node.func, ast.Name) and node.func.id in ("open", "send_file"))
            or full in ("codecs.open", "io.open", "flask.send_file")
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
        arg = node.args[0]
        if _is_const(arg):
            return
        taint = _taint_of(arg, self._assignments, self._class_attrs)
        if taint.status == TaintStatus.CLEAN:
            return
        if taint.status == TaintStatus.TAINTED:
            self._add(node, VulnType.XSS, Severity.HIGH, "AST-XSS-001",
                      f"{name}() called with user-controlled input — bypasses HTML auto-escaping:"
                      f" {taint.reason}",
                      taint)
        else:
            self._add(node, VulnType.XSS, Severity.MEDIUM, "AST-XSS-001",
                      f"[needs_review] {name}() called with a non-literal value —"
                      " verify no user input reaches this")

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

    # ── SSL/TLS certificate verification bypass ────────────────────────────────

    def _check_tls_verify(self, node: ast.Call) -> None:
        full = _full_name(node.func)
        if full not in _HTTP_CLIENT_FUNCS:
            return
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "AST-TLS-001",
                          f"{full}(..., verify=False) disables SSL/TLS certificate verification — "
                          "allows MITM attacks; remove verify=False or pin a CA bundle")
                return

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

        # Flask url_for() generates server-side URLs from endpoint names — always safe.
        if (isinstance(url_arg, ast.Call)
                and _full_name(url_arg.func) in {"url_for", "flask.url_for"}):
            return

        taint = _taint_of(url_arg, self._assignments, self._class_attrs)

        if taint.status == TaintStatus.CLEAN:
            return

        # Suppress when the URL is validated via urlparse+allowlist or Django guard —
        # applies for both TAINTED and UNKNOWN taint.
        _REDIRECT_VALIDATORS = {
            "urllib.parse.urlparse", "urlparse",
            "url_has_allowed_host_and_scheme",
            "django.utils.http.url_has_allowed_host_and_scheme",
        }
        if (isinstance(url_arg, ast.Name)
                and any(
                    isinstance(v, ast.Call)
                    and _full_name(v.func) in _REDIRECT_VALIDATORS
                    and v.args
                    and isinstance(v.args[0], ast.Name)
                    and v.args[0].id == url_arg.id
                    for v in self._assignments.values()
                    if isinstance(v, ast.Call)
                )):
            self._add_suppressed(node, VulnType.OPEN_REDIRECT,
                                 "AST-REDIR-001", "url_whitelist_validation", taint)
            return

        if taint.status == TaintStatus.TAINTED:
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

        full = _full_name(node.func) or ""

        if name in _TEMPLATE_RENDER_FUNCS:
            if not node.args or _is_const(node.args[0]):
                return
            taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            self._add(node, VulnType.SSTI, Severity.CRITICAL, "AST-SSTI-001",
                      f"{name}() renders a non-literal template string - "
                      "user-controlled template content leads to RCE via SSTI",
                      taint)

        elif name == "from_string":
            if not node.args or _is_const(node.args[0]):
                return
            taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
            self._add(node, VulnType.SSTI, sev, "AST-SSTI-002",
                      f"Environment.from_string() with {'tainted' if taint.status == TaintStatus.TAINTED else 'non-literal'} template - "
                      "user-controlled template content leads to RCE via SSTI",
                      taint)

        elif full in _TEMPLATE_CTOR_FUNCS or name in _TEMPLATE_CTOR_FUNCS:
            if not node.args or _is_const(node.args[0]):
                return
            taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            sev = Severity.CRITICAL if taint.status == TaintStatus.TAINTED else Severity.HIGH
            self._add(node, VulnType.SSTI, sev, "AST-SSTI-003",
                      f"{name}() constructed with {'tainted' if taint.status == TaintStatus.TAINTED else 'non-literal'} template string — "
                      "template constructors compile user input as executable template code; RCE risk",
                      taint)

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
        # Exclude non-XML parsers that share the name "parse" (e.g. ast.parse, json.loads)
        obj_qualifier = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            obj_qualifier = node.func.value.id
        if obj_qualifier in _XXE_SAFE_PARSE_QUALIFIERS:
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

    # ── XPath injection ────────────────────────────────────────────────────────

    def _check_xpath_injection(self, node: ast.Call) -> None:
        """Detect XPath injection via tainted XPath expression strings.

        Three real-world patterns (all from lxml / elementpath ecosystem):
          root.xpath(query)               — lxml Element method, arg 0 is expression
          elementpath.select(root, query) — second positional arg is expression
          lxml.etree.XPath(query)         — XPath object constructor, arg 0 is expression
        """
        full = _full_name(node.func)
        attr = _attr_name(node.func)

        # root.xpath(tainted_expr)
        if attr == "xpath" and isinstance(node.func, ast.Attribute):
            if not node.args:
                return
            taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            if _expr_apos_replaced(node.args[0], self._assignments):
                return
            sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
            self._add(node, VulnType.XPATH_INJECTION, sev, "AST-XPATH-001",
                      f"lxml .xpath() called with {'tainted' if sev == Severity.HIGH else 'non-literal'} "
                      f"expression — XPath injection allows data extraction bypass: {taint.reason}",
                      taint)

        # elementpath.select(root, tainted_query)
        elif full == "elementpath.select":
            if len(node.args) < 2:
                return
            taint = _taint_of(node.args[1], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            if _expr_apos_replaced(node.args[1], self._assignments):
                return
            sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
            self._add(node, VulnType.XPATH_INJECTION, sev, "AST-XPATH-002",
                      f"elementpath.select() called with {'tainted' if sev == Severity.HIGH else 'non-literal'} "
                      f"XPath query — injection allows data extraction bypass: {taint.reason}",
                      taint)

        # lxml.etree.XPath(tainted_expr) constructor
        elif full == "lxml.etree.XPath":
            if not node.args:
                return
            taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
            if taint.status == TaintStatus.CLEAN:
                return
            if _expr_apos_replaced(node.args[0], self._assignments):
                return
            sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
            self._add(node, VulnType.XPATH_INJECTION, sev, "AST-XPATH-003",
                      f"lxml.etree.XPath() constructed with {'tainted' if sev == Severity.HIGH else 'non-literal'} "
                      f"expression — XPath injection allows data extraction bypass: {taint.reason}",
                      taint)

    # ── NoSQL injection ─────────────────────────────────────────────────────────

    def _check_nosql_injection(self, node: ast.Call) -> None:
        """Detect NoSQL injection in MongoDB (pymongo) operations.

        Two patterns:
          collection.find({"$where": tainted})  — JavaScript execution in MongoDB → CRITICAL
          collection.count_documents(tainted)    — tainted filter on MongoDB-specific sinks → HIGH
        """
        if not isinstance(node.func, ast.Attribute):
            return
        attr = node.func.attr
        if attr not in _MONGO_FILTER_METHODS:
            return
        if not node.args:
            return
        filter_arg = node.args[0]

        # Pattern 1: {"$where": tainted} — JS execution (always CRITICAL, method agnostic)
        if isinstance(filter_arg, ast.Dict):
            for key, val in zip(filter_arg.keys, filter_arg.values):
                if isinstance(key, ast.Constant) and key.value == "$where":
                    if _is_const(val):
                        return
                    taint = _taint_of(val, self._assignments, self._class_attrs)
                    if taint.status == TaintStatus.CLEAN:
                        return
                    self._add(node, VulnType.NOSQL_INJECTION, Severity.CRITICAL,
                              "AST-NOSQL-001",
                              f"MongoDB {attr}() with tainted $where — executes arbitrary JavaScript "
                              f"on the database server; allows full collection access: {taint.reason}",
                              taint)
            return  # dict literal without $where — skip to avoid FPs

        # Pattern 2: entire filter arg is tainted (MongoDB-specific method names only)
        if attr not in _MONGO_SPECIFIC_METHODS:
            return
        if _is_const(filter_arg):
            return
        taint = _taint_of(filter_arg, self._assignments, self._class_attrs)
        if taint.status == TaintStatus.CLEAN:
            return
        sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
        self._add(node, VulnType.NOSQL_INJECTION, sev, "AST-NOSQL-002",
                  f"MongoDB {attr}() called with {'tainted' if sev == Severity.HIGH else 'non-literal'} "
                  f"filter — NoSQL injection may allow query manipulation: {taint.reason}",
                  taint)

    # ── Email header injection (CWE-93) ───────────────────────────────────────

    def _check_email_header_injection(self, node: ast.Call) -> None:
        """Detect email header injection via smtplib / Django mail (CWE-93).

        Two patterns:
        1. sendmail/send_mail/send() called with a tainted argument (subject,
           to, from, or the raw message body which contains headers).
        2. msg[header_key] = tainted_value — direct header assignment on an
           email.message.Message or MIMEText/MIMEMultipart object.
        """
        # Pattern 1: send function called with tainted args.
        # Covers method calls (server.sendmail) and direct calls (send_mail).
        func_attr = None
        if isinstance(node.func, ast.Attribute):
            func_attr = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_attr = node.func.id
        if func_attr not in _SMTP_SEND_FUNCS:
            return

        # Check positional args 0-3 (from, to, msg for smtplib; subject for Django)
        taint_args = [
            _taint_of(arg, self._assignments, self._class_attrs)
            for arg in node.args[:4]
        ]
        # Also check keyword args: subject=, to=, from_email=, recipient_list=, msg=
        for kw in node.keywords:
            if kw.arg in ("subject", "to", "from_email", "recipient_list", "msg"):
                taint_args.append(
                    _taint_of(kw.value, self._assignments, self._class_attrs)
                )
        for taint in taint_args:
            if taint.status == TaintStatus.CLEAN:
                continue
            sev = Severity.HIGH if taint.status == TaintStatus.TAINTED else Severity.MEDIUM
            rule = "AST-EMAIL-001" if sev == Severity.HIGH else "AST-EMAIL-002"
            prefix = "" if sev == Severity.HIGH else "[needs_review] "
            self._add(
                node, VulnType.EMAIL_INJECTION, sev, rule,
                f"{prefix}{func_attr}() called with {'tainted' if sev == Severity.HIGH else 'dynamic'} "
                f"argument — header injection allows spam relay or phishing: {taint.reason}",
                taint,
            )
            return  # one finding per call is enough

        # Pattern 2: msg[header_key] = tainted  (Subscript assignment via visit_Assign,
        # but we can detect it here via ast.walk on enclosing assign — skip for now;
        # this pattern is caught by visit_Assign in a future pass if needed)

    # ── Insecure cookie ────────────────────────────────────────────────────────

    def _check_insecure_cookie(self, node: ast.Call) -> None:
        """Detect Flask response.set_cookie() with secure=False (CWE-614).

        Only flags explicit secure=False — the unambiguous developer mistake.
        Missing secure= is not flagged (too many FPs in non-HTTPS dev contexts
        and non-sensitive cookies).
        """
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr != "set_cookie":
            return
        for kw in node.keywords:
            if kw.arg == "secure" and isinstance(kw.value, ast.Constant):
                if kw.value.value is False:
                    self._add(node, VulnType.INSECURE_COOKIE, Severity.MEDIUM,
                              "AST-COOKIE-001",
                              "response.set_cookie(secure=False) — cookie transmitted over plain HTTP; "
                              "set secure=True to restrict to HTTPS connections (CWE-614)")
                    return

    # ── Log injection ──────────────────────────────────────────────────────────

    def _check_log_injection(self, node: ast.Call) -> None:
        """Detect log injection: user-controlled data passed to logging calls.

        Fires only when the first argument is TAINTED (confirmed user input).
        Rationale: unsanitized user input in logs allows attackers to forge log
        entries by injecting newlines — e.g. '\nERROR: admin logged in as root'.
        Fix: strip or escape newlines before logging, or use structured logging.
        """
        full = _full_name(node.func)
        attr = _attr_name(node.func)
        is_log_call = (
            full in _LOG_MODULE_FUNCS
            or (attr in _LOG_INSTANCE_METHODS and isinstance(node.func, ast.Attribute))
        )
        if not is_log_call or not node.args:
            return
        taint = _taint_of(node.args[0], self._assignments, self._class_attrs)
        if taint.status != TaintStatus.TAINTED:
            return
        self._add(node, VulnType.LOG_INJECTION, Severity.MEDIUM, "AST-LOG-001",
                  f"{full or f'.{attr}'}() logs tainted user input — enables log forging "
                  f"via newline injection; strip \\n/\\r or use structured logging: {taint.reason}",
                  taint)

    # ── Flask debug mode ──────────────────────────────────────────────────────

    def _check_flask_debug(self, node: ast.Call) -> None:
        """Detect Flask app launched with debug=True — exposes Werkzeug RCE console."""
        func_name = _attr_name(node.func)
        full = _full_name(node.func)
        is_flask_ctor = full in _FLASK_CTOR_NAMES or func_name in _FLASK_CTOR_NAMES
        is_run = func_name == "run"
        if not (is_flask_ctor or is_run):
            return
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self._add(node, VulnType.MISSING_AUTHORIZATION, Severity.CRITICAL,
                          "AST-MISS-001",
                          "Flask app running with debug=True — Werkzeug interactive debugger "
                          "allows unauthenticated remote code execution in production; "
                          "set debug=False or use FLASK_DEBUG=0 env var")
                return

    # ── Jinja2 autoescape disabled ─────────────────────────────────────────────

    def _check_jinja_autoescape(self, node: ast.Call) -> None:
        """Detect Jinja2 Environment(autoescape=False) — XSS via unescaped templates."""
        full = _full_name(node.func)
        attr = _attr_name(node.func)
        if full not in ("jinja2.Environment", "Environment") and attr != "Environment":
            return
        for kw in node.keywords:
            if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add(node, VulnType.XSS, Severity.HIGH, "AST-XSS-003",
                          "Jinja2 Environment created with autoescape=False — all template "
                          "variables are rendered unescaped; use autoescape=True or "
                          "jinja2.select_autoescape([\"html\", \"xml\"])")
                return

    # ── Insecure tempfile ─────────────────────────────────────────────────────

    def _check_insecure_tempfile(self, node: ast.Call) -> None:
        """Detect tempfile.mktemp() — TOCTOU race condition in temp file creation."""
        full = _full_name(node.func)
        if full not in _INSECURE_TEMPFILE_FUNCS:
            return
        self._add(node, VulnType.RACE_CONDITION, Severity.MEDIUM, "AST-RACE-001",
                  "tempfile.mktemp() returns a filename without opening it atomically — "
                  "another process can create the file between mktemp() and open() (TOCTOU); "
                  "use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead")

    # ── SSL context attribute assignments ──────────────────────────────────────

    def _check_ssl_ctx_assign(self, target: ast.expr, value: ast.expr, node: ast.AST) -> None:
        """Detect ssl.SSLContext assignments that disable certificate validation."""
        if not isinstance(target, ast.Attribute):
            return
        attr = target.attr
        # ctx.check_hostname = False → disables hostname verification
        if attr == "check_hostname" and isinstance(value, ast.Constant) and value.value is False:
            self._add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "AST-SSL-001",
                      "SSL context check_hostname set to False — disables hostname "
                      "verification, allowing MITM attacks; keep check_hostname=True")
        # ctx.verify_mode = ssl.CERT_NONE → disables cert verification entirely
        if attr == "verify_mode":
            val_name = _full_name(value) or ""
            if val_name in _SSL_CERT_NONE_NAMES:
                self._add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.CRITICAL, "AST-SSL-002",
                          "SSL context verify_mode set to CERT_NONE — disables ALL certificate "
                          "validation, allowing any server to be impersonated (MITM); "
                          "use ssl.CERT_REQUIRED")

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
        # Only fire for variable names that look like response/output accumulators.
        # Avoids FPs on intermediate variables (e.g. string59781 += param) that are
        # never rendered as HTML.
        if not _RESPONSE_VAR_RE.match(node.target.id):
            return
        # Check taint of the value being appended
        taint = _taint_of(node.value, self._assignments, self._class_attrs)
        if taint.status != TaintStatus.TAINTED:
            return
        # Suppress if an HTML-specific sanitizer was applied.
        # Sanitizer names may be stored as fully-qualified paths (e.g. "helpers.utils.escape_for_html"),
        # so also check the last component against _HTML_SANITIZER_METHODS.
        if any(
            s in _HTML_SANITIZER_FUNCS
            or s in _HTML_SANITIZER_METHODS
            or s.rsplit(".", 1)[-1] in _HTML_SANITIZER_METHODS
            for s in (taint.sanitizers or [])
        ):
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

        # Exploitability filter: UNKNOWN-taint MEDIUM findings in functions with no
        # detected web entry-point markers are less likely to be reachable from
        # user-controlled HTTP input.  Downgrade severity to LOW, lower confidence,
        # and swap [needs_review] → [low_reach] in the description.
        # Restricted to MEDIUM severity: CRITICAL/HIGH with UNKNOWN taint (e.g.
        # pickle.loads, yaml.load) are always high-risk regardless of call site.
        confidence = taint_info.confidence if taint_info else 1.0
        if (taint_info is not None
                and taint_info.status == TaintStatus.UNKNOWN
                and severity == Severity.MEDIUM
                and not self._current_func_is_web_entry):
            severity = Severity.LOW
            confidence = 0.3
            description = description.replace("[needs_review]", "[low_reach]", 1)

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
            confidence=confidence,
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
        tainted_indices = tuple(
            i for i, t in enumerate(arg_taints) if t.status == TaintStatus.TAINTED
        )
        if not tainted_indices:
            return
        visit_key = (func_def.name, tainted_indices)
        if visit_key in self._interproc_visited:
            return
        self._interproc_visited.add(visit_key)
        param_assignments: dict[str, ast.expr] = {}
        for i, param in enumerate(func_def.args.args):
            if i in tainted_indices:
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
        """Walk stmt for calls to local or remote functions that receive ≥1 tainted argument.

        When found, re-analyse the callee's body with those params marked as tainted
        so that sink checks inside the callee fire at the correct (higher) severity.
        For remote (cross-file) callees, file_path and lines are temporarily swapped
        so findings are attributed to the callee's source file at the correct line.
        Skips functions already on the call stack to prevent infinite recursion.

        Handles both plain calls (func(arg)) and method calls (obj.method(arg)).
        """
        _rfd = getattr(_cross_file_local, "remote_func_defs", {})
        _rcm = getattr(_cross_file_local, "remote_class_methods", {})
        _all = getattr(_cross_file_local, "all_contents", {}) or {}
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            func_name = _full_name(node.func)
            attr = _attr_name(node.func) if isinstance(node.func, ast.Attribute) else None

            # Resolve callee: prefer full name match, then attribute-only match
            callee_def: ast.FunctionDef | ast.AsyncFunctionDef | None = None
            src_path_override: str | None = None
            skip_self = False

            if func_name and func_name not in self._call_stack:
                if func_name in _local_func_defs:
                    callee_def = _local_func_defs[func_name]
                elif func_name in _rfd:
                    callee_def, src_path_override = _rfd[func_name]

            # Method call fallback: obj.method(arg) where method is a local/remote class method
            if callee_def is None and attr and attr not in self._call_stack:
                if attr in _local_func_defs:
                    callee_def = _local_func_defs[attr]
                    skip_self = True
                elif attr in _rcm and _rcm[attr]:
                    callee_def = _rcm[attr][0]  # use first definition
                    skip_self = True

            if callee_def is None:
                continue

            arg_taints = [
                _taint_of(arg, self._assignments, self._class_attrs)
                for arg in node.args
            ]
            if not any(t.status == TaintStatus.TAINTED for t in arg_taints):
                continue

            # For method calls, skip the implicit 'self' parameter when mapping args
            effective_taints = arg_taints
            if skip_self:
                params = [p for p in callee_def.args.args if p.arg != "self"]
                effective_taints_m: list[TaintInfo] = []
                for _i, _p in enumerate(params):
                    if _i < len(arg_taints):
                        effective_taints_m.append(arg_taints[_i])
                effective_taints = effective_taints_m

            if src_path_override is None:
                self._analyze_with_tainted_params(callee_def, effective_taints)
            else:
                src_lines = _all.get(src_path_override, "").splitlines()
                saved_fp = self.file_path
                saved_lines = self.lines
                self.file_path = src_path_override
                self.lines = src_lines
                self._analyze_with_tainted_params(callee_def, effective_taints)
                self.file_path = saved_fp
                self.lines = saved_lines

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
            elif isinstance(stmt, ast.Try):
                # Process the try body with sequential guard propagation so that
                # guards like `if "'" in bar: return` inside try blocks suppress
                # subsequent sinks within the same try body.
                self._visit_stmts(stmt.body)
                for handler in stmt.handlers:
                    self.visit(handler)
                if stmt.orelse:
                    self._visit_stmts(stmt.orelse)
                if stmt.finalbody:
                    self._visit_stmts(stmt.finalbody)
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


def _collect_module_level_assignments(module: ast.Module) -> dict[str, ast.expr]:
    """Return {name: rhs} for simple name assignments at module top level.

    Only visits direct children of the module body (not nested scopes).
    Used to seed self._assignments before visiting module-level statements so
    that paths derived from __file__ (e.g. BASE_DIR = Path(__file__).parent)
    are resolved as CLEAN instead of UNKNOWN.
    """
    result: dict[str, ast.expr] = {}
    for stmt in module.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and stmt.value is not None:
                result[stmt.target.id] = stmt.value
    return result


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

    # Fourth pass: for-loop and comprehension target variables inherit taint from iterable.
    # Pattern: `for var in expr` — var is an element of expr, so it carries the same taint.
    # Real-world: `for name in request.form.keys()` → name is user-controlled (TAINTED).
    # Also covers generator/list/set/dict comprehension targets (same semantics, own scope).
    for node in ast.walk(func):
        if isinstance(node, (ast.For, ast.comprehension)):
            iter_expr = node.iter
            target = node.target
            if isinstance(target, ast.Name):
                result[target.id] = iter_expr
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
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

    # Corrective pass: fix stale Name references introduced by the BFS second pass for
    # AugAssign.  Pattern that causes FPs:
    #   copy = var        # copy aliases var when var is clean (Constant)
    #   var = ''          # var reset (still clean)
    #   var += param      # var becomes TAINTED
    #   copy += 'literal' # BFS sets result['copy'] = BinOp(Name('var'), Add, literal)
    #                     # which evaluates as TAINTED, but copy was clean at runtime.
    # Strategy: track which top-level variables hold constant values in execution order.
    # For each top-level AugAssign where the BFS result has a stale Name on the left
    # AND the augmented variable itself was a constant just before this AugAssign,
    # replace the stale Name with the concrete constant so taint is not over-propagated.
    _lin_state: dict[str, ast.expr | None] = {}
    for _stmt in func.body:
        if (
            isinstance(_stmt, ast.Assign)
            and id(_stmt) not in null_guard_ids
            and id(_stmt) not in dead_assign_ids
            and len(_stmt.targets) == 1
            and isinstance(_stmt.targets[0], ast.Name)
        ):
            _name = _stmt.targets[0].id
            _rhs = _stmt.value
            if isinstance(_rhs, ast.Constant):
                _lin_state[_name] = _rhs
            elif (
                isinstance(_rhs, ast.Name)
                and _rhs.id in _lin_state
                and isinstance(_lin_state[_rhs.id], ast.Constant)
            ):
                # Alias to a constant — propagate the constant value
                _lin_state[_name] = _lin_state[_rhs.id]
            else:
                _lin_state[_name] = None  # opaque / non-constant value
        elif (
            isinstance(_stmt, ast.AugAssign)
            and isinstance(_stmt.target, ast.Name)
        ):
            _var = _stmt.target.id
            _bfs = result.get(_var)
            # If the BFS second pass produced BinOp(Name('Y'), op, rhs) and the
            # variable being augmented (_var) was tracked as a constant in the
            # linear state just before this AugAssign, the Name('Y') is stale.
            # Replace it with the concrete constant to avoid over-propagating taint.
            if (
                isinstance(_bfs, ast.BinOp)
                and isinstance(_bfs.left, ast.Name)
                and isinstance(_lin_state.get(_var), ast.Constant)
            ):
                result[_var] = ast.BinOp(
                    left=_lin_state[_var],
                    op=_bfs.op,
                    right=_bfs.right,
                )
            _lin_state[_var] = None  # variable no longer holds a simple constant

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
        if name in ("True", "False", "None"):
            return CLEAN_BUILTIN
        if name in _CLEAN_DUNDER_NAMES:
            return CLEAN_BUILTIN
        base_taint: TaintInfo | None = None
        if assignments and name in assignments:
            # Assignments take precedence over name heuristics so that guard patches
            # (visit_If sets var→Constant to suppress within validated branch) work.
            val = assignments[name]
            if val is not node:
                base_taint = _taint_of(val, assignments, class_attrs, _depth + 1)
        elif name in _TAINTED_NAME_SOURCES:
            return TaintInfo(TaintStatus.TAINTED,
                             f"known user-input source '{name}'", source=name)
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
        # Phase B: check cross-file tainted module globals (e.g. HOST imported from config.py
        # where config.py has HOST = request.META.get("HTTP_HOST")).
        _rtg_b = getattr(_cross_file_local, "remote_tainted_globals", {})
        if name in _rtg_b:
            return TaintInfo(
                TaintStatus.TAINTED,
                f"tainted module global '{name}' from {_rtg_b[name]}",
                source=name,
            )
        # Fallback: module-level assignments (e.g. BASE_DIR = Path(__file__).parent).
        # Function-level params/assignments take precedence (checked above); this only
        # fires when the name wasn't resolved locally at all.
        _ml = getattr(_cross_file_local, "module_level_assignments", {})
        if name in _ml:
            val = _ml[name]
            if val is not node:
                return _taint_of(val, assignments, class_attrs, _depth + 1)
        return TaintInfo(TaintStatus.UNKNOWN,
                         f"untracked variable '{name}'", source=name)

    # ── Attribute access ────────────────────────────────────────────────────────
    if isinstance(node, ast.Attribute):
        attr = node.attr
        # os.environ is server configuration, not user input (see CLAUDE.md).
        if (isinstance(node.value, ast.Name) and node.value.id == "os"
                and attr == "environ"):
            return CLEAN_LITERAL
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
        # Path navigation attributes on UNKNOWN objects: cannot carry injected content
        # (TAINTED objects are caught above — their attributes propagate TAINTED).
        if attr in _CLEAN_PATH_ATTRS:
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

        # Phase 3a: self.method() / obj.method() where the short method name is a local
        # taint source.  _full_name returns "self.foo" which won't match _local_func_defs
        # keys (stored as "foo"), so we check attr separately.
        if attr and isinstance(node.func, ast.Attribute) and attr in _interprocedural_taint_sources:
            return TaintInfo(TaintStatus.TAINTED,
                             f"return of taint-source method '.{attr}()'", source=attr)

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

        # Phase 3b: self.method(tainted_arg) — attr call where the short method name is
        # in _local_func_defs but full ("self.foo") is not.  Skips 'self' when mapping params.
        if (attr and isinstance(node.func, ast.Attribute)
                and attr in _local_func_defs and _depth <= 12
                and (not full or full not in _local_func_defs)):
            _fd_m = _local_func_defs[attr]
            _arg_taints_m = [_taint_of(a, assignments, class_attrs, _depth + 1) for a in node.args]
            if any(t.status == TaintStatus.TAINTED for t in _arg_taints_m):
                _params_m = [p for p in _fd_m.args.args if p.arg != "self"]
                _pm_m: dict[str, ast.expr] = {}
                for _i, _param in enumerate(_params_m):
                    if _i < len(_arg_taints_m) and _arg_taints_m[_i].status == TaintStatus.TAINTED:
                        _pm_m[_param.arg] = ast.Name(id="request", ctx=ast.Load())
                if _pm_m and _callee_returns_tainted(_fd_m, _pm_m, _depth + 1):
                    return TaintInfo(TaintStatus.TAINTED,
                                     f"tainted arg flows through .{attr}() return", source=attr)

        # Phase 4: cross-file taint propagation.
        # If the called function is imported from another project-local file, check
        # whether a tainted argument flows through its return value.
        # (Remote taint-source functions — those that read request data directly —
        # are already merged into _interprocedural_taint_sources in analyze(), so the
        # check above at line ~1786 handles them. Phase 4 only needs to cover
        # the passthrough case: remote func receives a tainted arg and returns it.)
        # Skip Phase 4 for known sanitizer functions: the sanitizer handler below records
        # the sanitizer metadata correctly and must not be bypassed by Phase 4's TAINTED return.
        _phase4_is_sanitizer = (
            full in _HTML_SANITIZER_FUNCS | _URL_SANITIZER_FUNCS | _CMD_SANITIZER_FUNCS
            or attr in _HTML_SANITIZER_METHODS | _URL_SANITIZER_METHODS
        )
        if full and full not in _local_func_defs and _depth <= 11 and not _phase4_is_sanitizer:
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

        # argparse/click/typer CLI parsers: results are operator-controlled, not web user input.
        if attr in _CLI_PARSE_METHODS:
            return CLEAN_LITERAL

        # os.walk() yields (dirpath, dirnames, filenames) tuples from the OS filesystem.
        if full == "os.walk":
            return CLEAN_LITERAL

        # os.environ.get() / os.getenv(): server-configured environment variables,
        # not user-supplied input (per project policy — see CLAUDE.md).
        if full in {"os.environ.get", "os.getenv", "os.environ.__getitem__",
                    "os.environ.setdefault"}:
            return CLEAN_LITERAL

        # Server/OS functions: system clock, temp dir, PID — never user-controlled.
        if full in _CLEAN_SERVER_FUNCS:
            return CLEAN_LITERAL

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

            # Filesystem traversal on non-TAINTED path: yields existing filesystem paths.
            # TAINTED obj is caught directly by _check_path (AST-PATH-004) on the call itself.
            if attr in _PATH_ITER_METHODS and obj_taint.status != TaintStatus.TAINTED:
                return CLEAN_LITERAL

            # Path canonicalization on non-TAINTED objects.
            # Note: resolve() alone does NOT protect against traversal in web contexts;
            # TAINTED paths remain TAINTED via obj_taint propagation above.
            if attr in _PATH_CANON_METHODS and obj_taint.status != TaintStatus.TAINTED:
                return CLEAN_LITERAL

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

            # Catch-all: any remaining method call on a provably-CLEAN object stays CLEAN.
            # Template methods (format/join/replace) propagate taint from args and are handled
            # above; everything else (strftime, isoformat, encode, etc.) is a transform of
            # a clean value and cannot introduce user-controlled content.
            if obj_taint.status == TaintStatus.CLEAN:
                return CLEAN_LITERAL

        # Cross-file class method resolution: evaluate all known class implementations of
        # this method and derive a consensus taint result.  Handles two real patterns:
        #   thing = ThingFactory.createThing()   → UNKNOWN type
        #   bar = thing.doSomething(tainted)     → TAINTED (all impls pass arg through)
        # and suppresses FPs from safe wrapper methods that return constants:
        #   scr = request_wrapper(request)
        #   val = scr.get_safe_value("key")      → CLEAN (sole impl returns "bar")
        #
        # Consensus rules (avoids two bugs in the naive any-match approach):
        #   ALL TAINTED → TAINTED   (confident the call propagates taint)
        #   ALL CLEAN   → CLEAN     (every impl is provably constant/safe)
        #   otherwise   → fall through to UNKNOWN
        # "Otherwise" covers: mixed TAINTED+CLEAN (different classes behave differently,
        # we can't determine which is instantiated without type inference) and any impl
        # that returns UNKNOWN (wraps an opaque external API — don't assume CLEAN).
        if attr and _depth <= 11:
            _rcm = getattr(_cross_file_local, "remote_class_methods", {})
            if attr in _rcm:
                _arg_taints_cm = [
                    _taint_of(a, assignments, class_attrs, _depth + 1)
                    for a in node.args
                ]
                _cm_statuses: list[TaintStatus] = []
                for _m_node in _rcm[attr]:
                    # Map positional args to params, skipping 'self'
                    _params = [p for p in _m_node.args.args if p.arg != "self"]
                    _pm: dict[str, ast.expr] = {}
                    for _i, _p in enumerate(_params):
                        if _i < len(_arg_taints_cm):
                            if _arg_taints_cm[_i].status == TaintStatus.TAINTED:
                                _pm[_p.arg] = ast.Name(id="request", ctx=ast.Load())
                            elif _arg_taints_cm[_i].status == TaintStatus.CLEAN:
                                _pm[_p.arg] = ast.Constant(value="safe_literal")
                    _cm_statuses.append(
                        _callee_return_taint_status(_m_node, _pm, _depth + 1)
                    )
                if _cm_statuses:
                    if all(s == TaintStatus.TAINTED for s in _cm_statuses):
                        return TaintInfo(
                            TaintStatus.TAINTED,
                            f"tainted arg flows through .{attr}() implementation",
                            source=attr,
                        )
                    if all(s == TaintStatus.CLEAN for s in _cm_statuses):
                        return CLEAN_LITERAL
                    # Mixed or UNKNOWN implementations: fall through to UNKNOWN below

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
    # compiled_re.match/fullmatch/search(var) — pre-assigned compiled regex object
    # e.g. ID_RE = re.compile(r'\d+'); if ID_RE.match(uid): ...
    if (isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr in ("match", "fullmatch", "search")
            and isinstance(test.func.value, ast.Name)
            and test.func.value.id != "re"
            and test.args
            and isinstance(test.args[0], ast.Name)):
        return test.args[0].id
    # re.compile(pattern).match/fullmatch/search(var) — inline compiled regex validation
    if (isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr in ("match", "fullmatch", "search")
            and isinstance(test.func.value, ast.Call)
            and test.args
            and isinstance(test.args[0], ast.Name)):
        return test.args[0].id
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

    # DANGEROUS_CHAR in var → early-exit injection-character check; var is safe after exit.
    # Covers two patterns from real-world code:
    #   '../' in var  — path-traversal check (original)
    #   "'"  in var   — XPath / SQL injection character check
    #   '"'  in var   — XPath injection character check
    # The constant must be a recognised dangerous string, not an arbitrary literal,
    # to avoid over-marking guards like `if "foo" in var: return`.
    _DANGEROUS_CHAR_GUARDS = frozenset({"'", '"', "../", "..", ";"})
    if (isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and isinstance(test.left, ast.Constant)
            and isinstance(test.left.value, str)
            and any(test.left.value == c or c in test.left.value
                    for c in _DANGEROUS_CHAR_GUARDS)
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


def _expr_apos_replaced(node: ast.expr, assignments: dict[str, ast.expr]) -> bool:
    """True if all tainted parts of the expression have apostrophes replaced.

    Recognises the real-world XPath sanitisation pattern `var.replace("'", X)`
    where X does not contain an apostrophe (e.g. "&apos;", "").  When embedded
    in an f-string, every FormattedValue part must satisfy this property.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        val = assignments.get(node.id)
        return _expr_apos_replaced(val, assignments) if val is not None else False
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
            if len(node.args) >= 2:
                a0, a1 = node.args[0], node.args[1]
                if (isinstance(a0, ast.Constant) and isinstance(a0.value, str)
                        and "'" in a0.value
                        and isinstance(a1, ast.Constant) and isinstance(a1.value, str)
                        and "'" not in a1.value):
                    return True
    if isinstance(node, ast.JoinedStr):
        return all(
            _expr_apos_replaced(part.value, assignments)
            for part in node.values
            if isinstance(part, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (_expr_apos_replaced(node.left, assignments)
                and _expr_apos_replaced(node.right, assignments))
    return False


_EXIT_CALL_NAMES: frozenset[str] = frozenset({'abort', 'exit', 'quit'})
_EXIT_ATTR_CALLS: frozenset[str] = frozenset({'sys.exit', 'os._exit'})


def _is_always_exit(stmts: list[ast.stmt]) -> bool:
    """True if the last statement in the block always exits the current scope.

    Recognizes:
      return / raise / continue / break  — Python control-flow exits
      abort(code)                        — Flask / Werkzeug HTTP abort
      sys.exit() / os._exit()            — process exits
      exit() / quit()                    — interactive-session exits (rare in web code
                                          but harmless to treat as exits)
    """
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        call = last.value
        if isinstance(call.func, ast.Name) and call.func.id in _EXIT_CALL_NAMES:
            return True
        if (isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and f"{call.func.value.id}.{call.func.attr}" in _EXIT_ATTR_CALLS):
            return True
    return False


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

    Uses fixed-point iteration to handle transitive chains:
      def get_raw():    return request.args.get('q')   # direct source
      def get_wrapped(): data = get_raw(); return data  # transitive source

    Each pass expands the known-tainted set by one hop until stable.  Capped at 8
    passes (sufficient for all realistic nesting depths; O(n*passes) time).

    Security-first: if any code path can return a tainted value the function is
    marked as a taint source, even if other paths return a clean sentinel.
    """
    global _interprocedural_taint_sources

    func_nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    # Pre-compute assignments and returns ONCE before the fixed-point loop.
    # _collect_scope_assignments is a pure function of the AST node, so caching
    # avoids the O(n_funcs × n_passes × nodes_per_func) blow-up on large files.
    func_assignments: dict[str, dict] = {
        name: _collect_scope_assignments(node)
        for name, node in func_nodes.items()
    }
    func_returns: dict[str, list[ast.Return]] = {
        name: list(_iter_func_returns(node))
        for name, node in func_nodes.items()
    }

    current: frozenset[str] = frozenset()
    for _ in range(min(len(func_nodes) + 1, 8)):
        # Expose current known sources to _taint_of so transitive calls resolve.
        _interprocedural_taint_sources = current
        added: set[str] = set()
        for name in func_nodes:
            if name in current:
                continue
            assignments = func_assignments[name]
            for ret in func_returns[name]:
                if (ret.value is not None
                        # _depth=13: disables Phase 3 (≤12) and Phase 4 (≤11) interprocedural
                        # analysis.  This pre-pass only needs to detect inherent taint sources
                        # (direct request.args / input() reads and transitive chains via
                        # _interprocedural_taint_sources).  Full Phase 3/4 runs in analyze().
                        and _taint_of(ret.value, assignments, {}, 13).status == TaintStatus.TAINTED):
                    added.add(name)
                    break  # one tainted return is sufficient
        if not added:
            break
        current = current | frozenset(added)

    return current


def _is_tainted_expr_quick(
    node: ast.expr,
    tainted_vars: set[str],
    global_taint_sources: frozenset[str],
    depth: int = 0,
) -> bool:
    """Lightweight taint check for build_cross_file_summary Phase E.

    Does NOT run the full _taint_of machinery — intentionally simpler to avoid
    the recursive complexity of the main analyzer.  Handles the most common
    patterns: direct taint sources, attribute chains, subscripts, and calls.
    """
    if depth > 6:
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted_vars or node.id in _TAINTED_NAME_SOURCES
    if isinstance(node, ast.Attribute):
        if node.attr in _TAINTED_ATTR_NAMES:
            return True
        return _is_tainted_expr_quick(node.value, tainted_vars, global_taint_sources, depth + 1)
    if isinstance(node, ast.Subscript):
        return _is_tainted_expr_quick(node.value, tainted_vars, global_taint_sources, depth + 1)
    if isinstance(node, ast.Call):
        fn = _full_name(node.func)
        if fn in global_taint_sources or fn in _PY_ANY_QUALIFIER_TAINT_METHODS:
            return True
        # Propagate through method calls: request.args.get() → tainted because receiver is tainted
        if isinstance(node.func, ast.Attribute):
            if _is_tainted_expr_quick(node.func.value, tainted_vars, global_taint_sources, depth + 1):
                return True
        return any(
            _is_tainted_expr_quick(a, tainted_vars, global_taint_sources, depth + 1)
            for a in node.args
        )
    if isinstance(node, ast.BinOp):
        return (
            _is_tainted_expr_quick(node.left, tainted_vars, global_taint_sources, depth + 1)
            or _is_tainted_expr_quick(node.right, tainted_vars, global_taint_sources, depth + 1)
        )
    if isinstance(node, ast.JoinedStr):
        return any(
            _is_tainted_expr_quick(v, tainted_vars, global_taint_sources, depth + 1)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    return False


def _collect_tainted_vars_in_body(
    stmts: list[ast.stmt],
    seed: set[str],
    global_taint_sources: frozenset[str],
) -> set[str]:
    """Single-pass forward scan: return names assigned from tainted sources in *stmts*."""
    tainted = seed.copy()
    for stmt in stmts:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            val = stmt.value if isinstance(stmt, ast.Assign) else stmt.value
            if val is None:
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if _is_tainted_expr_quick(val, tainted, global_taint_sources):
                for t in targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
        elif isinstance(stmt, ast.AugAssign):
            if _is_tainted_expr_quick(stmt.value, tainted, global_taint_sources):
                if isinstance(stmt.target, ast.Name):
                    tainted.add(stmt.target.id)
    return tainted


def _is_clean_expr_quick(node: ast.expr, clean_vars: set[str], depth: int = 0) -> bool:
    """Lightweight CLEAN check for Phase F CLI-param propagation.

    Conservative: only constants, names in clean_vars, attribute access on CLEAN
    objects, and parse_args() returns qualify as CLEAN.  Arbitrary calls are not
    trusted so taint introduced by network/user operations is never suppressed.
    """
    if depth > 4:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in clean_vars
    if isinstance(node, ast.Attribute):
        # e.g. args.target where args came from parse_args() → CLEAN
        return _is_clean_expr_quick(node.value, clean_vars, depth + 1)
    if isinstance(node, ast.Call):
        attr = _attr_name(node.func)
        return attr in _CLI_PARSE_METHODS
    return False


def _collect_clean_vars_in_body(stmts: list[ast.stmt], seed: set[str]) -> set[str]:
    """Single-pass forward scan: return names assigned exclusively from CLEAN sources."""
    clean = seed.copy()
    for stmt in stmts:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            val = stmt.value if isinstance(stmt, ast.Assign) else stmt.value
            if val is None:
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if _is_clean_expr_quick(val, clean):
                for t in targets:
                    if isinstance(t, ast.Name):
                        clean.add(t.id)
    return clean


def _build_confirmed_clean_params(
    parsed_trees: dict[str, ast.Module],
) -> dict[str, frozenset[int]]:
    """Phase F: build {func_name: {param_idx}} for params confirmed CLEAN from CLI callers.

    Mirrors _build_confirmed_tainted_params but seeds from CLI entry functions
    (Click/Typer decorated) instead of web entry points.  Propagates transitively
    so helper functions called from CLI entries suppress path-traversal FPs.
    """
    confirmed: dict[str, set[int]] = {}

    func_bodies: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for tree in parsed_trees.values():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_bodies.setdefault(node.name, []).append(node)

    changed = True
    for _ in range(10):
        if not changed:
            break
        changed = False
        for _name, func_list in func_bodies.items():
            for func_def in func_list:
                params = [a.arg for a in func_def.args.args if a.arg != "self"]

                # Seed: CLI entry params are CLEAN; confirmed clean from previous iters
                clean_seed: set[str] = set()
                if _func_is_cli_entry(func_def):
                    clean_seed.update(params)
                for idx in confirmed.get(_name, set()):
                    if idx < len(params):
                        clean_seed.add(params[idx])

                if not clean_seed:
                    continue

                clean_vars = _collect_clean_vars_in_body(func_def.body, clean_seed)

                for node in ast.walk(func_def):
                    if not isinstance(node, ast.Call):
                        continue
                    callee = _full_name(node.func) or _attr_name(node.func)
                    if not callee:
                        continue
                    for i, arg in enumerate(node.args):
                        if _is_clean_expr_quick(arg, clean_vars):
                            if i not in confirmed.get(callee, set()):
                                confirmed.setdefault(callee, set()).add(i)
                                changed = True

    return {k: frozenset(v) for k, v in confirmed.items()}


def _build_confirmed_tainted_params(
    parsed_trees: dict[str, ast.Module],
    global_taint_sources: frozenset[str],
) -> dict[str, frozenset[int]]:
    """Phase E: build {func_name: {param_idx}} for params confirmed tainted at call sites.

    Two-phase fixed-point:
    1. Seed from web-entry functions: if a function has a 'request' param or similar,
       mark any downstream arg it passes as tainted.
    2. Propagate transitively: if function F's param 0 is confirmed tainted and
       F calls G(param0), then G's param 0 is also confirmed tainted.

    This enables HIGH-confidence findings in callee functions (e.g. dao.get_user) even
    when they are analyzed independently of their callers.
    """
    confirmed: dict[str, set[int]] = {}

    # Collect all function defs keyed by name for body lookup
    func_bodies: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for tree in parsed_trees.values():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_bodies.setdefault(node.name, []).append(node)

    changed = True
    max_iters = 10
    for _ in range(max_iters):
        if not changed:
            break
        changed = False
        for _name, func_list in func_bodies.items():
            for func_def in func_list:
                params = [a.arg for a in func_def.args.args if a.arg != "self"]

                # Seed tainted vars for this function's scope
                seed: set[str] = set()
                # Web entry: any param named 'request' or similar
                for arg in func_def.args.args:
                    if arg.arg in _TAINTED_NAME_SOURCES:
                        seed.add(arg.arg)
                # Confirmed tainted params from previous iterations
                for idx in confirmed.get(_name, set()):
                    if idx < len(params):
                        seed.add(params[idx])

                if not seed:
                    continue

                # Forward-propagate through the function body
                tainted_vars = _collect_tainted_vars_in_body(
                    func_def.body, seed, global_taint_sources
                )

                # Find calls that receive tainted args
                for node in ast.walk(func_def):
                    if not isinstance(node, ast.Call):
                        continue
                    callee = _full_name(node.func) or _attr_name(node.func)
                    if not callee or "." in callee:
                        # Skip qualified calls like obj.method — focus on plain func names
                        callee = _attr_name(node.func)
                    if not callee:
                        continue
                    for i, arg in enumerate(node.args):
                        if _is_tainted_expr_quick(arg, tainted_vars, global_taint_sources):
                            prev = confirmed.get(callee, set())
                            if i not in prev:
                                confirmed.setdefault(callee, set()).add(i)
                                changed = True

    return {k: frozenset(v) for k, v in confirmed.items()}


def build_cross_file_summary(all_contents: dict[str, str]) -> CrossFileTaintSummary:
    """Phase C pre-scan: build a global taint summary over *all_contents* before
    per-file analysis begins.

    Two-step algorithm:
    1. Collect ALL FunctionDef nodes from every Python file and run a single global
       fixed-point (_find_taint_source_funcs) to find inherent taint-source functions.
       Cross-file function chains are resolved because all functions are in scope.
    2. Fixed-point evaluation of module-level assignments across all files, using
       global_taint_sources so calls like ``HOST = get_host()`` are recognised even
       when get_host is defined in a transitively imported file.

    The resulting CrossFileTaintSummary is passed to set_cross_file_context() and
    consumed by analyze() which pre-seeds _interprocedural_taint_sources before
    calling _build_remote_func_defs (Phase B), enabling correct resolution of:
        config.py: ALLOWED_HOST = get_host()   ← get_host now in global sources
        views.py:  from config import ALLOWED_HOST → correctly TAINTED
    """
    global _interprocedural_taint_sources

    # ── Step 1: collect all function nodes from all Python files ───────────────
    all_func_nodes: list[ast.stmt] = []
    parsed_trees: dict[str, ast.Module] = {}

    for fp, content in all_contents.items():
        if not fp.endswith(".py"):
            continue
        try:
            tree = ast.parse(content)
            parsed_trees[fp] = tree
            all_func_nodes.extend(
                n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
        except SyntaxError:
            pass

    # ── Step 2: global fixed-point for inherent taint source functions ─────────
    if all_func_nodes:
        _fake_all = ast.Module(body=all_func_nodes, type_ignores=[])
        global_sources = _find_taint_source_funcs(_fake_all)
    else:
        global_sources = frozenset()

    # ── Step 3: fixed-point for module-level tainted globals ───────────────────
    # Make global sources visible to _taint_of during the global scan pass.
    _interprocedural_taint_sources = global_sources

    tainted_by_file: dict[str, frozenset[str]] = {}
    for _pass in range(6):
        _changed = False
        for fp, tree in parsed_trees.items():
            # Build sentinel assignments for tainted names imported from known files
            _imp_taint: dict[str, ast.expr] = {}
            for _s in tree.body:
                if isinstance(_s, ast.ImportFrom) and _s.module:
                    _src = _resolve_module_to_file(_s.module, fp, all_contents)
                    if _src and _src in tainted_by_file:
                        for _al in _s.names:
                            _as = _al.asname or _al.name
                            if _al.name in tainted_by_file[_src] or _al.name == "*":
                                _imp_taint[_as] = _TAINTED_MODULE_SENTINEL

            # Evaluate module-level assignments
            _new: set[str] = set()
            for _s in tree.body:
                if isinstance(_s, ast.Assign):
                    if _taint_of(_s.value, _imp_taint, {}).status == TaintStatus.TAINTED:
                        for _t in _s.targets:
                            if isinstance(_t, ast.Name):
                                _new.add(_t.id)
                elif isinstance(_s, ast.AnnAssign) and _s.value is not None:
                    if _taint_of(_s.value, _imp_taint, {}).status == TaintStatus.TAINTED:
                        if isinstance(_s.target, ast.Name):
                            _new.add(_s.target.id)

            _nf = frozenset(_new)
            if _nf != tainted_by_file.get(fp, frozenset()):
                tainted_by_file[fp] = _nf
                _changed = True
        if not _changed:
            break

    # Restore to empty so it is cleanly set per-file during analyze()
    _interprocedural_taint_sources = frozenset()

    # ── Step 4 (Phase E): confirmed-tainted parameter map ─────────────────────
    # Build {func_name: {param_idx}} for parameters that are confirmed to receive
    # tainted input from callers.  Used in visit_FunctionDef to inject TAINTED
    # sentinels, raising finding confidence from 0.3 (UNKNOWN/low_reach) to 0.9.
    conf_params = _build_confirmed_tainted_params(parsed_trees, global_sources)

    # ── Step 5 (Phase F): confirmed-CLEAN parameter map ───────────────────────
    # Build {func_name: {param_idx}} for parameters confirmed to receive only
    # CLI-originated (operator-controlled) input.  These params are injected as
    # CLEAN sentinels to suppress false positives for internal path operations.
    conf_clean_params = _build_confirmed_clean_params(parsed_trees)

    return CrossFileTaintSummary(
        global_taint_sources=global_sources,
        tainted_globals=tainted_by_file,
        confirmed_tainted_params=conf_params,
        confirmed_clean_params=conf_clean_params,
    )
