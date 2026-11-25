"""Go AST taint analyzer (tree-sitter-go).

Detects user-controlled data flowing from net/http, Gin, Echo, and Chi
request objects into dangerous sinks via fixed-point taint propagation.

Improvements over the regex-based GoAnalyzer:
  - True AST parsing: no false matches inside comments or string literals
  - Multi-hop taint: x := r.FormValue(...); q := "SELECT..." + x; db.Query(q)
  - fmt.Sprintf taint propagation: q := fmt.Sprintf("...%s", id) → q tainted
  - Index expression: r.URL.Query()["key"] handled correctly
  - Function-level analysis: named functions returning request data propagate

Rule IDs (GOAST-*):
  GOAST-SQL-001   SQL injection (database/sql Query/Exec/QueryRow)
  GOAST-CMD-001   Command injection (exec.Command / exec.CommandContext)
  GOAST-PATH-001  Path traversal (os.Open/ReadFile/Create, filepath.Join)
  GOAST-XSS-001   Reflected XSS (fmt.Fprintf/Fprintln to ResponseWriter)
  GOAST-SSRF-001  SSRF (http.Get/Post/NewRequest, client.Do)
  GOAST-REDIR-001 Open redirect (http.Redirect with user-controlled URL)
  GOAST-TMPL-001  XSS via template.HTML() type conversion (escaping bypass)
  GOAST-LOG-001   Log injection (log.Printf/Println with user-controlled data)
  GOAST-SSTI-001  SSTI via template.New("").Parse(tainted) — user-controlled template
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

try:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language, Parser as _TSParser
    _GO_LANGUAGE = Language(_tsgo.language())
    _go_parser = _TSParser(_GO_LANGUAGE)
    _TS_GO_AVAILABLE = True
except Exception:
    _TS_GO_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType


# ── Cross-file taint context ──────────────────────────────────────────────────

@dataclass
class GoCrossFileContext:
    """Which Go function params receive tainted HTTP input from cross-file callers."""
    confirmed_tainted_params: dict[str, frozenset[int]] = field(default_factory=dict)


_go_cf_local = threading.local()


def set_go_cross_file_context(ctx: GoCrossFileContext | None) -> None:
    _go_cf_local.ctx = ctx


def _get_go_cf_ctx() -> GoCrossFileContext | None:
    return getattr(_go_cf_local, "ctx", None)

_GO_EXTS = (".go",)

# ── Request source detection ──────────────────────────────────────────────────

# Conventional *http.Request parameter names
_REQ_NAMES = frozenset({"r", "req", "request"})
# Gin / Echo / Chi context parameter names
_CTX_NAMES = frozenset({"c", "ctx"})

# *http.Request methods that directly return user-controlled strings
_HTTP_REQ_METHODS = frozenset({
    "FormValue", "PostFormValue", "PathValue",
})
# Gin / Echo / Chi context methods returning user input
_FRAMEWORK_METHODS = frozenset({
    "Query", "DefaultQuery", "PostForm", "DefaultPostForm",
    "Param", "GetHeader", "GetQuery", "GetPostForm",
    "QueryParam", "FormValue", "QueryString",
    "GetRawData",
})
# Methods on sub-objects (r.Header, r.URL) that return user data
_HEADER_URL_METHODS = frozenset({"Get", "Values"})
# Gin / Echo / Fiber struct-binding methods: c.ShouldBindJSON(&req) marks req as tainted
_GIN_BIND_METHODS = frozenset({
    "Bind", "BindJSON", "BindXML", "BindYAML", "BindQuery", "BindHeader",
    "BindUri", "BindForm",
    "ShouldBind", "ShouldBindJSON", "ShouldBindXML", "ShouldBindYAML",
    "ShouldBindQuery", "ShouldBindHeader", "ShouldBindUri", "ShouldBindForm",
    "ShouldBindBodyWith",
    # fasthttp/fiber
    "BodyParser",
})

# ── Taint-propagating calls (not sinks, but result is tainted if args are) ───

_PROPAGATING_PKGS = frozenset({
    "fmt", "strings", "strconv", "path", "filepath",
    # io.ReadAll(r.Body) / io.ReadFull(r.Body) → result is tainted
    "io",
    # json.NewDecoder(r.Body) / xml.NewDecoder(r.Body) → decoder is tainted
    "json", "xml", "yaml", "toml",
})
_PROPAGATING_METHODS = frozenset({
    "Sprintf", "Errorf",
    "Join", "Replace", "ReplaceAll", "TrimSpace", "Trim", "TrimPrefix",
    "TrimSuffix", "ToLower", "ToUpper", "Title",
    "Itoa", "FormatInt", "FormatFloat",
    # io helpers that read from a tainted reader
    "ReadAll", "ReadFull",
    # json/xml/yaml NewDecoder(tainted) — creates a tainted decoder
    "NewDecoder",
})

# ── Sink definitions ──────────────────────────────────────────────────────────

_SQL_METHODS = frozenset({
    "Query", "QueryRow", "Exec",
    "QueryContext", "QueryRowContext", "ExecContext",
    "Prepare",
})
_OS_SINKS = frozenset({
    "Open", "OpenFile", "Create", "CreateTemp",
    "ReadFile", "WriteFile", "Remove", "Rename",
    "Mkdir", "MkdirAll", "Stat", "Lstat",
})
_FILEPATH_SINKS = frozenset({"Join", "Abs", "EvalSymlinks"})
_HTTP_SSRF_METHODS = frozenset({"Get", "Post", "Head", "PostForm"})
# Log injection: standard library and common third-party log packages
# `.Parse(x)` is a template sink only in a file that imports a template package, and never as
# a package-level parser of something else (url.Parse, time.Parse, uuid.Parse ...).
_TEMPLATE_IMPORT_RE = re.compile(r'"(?:html|text)/template"|"github\.com/[^"]*(?:template|tmpl)[^"]*"')
_NON_TEMPLATE_PARSE_PKGS = frozenset({
    "url", "time", "uuid", "semver", "version", "netip", "net", "mail", "mime", "strconv",
    "filepath", "path", "big", "json", "yaml", "toml", "cron", "duration", "ulid", "xml", "html",
})

_LOG_PKGS = frozenset({"log", "slog", "zap", "zerolog", "logrus", "logging"})
_LOG_METHODS = frozenset({
    "Print", "Printf", "Println",
    "Fatal", "Fatalf", "Fatalln",
    "Panic", "Panicf", "Panicln",
    "Warn", "Warnf", "Error", "Errorf", "Info", "Infof", "Debug", "Debugf",
})


# ── AST helpers ───────────────────────────────────────────────────────────────

def _walk(node):
    """Yield node and all descendants in pre-order."""
    yield node
    for child in node.children:
        yield from _walk(child)


_SHELL_LIKE_PROGRAMS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "cmd", "powershell", "pwsh",
    "python", "python2", "python3", "perl", "ruby", "node", "php", "env", "xargs", "sudo", "su", "eval",
})


def _literal_program_name(node) -> str | None:
    """Base name of a string-literal program argument (``"/usr/bin/git"`` -> ``git``), else None."""
    if node is None or node.type not in ("interpreted_string_literal", "raw_string_literal"):
        return None
    text = node.text.decode("utf-8", errors="replace").strip("`\"")
    base = text.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base or None


def _selector_chain(node) -> list[str]:
    """Return name segments of a selector/call/identifier chain, root first.

    E.g. r.URL.Query().Get → ['r', 'URL', 'Query', 'Get']
    """
    if node.type == "identifier":
        return [node.text.decode("utf-8", errors="replace")]
    if node.type == "field_identifier":
        return [node.text.decode("utf-8", errors="replace")]
    if node.type == "selector_expression":
        operand = node.child_by_field_name("operand")
        field = node.child_by_field_name("field")
        chain = _selector_chain(operand) if operand else []
        if field:
            chain.append(field.text.decode("utf-8", errors="replace"))
        return chain
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        return _selector_chain(fn) if fn else []
    return []


def _is_request_source_node(node) -> bool:
    """True when node directly produces HTTP request data."""
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is None:
            return False
        chain = _selector_chain(fn)
        if not chain:
            return False
        root = chain[0]

        # r.FormValue(), r.PostFormValue(), r.PathValue()
        if root in _REQ_NAMES and len(chain) == 2 and chain[1] in _HTTP_REQ_METHODS:
            return True
        # r.Header.Get(), r.Header.Values()
        if (root in _REQ_NAMES and len(chain) == 3
                and chain[1] == "Header" and chain[2] in _HEADER_URL_METHODS):
            return True
        # r.URL.Query().Get(), r.URL.Query().Values(), r.URL.Query()["key"]
        if root in _REQ_NAMES and len(chain) >= 3 and chain[1] == "URL":
            return True
        # Gin/Echo: c.Query(), c.PostForm(), c.Param(), etc.
        if root in _CTX_NAMES and len(chain) == 2 and chain[1] in _FRAMEWORK_METHODS:
            return True

    if node.type == "index_expression":
        # r.URL.Query()["key"]
        operand = node.child_by_field_name("operand")
        return operand is not None and _is_request_source_node(operand)

    if node.type == "selector_expression":
        # r.URL.Path, r.URL.RawPath, r.URL.RawQuery, r.RequestURI, r.Body
        chain = _selector_chain(node)
        if (chain and chain[0] in _REQ_NAMES and len(chain) >= 2
                and chain[1] in ("URL", "RequestURI", "Host", "RemoteAddr", "Body")):
            return True

    return False


# ── Taint state helpers ───────────────────────────────────────────────────────

def _is_tainted(node, tainted: set[str], tainted_funcs: set[str]) -> bool:
    """Return True if node carries taint (request source or tainted variable)."""
    if node is None:
        return False

    if node.type == "identifier":
        return node.text.decode("utf-8", errors="replace") in tainted

    if _is_request_source_node(node):
        return True

    if node.type == "binary_expression":
        return any(
            _is_tainted(c, tainted, tainted_funcs)
            for c in node.named_children
        )

    if node.type in ("index_expression",):
        operand = node.child_by_field_name("operand")
        return operand is not None and _is_tainted(operand, tainted, tainted_funcs)

    if node.type == "selector_expression":
        if _is_request_source_node(node):
            return True
        operand = node.child_by_field_name("operand")
        return operand is not None and _is_tainted(operand, tainted, tainted_funcs)

    if node.type == "call_expression":
        if _is_request_source_node(node):
            return True
        # Taint-propagating functions (fmt.Sprintf, strings.Join, etc.)
        fn = node.child_by_field_name("function")
        if fn is not None:
            chain = _selector_chain(fn)
            if len(chain) >= 2 and chain[0] in _PROPAGATING_PKGS and chain[-1] in _PROPAGATING_METHODS:
                args = node.child_by_field_name("arguments")
                if args and any(
                    _is_tainted(c, tainted, tainted_funcs)
                    for c in args.named_children
                ):
                    return True
            # Named function returning tainted data
            if len(chain) == 1 and chain[0] in tainted_funcs:
                return True
        return False

    if node.type in ("type_conversion_expression", "unary_expression"):
        nc = node.named_children
        return bool(nc) and _is_tainted(nc[0], tainted, tainted_funcs)

    return False


# ── Taint collection (fixed-point) ────────────────────────────────────────────

def _lhs_names(expr_list) -> list[str]:
    """Extract variable names from the LHS expression_list of := or =."""
    names = []
    for child in expr_list.named_children:
        if child.type == "identifier":
            names.append(child.text.decode("utf-8", errors="replace"))
    return names


def _collect_pass(root, tainted: set[str], tainted_funcs: set[str], walker=_walk) -> bool:
    """Single taint-collection pass. Returns True if any new variable was tainted."""
    changed = False

    for node in walker(root):
        # x := rhs   (short variable declaration)
        if node.type == "short_var_declaration":
            lhs_list = node.named_children[0] if node.named_children else None
            rhs_list = node.named_children[-1] if len(node.named_children) >= 2 else None
            if lhs_list is None or rhs_list is None:
                continue
            lhs_names = _lhs_names(lhs_list)
            rhs_exprs = [c for c in rhs_list.named_children]
            # For multi-return: rows, err := db.Query(...)
            # Only the first var (index 0) receives the primary return value
            for i, name in enumerate(lhs_names):
                if name in tainted or name == "_":
                    continue
                rhs = rhs_exprs[i] if i < len(rhs_exprs) else (rhs_exprs[0] if rhs_exprs else None)
                if rhs and _is_tainted(rhs, tainted, tainted_funcs):
                    tainted.add(name)
                    changed = True

        # x = rhs   (assignment)
        elif node.type == "assignment_statement":
            lhs_list = node.named_children[0] if node.named_children else None
            rhs_list = node.named_children[-1] if len(node.named_children) >= 2 else None
            if lhs_list is None or rhs_list is None:
                continue
            lhs_names = _lhs_names(lhs_list)
            rhs_exprs = [c for c in rhs_list.named_children]
            for i, name in enumerate(lhs_names):
                if name in tainted or name == "_":
                    continue
                rhs = rhs_exprs[i] if i < len(rhs_exprs) else (rhs_exprs[0] if rhs_exprs else None)
                if rhs and _is_tainted(rhs, tainted, tainted_funcs):
                    tainted.add(name)
                    changed = True

        # Gin/Echo/Fiber struct binding: c.ShouldBindJSON(&req) / c.Bind(&req)
        # The struct pointed to by &req is populated from the request body/query —
        # mark the struct variable itself as tainted so req.Field accesses propagate.
        elif node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is None:
                continue
            chain = _selector_chain(fn)
            args_node = node.child_by_field_name("arguments")

            # Gin/Echo bind methods on context: c.ShouldBindJSON(&req)
            if (fn.type == "selector_expression"
                    and len(chain) == 2
                    and chain[0] in _CTX_NAMES
                    and chain[1] in _GIN_BIND_METHODS):
                if args_node:
                    for arg in args_node.named_children:
                        if (arg.type == "unary_expression"
                                and arg.named_children
                                and arg.named_children[0].type == "identifier"):
                            var_name = arg.named_children[0].text.decode(
                                "utf-8", errors="replace"
                            )
                            if var_name not in tainted:
                                tainted.add(var_name)
                                changed = True

            # json.Unmarshal(tainted, &req) / xml.Unmarshal / yaml.Unmarshal
            elif (len(chain) == 2
                    and chain[0] in ("json", "xml", "yaml", "toml")
                    and chain[1] == "Unmarshal"
                    and args_node):
                arg_list = list(args_node.named_children)
                if len(arg_list) >= 2 and _is_tainted(arg_list[0], tainted, tainted_funcs):
                    target = arg_list[1]
                    if (target.type == "unary_expression"
                            and target.named_children
                            and target.named_children[0].type == "identifier"):
                        vname = target.named_children[0].text.decode("utf-8", errors="replace")
                        if vname not in tainted:
                            tainted.add(vname)
                            changed = True

            # decoder.Decode(&req) — decoder is tainted when created from r.Body
            elif (fn.type == "selector_expression"
                    and chain and chain[-1] in ("Decode", "DecodeElement")
                    and args_node):
                recv = fn.child_by_field_name("operand")
                if recv is not None and _is_tainted(recv, tainted, tainted_funcs):
                    for arg in args_node.named_children:
                        if (arg.type == "unary_expression"
                                and arg.named_children
                                and arg.named_children[0].type == "identifier"):
                            vname = arg.named_children[0].text.decode("utf-8", errors="replace")
                            if vname not in tainted:
                                tainted.add(vname)
                                changed = True

    return changed


def _collect_func_taint(root, tainted: set[str], tainted_funcs: set[str], scope_of=None) -> bool:
    """Find named functions that return tainted data.

    scope_of: {function node id: tainted locals}; when given, each function's returns are
    judged against its own scope instead of the single ``tainted`` set.
    """
    changed = False
    for node in _walk(root):
        if node.type != "function_declaration":
            continue
        if scope_of is not None:
            tainted = scope_of.get(node.id, tainted)
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        fname = name_node.text.decode("utf-8", errors="replace")
        if fname in tainted_funcs:
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        for sub in _walk(body):
            if sub.type == "return_statement":
                for child in sub.named_children:
                    # Go return_statement wraps values in expression_list
                    exprs = (
                        child.named_children
                        if child.type == "expression_list"
                        else [child]
                    )
                    if any(_is_tainted(e, tainted, tainted_funcs) for e in exprs):
                        tainted_funcs.add(fname)
                        changed = True
                        break
    return changed


def _build_taint(root) -> tuple[set[str], set[str]]:
    """Fixed-point taint collection, max 8 passes."""
    tainted: set[str] = set()
    tainted_funcs: set[str] = set()
    for _ in range(8):
        c1 = _collect_pass(root, tainted, tainted_funcs)
        c2 = _collect_func_taint(root, tainted, tainted_funcs)
        if not c1 and not c2:
            break
    return tainted, tainted_funcs


# ── Per-function taint scopes ────────────────────────────────────────────────

_FUNC_DECLS = ("function_declaration", "method_declaration")


def _walk_scope(node):
    """Like _walk, but does not descend into nested function/method declarations.

    Func literals are not declarations, so they stay inside the enclosing scope and
    share its locals (closures).
    """
    yield node
    for child in node.children:
        if child.type in _FUNC_DECLS:
            continue
        yield from _walk_scope(child)


class _ScopeTaint:
    """Tainted names visible in one function: its own locals plus file-shared names.

    Package-level variables are shared by every function in the file; everything else
    is local.  Only ``in``, ``add`` and ``copy`` are used by the collectors.
    """

    def __init__(self, shared: set[str], pkg_vars: frozenset[str], local: "set[str] | None" = None):
        self.local: set[str] = set(local or ())
        self.shared = shared
        self.pkg_vars = pkg_vars

    def __contains__(self, name) -> bool:
        return name in self.local or name in self.shared

    def add(self, name: str) -> None:
        (self.shared if name in self.pkg_vars else self.local).add(name)

    def copy(self) -> "_ScopeTaint":
        return _ScopeTaint(self.shared, self.pkg_vars, self.local)

    def __bool__(self) -> bool:
        return bool(self.local or self.shared)


def _package_vars(root) -> frozenset[str]:
    """Names declared by top-level ``var`` declarations."""
    names: set[str] = set()
    for child in root.children:
        if child.type != "var_declaration":
            continue
        for sub in _walk(child):
            if sub.type == "var_spec":
                for n in sub.children_by_field_name("name"):
                    names.add(n.text.decode("utf-8", errors="replace"))
    return frozenset(names)


def _decl_param_names(func_node) -> list[str]:
    """Positional parameter names, expanding ``a, b string`` and variadics."""
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    result: list[str] = []
    for param in params_node.named_children:
        if param.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        names = [n.text.decode("utf-8", errors="replace") for n in param.children_by_field_name("name")]
        result.extend(names or [""])
    return result


def _seed_callee_params(roots, scopes, tainted_funcs, defs, method_defs) -> bool:
    """A callee's parameter is tainted when an in-file call passes it a tainted argument."""
    changed = False
    for r in roots:
        scope = scopes[r.id]
        for node in _walk_scope(r):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if fn is None or args_node is None:
                continue
            chain = _selector_chain(fn)
            if len(chain) == 1:
                targets = defs.get(chain[0], ())
            elif len(chain) >= 2 and fn.type == "selector_expression":
                targets = method_defs.get(chain[-1], ())
            else:
                continue
            if not targets:
                continue
            for i, arg in enumerate(args_node.named_children):
                if not _is_tainted(arg, scope, tainted_funcs):
                    continue
                for names, def_node in targets:
                    if i < len(names) and names[i] and names[i] not in scopes[def_node.id]:
                        scopes[def_node.id].add(names[i])
                        changed = True
    return changed


def _build_taint_scoped(root):
    """Fixed-point taint collection (max 8 passes), one local set per function.

    Returns (scope_roots, {root.id: _ScopeTaint}, tainted_funcs).  Package-level vars and
    tainted function names are shared by the file; locals are not.  The file level
    (outside any function) is a scope of its own.
    """
    roots = [root] + [n for n in _walk(root) if n.type in _FUNC_DECLS]
    shared: set[str] = set()
    pkg_vars = _package_vars(root)
    scopes = {r.id: _ScopeTaint(shared, pkg_vars) for r in roots}
    tainted_funcs: set[str] = set()
    defs: dict[str, list] = {}
    method_defs: dict[str, list] = {}
    for r in roots[1:]:
        name_node = r.child_by_field_name("name")
        if name_node is None:
            continue
        entry = (_decl_param_names(r), r)
        target = defs if r.type == "function_declaration" else method_defs
        target.setdefault(name_node.text.decode("utf-8", errors="replace"), []).append(entry)
    for _ in range(8):
        changed = False
        for r in roots:
            changed |= _collect_pass(r, scopes[r.id], tainted_funcs, walker=_walk_scope)
        changed |= _collect_func_taint(root, shared, tainted_funcs, scope_of=scopes)
        changed |= _seed_callee_params(roots, scopes, tainted_funcs, defs, method_defs)
        if not changed:
            break
    return roots, scopes, tainted_funcs


# ── Cross-file helpers ────────────────────────────────────────────────────────

_HTTP_HANDLER_TYPE_MARKERS = (
    "http.Request", "gin.Context", "echo.Context",
    "fiber.Ctx", "fasthttp.RequestCtx",
)


def _is_http_handler_decl(func_node) -> bool:
    """True if this function has a *http.Request or framework context parameter."""
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return False
    for param in params_node.named_children:
        if param.type != "parameter_declaration":
            continue
        type_node = param.child_by_field_name("type")
        if type_node is None:
            continue
        type_text = type_node.text.decode("utf-8", errors="replace")
        if any(m in type_text for m in _HTTP_HANDLER_TYPE_MARKERS):
            return True
    return False


def _get_param_names(func_node) -> list[str]:
    """Return positional parameter names of a function_declaration, in order."""
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    result: list[str] = []
    for param in params_node.named_children:
        if param.type != "parameter_declaration":
            continue
        name_node = param.child_by_field_name("name")
        result.append(
            name_node.text.decode("utf-8", errors="replace")
            if name_node and name_node.type == "identifier"
            else ""
        )
    return result


def build_go_cross_file_context(all_contents: dict[str, str]) -> GoCrossFileContext:
    """Build cross-file taint context: which function params receive HTTP taint.

    Strategy (fixed-point, up to 12 hops):
      1. HTTP handler functions seed their request-named params as taint sources.
      2. For each seeded/confirmed-tainted function, propagate taint within its
         body and find direct (unqualified) calls to project-local functions with
         tainted args → mark those callee params as confirmed_tainted_params.
      3. Repeat until stable.
    """
    if not _TS_GO_AVAILABLE:
        return GoCrossFileContext()

    # Parse all Go files and collect function declarations by name.
    func_bodies: dict[str, list] = {}
    for path, content in all_contents.items():
        if not path.endswith(".go"):
            continue
        try:
            tree = _go_parser.parse(content.encode("utf-8", errors="replace"))
        except Exception:
            continue
        for node in _walk(tree.root_node):
            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    fname = name_node.text.decode("utf-8", errors="replace")
                    func_bodies.setdefault(fname, []).append(node)

    confirmed: dict[str, set[int]] = {}

    for _pass in range(12):
        changed = False

        for fname, func_list in func_bodies.items():
            for func_def in func_list:
                params = _get_param_names(func_def)
                local_tainted: set[str] = set()

                # Seed 1: HTTP handler — request-named params are taint sources.
                if _is_http_handler_decl(func_def):
                    for p in params:
                        if p in _REQ_NAMES or p in _CTX_NAMES:
                            local_tainted.add(p)

                # Seed 2: confirmed cross-file tainted params.
                for i in confirmed.get(fname, set()):
                    if i < len(params) and params[i]:
                        local_tainted.add(params[i])

                if not local_tainted:
                    continue

                body = func_def.child_by_field_name("body")
                if body is None:
                    continue

                # Propagate taint within the function body.
                tainted = local_tainted.copy()
                tainted_funcs: set[str] = set(confirmed.keys())
                for _ in range(8):
                    if not _collect_pass(body, tainted, tainted_funcs):
                        break

                # Find unqualified calls to project-local functions with tainted args.
                for node in _walk(body):
                    if node.type != "call_expression":
                        continue
                    fn_node = node.child_by_field_name("function")
                    args_node = node.child_by_field_name("arguments")
                    if fn_node is None or args_node is None:
                        continue
                    chain = _selector_chain(fn_node)
                    if len(chain) != 1:
                        continue  # skip pkg.Func() — external package calls
                    callee = chain[0]
                    if callee not in func_bodies:
                        continue
                    for i, arg in enumerate(args_node.named_children):
                        if _is_tainted(arg, tainted, tainted_funcs):
                            if i not in confirmed.get(callee, set()):
                                confirmed.setdefault(callee, set()).add(i)
                                changed = True

        if not changed:
            break

    return GoCrossFileContext(
        confirmed_tainted_params={k: frozenset(v) for k, v in confirmed.items()}
    )


# ── Sink checking ─────────────────────────────────────────────────────────────

def _emit(
    findings: list[Finding],
    seen: set[tuple],
    file_path: str,
    line: int,
    lines: list[str],
    repo_url: str,
    vuln_type: VulnType,
    severity: Severity,
    rule_id: str,
    desc: str,
) -> None:
    key = (rule_id, line)
    if key in seen:
        return
    seen.add(key)
    content = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    findings.append(Finding(
        vuln_type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_number=line,
        line_content=content,
        description=desc,
        rule_id=rule_id,
        repo_url=repo_url,
        snippet="\n".join(lines[max(0, line - 3): min(len(lines), line + 2)]),
    ))


def _check_sinks(
    root,
    tainted: set[str],
    tainted_funcs: set[str],
    file_path: str,
    lines: list[str],
    repo_url: str,
    walker=_walk,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple] = set()

    def taint_check(n):
        return _is_tainted(n, tainted, tainted_funcs)

    imports_template = any(_TEMPLATE_IMPORT_RE.search(l) for l in lines[:200])

    for node in walker(root):
        if node.type != "call_expression":
            continue

        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue

        chain = _selector_chain(fn)
        if len(chain) < 2:
            continue

        pkg = chain[0]
        method = chain[-1]
        line = node.start_point[0] + 1
        arg_nodes = list(args.named_children)

        # ── SQL injection ─────────────────────────────────────────────────
        if method in _SQL_METHODS and arg_nodes and taint_check(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SQL_INJECTION, Severity.HIGH,
                  "GOAST-SQL-001",
                  f"User-controlled data flows into db.{method}() — SQL injection risk")

        # ── Command injection ─────────────────────────────────────────────
        elif pkg == "exec" and method in ("Command", "CommandContext"):
            # CommandContext(ctx, cmd, args...) → skip ctx at index 0
            # Command(cmd, args...) → all args checked
            start = 1 if method == "CommandContext" else 0
            if any(taint_check(a) for a in arg_nodes[start:]):
                prog = arg_nodes[start] if len(arg_nodes) > start else None
                prog_name = _literal_program_name(prog)
                if prog_name and prog_name not in _SHELL_LIKE_PROGRAMS:
                    # No shell is involved: only the arguments of a fixed program are
                    # attacker-influenced (option / argument injection), not the command.
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.COMMAND_INJECTION, Severity.HIGH,
                          "GOAST-CMD-001",
                          f"User-controlled data flows into the arguments of exec.{method}({prog_name!r}, ...) "
                          "— argument injection risk (no shell involved)")
                else:
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                          "GOAST-CMD-001",
                          f"User-controlled data flows into exec.{method}() — OS command injection risk")

        # ── Path traversal: os.Open, os.ReadFile, etc. ────────────────────
        elif pkg in ("os", "ioutil") and method in _OS_SINKS:
            if arg_nodes and taint_check(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH,
                      "GOAST-PATH-001",
                      f"User-controlled path flows into {pkg}.{method}() — path traversal risk")

        # ── Path traversal: filepath.Join ─────────────────────────────────
        elif pkg == "filepath" and method in _FILEPATH_SINKS:
            if any(taint_check(a) for a in arg_nodes):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.MEDIUM,
                      "GOAST-PATH-001",
                      f"User-controlled path in filepath.{method}() — verify within allowed root")

        # ── Reflected XSS: fmt.Fprintf(w, tainted) ────────────────────────
        elif pkg == "fmt" and method in ("Fprintf", "Fprintln", "Fprint"):
            # arg[0] is the writer (ResponseWriter), arg[1] is the format/value
            if len(arg_nodes) >= 2 and taint_check(arg_nodes[1]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.XSS, Severity.HIGH,
                      "GOAST-XSS-001",
                      f"User-controlled data flows into fmt.{method}() — XSS risk if writing HTML")

        # ── SSRF: http.Get(url), http.Post(url) ───────────────────────────
        elif pkg == "http" and method in _HTTP_SSRF_METHODS:
            if arg_nodes and taint_check(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSRF, Severity.HIGH,
                      "GOAST-SSRF-001",
                      f"User-controlled URL flows into http.{method}() — SSRF risk")

        # ── SSRF: http.NewRequest(method, tainted_url, body) ─────────────
        elif pkg == "http" and method == "NewRequest":
            if len(arg_nodes) >= 2 and taint_check(arg_nodes[1]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSRF, Severity.HIGH,
                      "GOAST-SSRF-001",
                      "User-controlled URL flows into http.NewRequest() — SSRF risk")

        # ── SSRF: client.Get/Post/Do ──────────────────────────────────────
        elif method in ("Get", "Post", "Do", "Head") and arg_nodes and taint_check(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SSRF, Severity.HIGH,
                  "GOAST-SSRF-001",
                  f"User-controlled data flows into .{method}() — SSRF risk")

        # ── Open redirect: http.Redirect(w, r, tainted_url, code) ────────
        # arg[2] is the URL; arg[0] is ResponseWriter, arg[1] is *Request
        elif pkg == "http" and method == "Redirect":
            if len(arg_nodes) >= 3 and taint_check(arg_nodes[2]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.OPEN_REDIRECT, Severity.MEDIUM,
                      "GOAST-REDIR-001",
                      "User-controlled URL flows into http.Redirect() — open redirect risk")

        # ── XSS via unsafe HTML conversion: template.HTML(tainted) ───────
        elif pkg == "template" and method == "HTML":
            if arg_nodes and taint_check(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.XSS, Severity.HIGH,
                      "GOAST-TMPL-001",
                      "User-controlled data cast to template.HTML() — XSS bypass, escaping suppressed")

        # ── SSTI: .Parse(tainted) — user-controlled template string ──────
        # template.New("name").Parse(userInput) evaluates user-supplied template
        elif (method == "Parse" and arg_nodes and taint_check(arg_nodes[0])
              and pkg not in _NON_TEMPLATE_PARSE_PKGS and imports_template):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SSTI, Severity.CRITICAL,
                  "GOAST-SSTI-001",
                  "User-controlled data flows into .Parse() — Go template SSTI / code execution risk")

        # ── Log injection: log.Printf(tainted), log.Println(tainted) ─────
        elif pkg in _LOG_PKGS and method in _LOG_METHODS:
            if arg_nodes and taint_check(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.LOG_INJECTION, Severity.LOW,
                      "GOAST-LOG-001",
                      f"User-controlled data flows into {pkg}.{method}() — log injection risk")

    return findings


def _check_cross_file_sinks(
    root,
    scopes: dict,
    global_tainted: set[str],
    global_tainted_funcs: set[str],
    cf_ctx: GoCrossFileContext,
    file_path: str,
    lines: list[str],
    repo_url: str,
) -> list[Finding]:
    """Detect sinks in functions whose params are tainted by cross-file callers."""
    findings: list[Finding] = []

    for node in _walk(root):
        if node.type != "function_declaration":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        fname = name_node.text.decode("utf-8", errors="replace")
        if fname not in cf_ctx.confirmed_tainted_params:
            continue

        params = _get_param_names(node)
        local_tainted = scopes[node.id].copy() if node.id in scopes else global_tainted.copy()
        added = False
        for i in cf_ctx.confirmed_tainted_params[fname]:
            if i < len(params) and params[i] and params[i] not in local_tainted:
                local_tainted.add(params[i])
                added = True

        if not added:
            continue

        body = node.child_by_field_name("body")
        if body is None:
            continue

        for _ in range(8):
            if not _collect_pass(body, local_tainted, global_tainted_funcs):
                break

        findings.extend(
            _check_sinks(body, local_tainted, global_tainted_funcs, file_path, lines, repo_url)
        )

    return findings


# ── Analyzer ──────────────────────────────────────────────────────────────────

class GoASTAnalyzer(BaseAnalyzer):
    """Go AST taint analyzer (tree-sitter-go).

    Covers .go files — net/http, Gin, Echo, Chi handler patterns.
    """

    supported_extensions = _GO_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_GO_AVAILABLE:
            return []
        if not file_path.endswith(".go"):
            return []
        try:
            tree = _go_parser.parse(content.encode("utf-8", errors="replace"))
        except Exception:
            return []

        lines = content.splitlines()
        roots, scopes, tainted_funcs = _build_taint_scoped(tree.root_node)

        findings: list[Finding] = []
        if tainted_funcs or any(scopes[r.id] for r in roots):
            for r in roots:
                findings.extend(
                    _check_sinks(r, scopes[r.id], tainted_funcs, file_path, lines, repo_url,
                                 walker=_walk_scope)
                )

        cf_ctx = _get_go_cf_ctx()
        if cf_ctx and cf_ctx.confirmed_tainted_params:
            findings.extend(
                _check_cross_file_sinks(
                    tree.root_node, scopes, scopes[tree.root_node.id], tainted_funcs, cf_ctx,
                    file_path, lines, repo_url
                )
            )

        return findings
