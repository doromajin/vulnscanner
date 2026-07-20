"""JavaScript/TypeScript AST taint analyzer (tree-sitter).

Improvements over the regex-based JSTaintAnalyzer (JSTAINT-* rules):
  - True AST parsing: no false matches inside comments or string literals
  - Interprocedural analysis: named functions that return tainted data propagate
    taint to their call sites (same-file, fixed-point iteration)
  - Accurate object destructuring (shorthand, aliased, default-value forms)
  - await_expression / TypeScript as_expression / non_null_expression unwrapping

Rule IDs (JSAST-*):
  JSAST-SQL-001   SQL injection (query / execute with tainted arg)
  JSAST-CMD-001   Command injection (exec / spawn family)
  JSAST-PATH-001  Path traversal (fs.* operations)
  JSAST-PATH-002  Path traversal (path.join/resolve)
  JSAST-XSS-001   Reflected XSS (res.send/write/end)
  JSAST-EVAL-001  Code injection (eval / new Function)
  JSAST-SSRF-001  SSRF (fetch / axios / http)

Analyzers:
  JSASTAnalyzer  — .js / .jsx / .mjs / .cjs  (tree-sitter-javascript)
  TSASTAnalyzer  — .ts / .tsx                 (tree-sitter-typescript)
"""
from __future__ import annotations

try:
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser as _TSParser
    _JS_LANGUAGE = Language(_tsjs.language())
    _js_parser = _TSParser(_JS_LANGUAGE)
    _TS_JS_AVAILABLE = True
except Exception:
    _TS_JS_AVAILABLE = False

try:
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language as _TSLang, Parser as _TSParserCls
    _TS_LANGUAGE = _TSLang(_tsts.language_typescript())
    _TSX_LANGUAGE = _TSLang(_tsts.language_tsx())
    _ts_parser = _TSParserCls(_TS_LANGUAGE)
    _tsx_parser = _TSParserCls(_TSX_LANGUAGE)
    _TS_TS_AVAILABLE = True
except Exception:
    _TS_TS_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_JS_AST_EXTS = (".js", ".jsx", ".mjs", ".cjs")
_TS_AST_EXTS = (".ts", ".tsx")

# ── Taint source detection ────────────────────────────────────────────────────

_SOURCE_ROOTS = frozenset({"req", "request", "ctx", "event"})
_SOURCE_PROPS = frozenset({
    "body", "query", "params", "headers", "cookies",
    "queryStringParameters", "pathParameters", "multiValueQueryStringParameters",
    "files",
})


def _member_chain(node) -> list[str]:
    """Return identifier names in a member expression chain, root first.

    E.g. ``req.body.name`` → ``['req', 'body', 'name']``.
    """
    if node.type == "identifier":
        return [node.text.decode("utf-8", errors="replace")]
    if node.type in ("member_expression", "subscript_expression"):
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property") or node.child_by_field_name("index")
        chain = _member_chain(obj) if obj else []
        if prop is not None:
            chain.append(prop.text.decode("utf-8", errors="replace"))
        return chain
    return []


def _is_request_source(node) -> bool:
    """True when node accesses a known HTTP request taint property."""
    chain = _member_chain(node)
    if len(chain) < 2:
        return False
    root, prop = chain[0], chain[1]
    if root not in _SOURCE_ROOTS:
        return False
    # ctx.request.body, ctx.request.query, …
    if root == "ctx" and prop == "request" and len(chain) >= 3:
        return chain[2] in _SOURCE_PROPS
    return prop in _SOURCE_PROPS


# ── Sanitizer detection ───────────────────────────────────────────────────────

_SANITIZER_FUNCS = frozenset({
    "parseInt", "parseFloat", "Number", "Boolean", "BigInt",
    "encodeURIComponent", "encodeURI", "escape",
})
_SANITIZER_METHODS = frozenset({
    "sanitize",  # DOMPurify.sanitize
    "escape",    # validator.escape
    "stringify", # JSON.stringify
})


def _is_sanitizer(node) -> bool:
    """True if node is a call to a value-sanitizing function."""
    if node.type != "call_expression":
        return False
    func = node.child_by_field_name("function")
    if func is None:
        return False
    if func.type == "identifier" and func.text.decode() in _SANITIZER_FUNCS:
        return True
    if func.type == "member_expression":
        prop = func.child_by_field_name("property")
        if prop and prop.text.decode() in _SANITIZER_METHODS:
            return True
    return False


# ── AST utilities ─────────────────────────────────────────────────────────────

def _walk(node):
    """Yield node and all descendants in pre-order."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _unwrap(node):
    """Strip JS/TS wrapper nodes that don't affect taint semantics.

    Handles: await_expression, as_expression (TS type cast),
    non_null_expression (TS ! operator), parenthesized_expression.
    """
    _STRIP = frozenset({
        "await_expression",
        "as_expression",        # expr as Type  (TypeScript)
        "non_null_expression",  # expr!          (TypeScript)
        "parenthesized_expression",
    })
    while node.type in _STRIP and node.named_children:
        node = node.named_children[0]
    return node




# ── Taint state ───────────────────────────────────────────────────────────────

class _JSTaintState:
    """Accumulates taint for a single JS file across multiple passes."""

    __slots__ = ("tainted", "tainted_funcs")

    def __init__(self) -> None:
        self.tainted: dict[str, tuple[int, str]] = {}    # var → (line, desc)
        self.tainted_funcs: set[str] = set()              # function names

    def mark(self, var: str, line: int, desc: str) -> bool:
        if var not in self.tainted:
            self.tainted[var] = (line, desc)
            return True
        return False

    def is_tainted_node(self, node) -> bool:
        """Return True if this AST node carries taint."""
        node = _unwrap(node)  # strips await / as / ! / parens

        if node.type == "identifier":
            return node.text.decode("utf-8", errors="replace") in self.tainted

        if node.type in ("member_expression", "subscript_expression"):
            if _is_request_source(node):
                return True
            obj = node.child_by_field_name("object")
            return obj is not None and self.is_tainted_node(obj)

        if node.type == "template_string":
            for sub in node.children:
                if sub.type == "template_substitution":
                    for expr in sub.named_children:
                        if self.is_tainted_node(expr):
                            return True
            return False

        if node.type == "binary_expression":
            return any(self.is_tainted_node(c) for c in node.named_children)

        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func is not None and func.type == "identifier":
                fname = func.text.decode("utf-8", errors="replace")
                if fname in self.tainted_funcs:
                    return True
            return False

        return False


# ── Pass 1 & 2: collect declarations and function taint ───────────────────────

def _collect_declarations(root, state: _JSTaintState) -> bool:
    """Walk all variable declarations. Return True if any taint was newly added."""
    changed = False
    for node in _walk(root):
        # const/let/var x = rhs   or   const { a, b: c } = rhs
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            val_node = node.child_by_field_name("value")
            if name_node is None or val_node is None:
                continue
            line = name_node.start_point[0] + 1
            val_node = _unwrap(val_node)

            if _is_sanitizer(val_node):
                continue

            if name_node.type == "identifier":
                var = name_node.text.decode()
                if var not in state.tainted and state.is_tainted_node(val_node):
                    short = val_node.text.decode("utf-8", errors="replace")[:60]
                    if state.mark(var, line, f"assigned from: {short}"):
                        changed = True

            elif name_node.type == "object_pattern":
                rhs_tainted = (
                    state.is_tainted_node(val_node)
                    or _is_request_source(val_node)
                )
                if rhs_tainted:
                    short_rhs = val_node.text.decode("utf-8", errors="replace")[:40]
                    for child in name_node.named_children:
                        local = _extract_destruct_local(child)
                        if local and local not in state.tainted:
                            if state.mark(local, line, f"destructured from {short_rhs}"):
                                changed = True

            elif name_node.type == "array_pattern":
                if state.is_tainted_node(val_node) or _is_request_source(val_node):
                    short_rhs = val_node.text.decode("utf-8", errors="replace")[:40]
                    for child in name_node.named_children:
                        if child.type == "identifier":
                            local = child.text.decode()
                            if local not in state.tainted:
                                if state.mark(local, line, f"array destructured from {short_rhs}"):
                                    changed = True

        # x = rhs  (re-assignment, not declaration)
        elif node.type == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs is None or rhs is None:
                continue
            if lhs.type == "identifier":
                var = lhs.text.decode()
                line = lhs.start_point[0] + 1
                rhs = _unwrap(rhs)
                if _is_sanitizer(rhs):
                    state.tainted.pop(var, None)
                elif var not in state.tainted and state.is_tainted_node(rhs):
                    short = rhs.text.decode("utf-8", errors="replace")[:60]
                    if state.mark(var, line, f"reassigned from: {short}"):
                        changed = True
    return changed


def _extract_destruct_local(node) -> str | None:
    """Return local variable name from a destructuring pattern child node."""
    if node.type == "shorthand_property_identifier_pattern":
        return node.text.decode("utf-8", errors="replace")
    if node.type == "pair_pattern":
        # { key: localName } — value is the local identifier
        nc = node.named_children
        if len(nc) >= 2 and nc[1].type == "identifier":
            return nc[1].text.decode("utf-8", errors="replace")
    if node.type == "object_assignment_pattern":
        # { name = default } — first child is the shorthand pattern
        nc = node.named_children
        if nc and nc[0].type == "shorthand_property_identifier_pattern":
            return nc[0].text.decode("utf-8", errors="replace")
    return None


def _analyze_functions(root, state: _JSTaintState) -> bool:
    """Find named functions whose return value is tainted. Returns True if new."""
    changed = False
    for node in _walk(root):
        if node.type not in ("function_declaration", "generator_function_declaration"):
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        fname = name_node.text.decode("utf-8", errors="replace")
        if fname in state.tainted_funcs:
            continue

        # Get parameter names → they are locally scoped and not tainted per se
        # (we can't know if callers pass tainted args without tracking call sites)
        params: set[str] = set()
        param_node = node.child_by_field_name("parameters")
        if param_node:
            for p in param_node.named_children:
                if p.type == "identifier":
                    params.add(p.text.decode())

        body = node.child_by_field_name("body")
        if body is None:
            continue

        # Check if any return statement returns tainted data
        for sub in _walk(body):
            if sub.type == "return_statement" and sub.named_children:
                ret_val = sub.named_children[0]
                ret_val = _unwrap(ret_val)
                if state.is_tainted_node(ret_val) or _is_request_source(ret_val):
                    state.tainted_funcs.add(fname)
                    changed = True
                    break
    return changed


def _build_taint_state(root) -> _JSTaintState:
    """Fixed-point taint collection with at most 8 passes."""
    state = _JSTaintState()
    for _ in range(8):
        c1 = _collect_declarations(root, state)
        c2 = _analyze_functions(root, state)
        if not c1 and not c2:
            break
    return state


# ── Sink definitions ──────────────────────────────────────────────────────────

_SQL_METHOD_SINKS = frozenset({"query", "execute", "raw", "all", "run", "prepare"})
_CMD_GLOBAL_SINKS = frozenset({
    "exec", "execSync", "execFile", "execFileSync", "spawnSync", "spawn",
})
_FS_SINKS = frozenset({
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "appendFile", "appendFileSync", "createReadStream", "createWriteStream",
    "unlink", "unlinkSync", "stat", "statSync", "rename", "renameSync",
    "open", "openSync", "access", "accessSync", "mkdir", "mkdirSync",
    "rmdir", "rmdirSync", "copyFile", "copyFileSync",
})
_RES_SINKS = frozenset({"send", "write", "end", "render", "sendFile"})
_SSRF_GLOBAL = frozenset({"fetch"})
_SSRF_OBJS = frozenset({"axios", "superagent", "got", "needle", "request"})
_HTTP_OBJS = frozenset({"http", "https"})
_SSRF_METHODS = frozenset({"get", "post", "put", "delete", "patch", "request"})


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
        snippet="\n".join(
            lines[max(0, line - 3): min(len(lines), line + 2)]
        ),
    ))


def _check_sinks(
    root,
    state: _JSTaintState,
    file_path: str,
    lines: list[str],
    repo_url: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple] = set()

    def tainted_args(args_node) -> list:
        return [c for c in args_node.named_children if state.is_tainted_node(c)]

    for node in _walk(root):
        line = node.start_point[0] + 1

        # ── new Function(tainted) ───────────────────────────────────────────
        if node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            args = node.child_by_field_name("arguments")
            if (
                ctor is not None
                and ctor.type == "identifier"
                and ctor.text.decode() == "Function"
                and args is not None
                and tainted_args(args)
            ):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                      "JSAST-EVAL-001",
                      "User-controlled data flows into new Function() — arbitrary code execution")
            continue

        if node.type != "call_expression":
            continue

        func_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if func_node is None or args_node is None:
            continue

        # ── Global function calls ─────────────────────────────────────────
        if func_node.type == "identifier":
            fname = func_node.text.decode()

            if fname == "eval" and tainted_args(args_node):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                      "JSAST-EVAL-001",
                      "User-controlled data flows into eval() — arbitrary code execution")

            elif fname in _CMD_GLOBAL_SINKS and tainted_args(args_node):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                      "JSAST-CMD-001",
                      f"User-controlled data flows into {fname}() — OS command injection risk")

            elif fname in _SSRF_GLOBAL and tainted_args(args_node):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSRF, Severity.HIGH,
                      "JSAST-SSRF-001",
                      "User-controlled URL flows into fetch() — SSRF risk")

        # ── Member call expressions ───────────────────────────────────────
        elif func_node.type == "member_expression":
            obj_node = func_node.child_by_field_name("object")
            prop_node = func_node.child_by_field_name("property")
            if obj_node is None or prop_node is None:
                continue
            prop = prop_node.text.decode("utf-8", errors="replace")
            obj_chain = _member_chain(obj_node)
            obj_root = obj_chain[0] if obj_chain else ""

            # SQL injection
            if prop in _SQL_METHOD_SINKS:
                named = list(args_node.named_children)
                t_args = tainted_args(args_node)
                has_tainted = bool(t_args)
                if not has_tainted and named:
                    # Also check template/concat in first arg
                    first = named[0]
                    has_tainted = (
                        (first.type == "template_string" and state.is_tainted_node(first))
                        or (first.type == "binary_expression" and state.is_tainted_node(first))
                    )
                if has_tainted:
                    # Skip parameterized queries: .query(sql, [params])
                    if len(named) >= 2 and named[1].type == "array":
                        pass
                    else:
                        _emit(findings, seen, file_path, line, lines, repo_url,
                              VulnType.SQL_INJECTION, Severity.HIGH,
                              "JSAST-SQL-001",
                              f"User-controlled data flows into .{prop}() — SQL injection risk")

            # fs operations
            elif obj_root in ("fs", "fsPromises", "fsp") and prop in _FS_SINKS:
                if tainted_args(args_node):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.PATH_TRAVERSAL, Severity.HIGH,
                          "JSAST-PATH-001",
                          f"User-controlled path flows into fs.{prop}() — path traversal risk")

            # path.join / resolve
            elif obj_root == "path" and prop in ("join", "resolve", "normalize"):
                if tainted_args(args_node):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.PATH_TRAVERSAL, Severity.MEDIUM,
                          "JSAST-PATH-002",
                          f"User-controlled path in path.{prop}() — verify within allowed root")

            # Response output (XSS)
            elif obj_root in ("res", "response") and prop in _RES_SINKS:
                if tainted_args(args_node):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.XSS, Severity.HIGH,
                          "JSAST-XSS-001",
                          f"User-controlled data in res.{prop}() — XSS risk if Content-Type is text/html")

            # SSRF via axios / http / superagent / etc.
            elif (
                (obj_root in _SSRF_OBJS or obj_root in _HTTP_OBJS)
                and prop in _SSRF_METHODS
                and tainted_args(args_node)
            ):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSRF, Severity.HIGH,
                      "JSAST-SSRF-001",
                      f"User-controlled URL flows into {obj_root}.{prop}() — SSRF risk")

            # child_process method on object: cp.exec(tainted)
            elif prop in _CMD_GLOBAL_SINKS and tainted_args(args_node):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                      "JSAST-CMD-001",
                      f"User-controlled data flows into .{prop}() — OS command injection risk")

    return findings


# ── Analyzer ──────────────────────────────────────────────────────────────────

def _analyze_with_parser(
    parser, file_path: str, content: str, repo_url: str
) -> list[Finding]:
    """Shared analysis entry point for JS and TS parsers."""
    try:
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:
        return []
    lines = content.splitlines()
    state = _build_taint_state(tree.root_node)
    if not state.tainted and not state.tainted_funcs:
        return []
    return _check_sinks(tree.root_node, state, file_path, lines, repo_url)


class JSASTAnalyzer(BaseAnalyzer):
    """JavaScript AST taint analyzer (tree-sitter-javascript).

    Covers .js / .jsx / .mjs / .cjs.
    """

    supported_extensions = _JS_AST_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_JS_AVAILABLE:
            return []
        if not any(file_path.endswith(ext) for ext in _JS_AST_EXTS):
            return []
        return _analyze_with_parser(_js_parser, file_path, content, repo_url)


class TSASTAnalyzer(BaseAnalyzer):
    """TypeScript/TSX AST taint analyzer (tree-sitter-typescript).

    Covers .ts / .tsx — handles TS type annotations, as-expressions,
    non-null assertions, and generic types that trip up the JS parser.
    Reuses all taint collection and sink detection logic from JSASTAnalyzer.
    """

    supported_extensions = _TS_AST_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_TS_AVAILABLE:
            return []
        if file_path.endswith(".tsx"):
            parser = _tsx_parser
        elif file_path.endswith(".ts"):
            parser = _ts_parser
        else:
            return []
        return _analyze_with_parser(parser, file_path, content, repo_url)
