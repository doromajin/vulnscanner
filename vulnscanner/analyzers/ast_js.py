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
  JSAST-REDIR-001 Open redirect (res.redirect with user-controlled URL)
  JSAST-NOSQL-001 NoSQL injection (MongoDB find/findOne/updateOne …)
  JSAST-LOG-001   Log injection (console.log / logger.error …)
  JSAST-SSTI-001  SSTI (ejs/pug/handlebars/nunjucks render/compile)
  JSAST-PROTO-001 Prototype pollution (_.merge / Object.assign …)
  JSAST-REDOS-001 ReDoS — nested quantifiers / ambiguous alternation in regex literals
  JSAST-DOMXSS-001 DOM XSS — innerHTML/outerHTML/document.write with user-controlled data
  JSAST-DOMXSS-002 Client-side open redirect — location.href = tainted URL
  Class field taint: this.x = req.body.x propagated to sinks in other methods
  Promise chain taint: promise.then(x => sink(x)) propagates taint to callback param
  Client-side sources: location.search/hash, document.URL/referrer, localStorage.getItem

Analyzers:
  JSASTAnalyzer  — .js / .jsx / .mjs / .cjs  (tree-sitter-javascript)
  TSASTAnalyzer  — .ts / .tsx                 (tree-sitter-typescript)
"""
from __future__ import annotations

import re as _re

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

# ── Client-side (DOM) taint sources ──────────────────────────────────────────
# Browser APIs that return attacker-controlled strings
_DOM_SOURCE_ROOTS = frozenset({"location", "document", "window"})
_DOM_LOCATION_PROPS = frozenset({"search", "hash", "href", "pathname", "host", "hostname"})
_DOM_DOCUMENT_PROPS = frozenset({"URL", "documentURI", "referrer", "cookie"})
_DOM_WINDOW_PROPS = frozenset({"name"})
# Methods that retrieve user-controlled values from browser storage / URL params
_DOM_GET_METHODS = frozenset({"get", "getItem", "getAll"})


def _member_chain(node) -> list[str]:
    """Return identifier names in a member expression chain, root first.

    E.g. ``req.body.name`` → ``['req', 'body', 'name']``.
    ``require('fs')`` → ``['fs']`` (inline-require treated as its module name).
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
    # require('module') → ['module'] so that require('fs').readFileSync() is
    # treated the same as a variable named 'fs'.
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if (func is not None and func.type == "identifier"
                and func.text.decode("utf-8", errors="replace") == "require"
                and args is not None):
            for arg in args.named_children:
                raw = arg.text.decode("utf-8", errors="replace").strip("'\"")
                # Normalise 'node:fs', 'fs/promises', 'node:fs/promises' → 'fs'
                mod = raw.replace("node:", "").split("/")[0]
                if mod:
                    return [mod]
    return []


def _is_request_source(node) -> bool:
    """True when node accesses a known HTTP request taint property (server or client)."""
    # call_expression: localStorage.getItem(k), URLSearchParams.get(k) — recurse on .function
    # Must check BEFORE the chain-length guard since _member_chain returns [] for calls.
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None:
            return _is_request_source(fn)
        return False

    chain = _member_chain(node)
    if len(chain) < 2:
        return False
    root, prop = chain[0], chain[1]

    # ── Server-side sources (req/request/ctx/event) ───────────────────────────
    if root in _SOURCE_ROOTS:
        if root == "ctx" and prop == "request" and len(chain) >= 3:
            return chain[2] in _SOURCE_PROPS
        return prop in _SOURCE_PROPS

    # ── Client-side DOM sources ───────────────────────────────────────────────
    if root == "location" and prop in _DOM_LOCATION_PROPS:
        return True
    if root == "document" and prop in _DOM_DOCUMENT_PROPS:
        return True
    if root == "window" and prop in _DOM_WINDOW_PROPS:
        return True
    # URLSearchParams.get("key"), localStorage.getItem("key"), sessionStorage.getItem()
    if root in ("URLSearchParams", "searchParams", "localStorage", "sessionStorage"):
        if prop in _DOM_GET_METHODS:
            return True

    return False


# ── Sanitizer detection ───────────────────────────────────────────────────────

_SANITIZER_FUNCS = frozenset({
    # Numeric casts — safe for SQL when result is used as number
    "parseInt", "parseFloat", "Number", "Boolean", "BigInt",
    "Math.floor", "Math.ceil", "Math.round", "Math.abs",
    # URL encoding — XSS-safe for attribute/URL contexts
    "encodeURIComponent", "encodeURI", "escape",
    # HTML escape libraries
    "escapeHtml", "sanitizeHtml", "filterXSS",
    # xss library: xss(str)
    "xss",
})
_SANITIZER_METHODS = frozenset({
    "sanitize",      # DOMPurify.sanitize / sanitizer.sanitize
    "clean",         # DOMPurify.clean
    "escape",        # validator.escape / _.escape / he.escape
    "encode",        # he.encode / htmlencode
    "stringify",     # JSON.stringify (converts to safe JSON string)
    "escapeHtml",    # various libraries
    "sanitizeHtml",  # sanitize-html library
    "stripTags",     # striptags library
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

    __slots__ = ("tainted", "tainted_funcs", "tainted_attrs")

    def __init__(self) -> None:
        self.tainted: dict[str, tuple[int, str]] = {}    # var → (line, desc)
        self.tainted_funcs: set[str] = set()              # function names
        self.tainted_attrs: set[str] = set()              # this.x attribute names

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
            # this.attr — check if attr was previously tainted via assignment
            if obj is not None and obj.type == "this":
                prop = node.child_by_field_name("property")
                if prop is not None:
                    attr = prop.text.decode("utf-8", errors="replace")
                    if attr in self.tainted_attrs:
                        return True
                return False
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
            # DOM source calls: localStorage.getItem(), URLSearchParams.get(), etc.
            if _is_request_source(node):
                return True
            func = node.child_by_field_name("function")
            if func is not None and func.type == "identifier":
                fname = func.text.decode("utf-8", errors="replace")
                if fname in self.tainted_funcs:
                    return True
            return False

        # Object literal {key: taintedVal} — common in NoSQL queries like find({name: x})
        if node.type == "object":
            for pair in node.named_children:
                if pair.type == "pair":
                    val = pair.child_by_field_name("value")
                    if val is not None and self.is_tainted_node(val):
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
            rhs_unwrapped = _unwrap(rhs)
            if lhs.type == "identifier":
                var = lhs.text.decode()
                line = lhs.start_point[0] + 1
                if _is_sanitizer(rhs_unwrapped):
                    state.tainted.pop(var, None)
                elif var not in state.tainted and state.is_tainted_node(rhs_unwrapped):
                    short = rhs_unwrapped.text.decode("utf-8", errors="replace")[:60]
                    if state.mark(var, line, f"reassigned from: {short}"):
                        changed = True

            # this.attr = tainted — class field assignment; attr becomes tainted
            elif lhs.type == "member_expression":
                obj = lhs.child_by_field_name("object")
                prop = lhs.child_by_field_name("property")
                if (obj is not None and obj.type == "this"
                        and prop is not None
                        and not _is_sanitizer(rhs_unwrapped)):
                    attr = prop.text.decode("utf-8", errors="replace")
                    if (attr not in state.tainted_attrs
                            and (state.is_tainted_node(rhs_unwrapped)
                                 or _is_request_source(rhs_unwrapped))):
                        state.tainted_attrs.add(attr)
                        changed = True

        # Promise chain: taintedPromise.then(param => ...) / .catch(param => ...)
        # The first parameter of the callback receives the resolved/rejected value.
        # Mark it as tainted when the receiver produces tainted output.
        elif node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is None or args is None or fn.type != "member_expression":
                continue
            prop_node = fn.child_by_field_name("property")
            if prop_node is None:
                continue
            method = prop_node.text.decode("utf-8", errors="replace")
            if method not in ("then", "catch", "finally"):
                continue
            recv = fn.child_by_field_name("object")
            if recv is None:
                continue
            # Receiver is tainted if: directly tainted, request source, a tainted function
            # call, or a call wrapping tainted args (e.g. Promise.resolve(tainted))
            recv_tainted = state.is_tainted_node(recv) or _is_request_source(recv)
            if not recv_tainted and recv.type == "call_expression":
                recv_args = recv.child_by_field_name("arguments")
                if recv_args is not None and any(
                    state.is_tainted_node(a) or _is_request_source(a)
                    for a in recv_args.named_children
                ):
                    recv_tainted = True
            if not recv_tainted:
                continue
            # Extract first parameter of the callback arrow/function
            for cb in args.named_children:
                cb = _unwrap(cb)
                if cb.type in ("arrow_function", "function_expression", "function"):
                    params = cb.child_by_field_name("parameters") or cb.child_by_field_name("parameter")
                    if params is None:
                        break
                    # arrow_function with single identifier param: x => ...
                    if params.type == "identifier":
                        pname = params.text.decode("utf-8", errors="replace")
                        if pname not in state.tainted:
                            line = cb.start_point[0] + 1
                            if state.mark(pname, line, f"promise .{method}() callback parameter"):
                                changed = True
                    else:
                        # (x, y) => ... — take first named param
                        for p in params.named_children:
                            if p.type == "identifier":
                                pname = p.text.decode("utf-8", errors="replace")
                                if pname not in state.tainted:
                                    line = p.start_point[0] + 1
                                    if state.mark(pname, line, f"promise .{method}() callback parameter"):
                                        changed = True
                                break
                break

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


_NESTJS_PARAM_DECORATORS = frozenset({
    "Body", "Query", "Param", "Headers", "Req", "Request",
    "UploadedFile", "UploadedFiles",
})


def _collect_nestjs_params(root, state: _JSTaintState) -> bool:
    """Mark Nest.js / Next.js controller method parameters as tainted.

    Patterns detected:
      @Get() async findAll(@Query() query: QueryDto) { ... }
      @Post() async create(@Body() dto: CreateDto) { ... }
      @Get(':id') async find(@Param('id') id: string) { ... }

    The decorator-annotated parameter variable is added to state.tainted so that
    any downstream sink receives taint from it.
    """
    changed = False
    for node in _walk(root):
        # Look for method definitions (class methods) in TypeScript/JavaScript
        if node.type not in ("method_definition", "public_field_definition"):
            continue
        # Find the formal parameter list
        params_node = node.child_by_field_name("parameters") or node.child_by_field_name("value")
        if params_node is None:
            continue
        for param in params_node.named_children:
            # A decorated parameter looks like: decorator+ identifier/pattern
            decorators = [c for c in param.children if c.type == "decorator"]
            if not decorators:
                continue
            for dec in decorators:
                # decorator → @ call_expression  or  @ identifier
                dec_body = dec.named_children[0] if dec.named_children else None
                if dec_body is None:
                    continue
                # Get the decorator name (may be a call like @Body() or identifier @Body)
                if dec_body.type == "call_expression":
                    fn = dec_body.child_by_field_name("function")
                    dec_name = fn.text.decode("utf-8", errors="replace") if fn else ""
                elif dec_body.type == "identifier":
                    dec_name = dec_body.text.decode("utf-8", errors="replace")
                else:
                    dec_name = ""
                if dec_name not in _NESTJS_PARAM_DECORATORS:
                    continue
                # Find the parameter identifier
                for child in param.children:
                    if child.type in ("identifier", "required_parameter",
                                      "optional_parameter"):
                        name_node = child if child.type == "identifier" else \
                            child.child_by_field_name("pattern") or child.child_by_field_name("name")
                        if name_node and name_node.type == "identifier":
                            pname = name_node.text.decode("utf-8", errors="replace")
                            if pname not in state.tainted:
                                line = name_node.start_point[0] + 1
                                if state.mark(pname, line, f"Nest.js @{dec_name}() parameter"):
                                    changed = True
                        break
    return changed


def _build_taint_state(root) -> _JSTaintState:
    """Fixed-point taint collection with at most 8 passes."""
    state = _JSTaintState()
    _collect_nestjs_params(root, state)  # Nest.js decorators — one-shot, no iteration needed
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
# NoSQL injection: MongoDB driver methods where the filter/query arg is user-controlled
_NOSQL_METHOD_SINKS = frozenset({
    "find", "findOne", "findOneAndUpdate", "findOneAndReplace", "findOneAndDelete",
    "aggregate", "count", "countDocuments", "distinct", "deleteOne", "deleteMany",
    "updateOne", "updateMany", "replaceOne",
})
# Log injection: logging frameworks that render the first arg as-is
_LOG_ROOTS = frozenset({"console", "logger", "log", "winston", "pino", "bunyan"})
_LOG_METHODS = frozenset({"log", "warn", "error", "info", "debug", "trace", "fatal"})
# SSTI: template engine objects and their render/compile methods
_SSTI_ROOTS = frozenset({
    "ejs", "pug", "jade", "nunjucks", "handlebars", "Handlebars",
    "mustache", "Mustache", "swig", "eta", "Eta",
})
_SSTI_RENDER_METHODS = frozenset({
    "render", "renderFile", "renderString", "renderToString",
    "compile", "template",
})
# Prototype pollution: merge / extend style functions (arg[1+] merges into arg[0])
_MERGE_GLOBAL_FUNCS = frozenset({
    "merge", "extend", "deepMerge", "deepExtend", "mergeWith",
    "defaults", "defaultsDeep", "mixin",
})
_MERGE_ROOTS = frozenset({"_", "lodash", "$", "jQuery", "deepmerge"})
_MERGE_METHODS = frozenset({
    "merge", "extend", "mergeWith", "defaults", "defaultsDeep", "assign", "mixin",
})
# DOM XSS: assignment sinks where LHS property causes script execution
_DOM_ASSIGN_SINKS = frozenset({"innerHTML", "outerHTML", "srcdoc"})
# DOM redirect: assignment to location.href / location causes navigation
_DOM_LOCATION_ASSIGN = frozenset({"href", "replace"})
# DOM write call sinks
_DOM_WRITE_METHODS = frozenset({"write", "writeln"})

# ── ReDoS detection ────────────────────────────────────────────────────────────
# Detect nested quantifiers: a group containing a quantifier wrapped in an outer
# quantifier — the classic exponential-backtracking pattern e.g. (a+)+ or (a*b*)+
# We match on the raw regex source string (not the AST), which is simpler and safe.

# Pattern 1: group with inner quantifier, followed by outer quantifier
#   e.g.  (a+)+  ([a-z]+\s*)+  (\w*:\w*)+
_REDOS_NESTED = _re.compile(
    r'(?<![\\])'      # not escaped
    r'\('             # open group
    r'(?:[^()\\]|\\.)*'  # group content (non-nested, handles escape seqs)
    r'(?:[+*]|\{[0-9]+,[0-9]*\})'  # inner quantifier
    r'(?:[^()\\]|\\.)*'
    r'\)'             # close group
    r'(?:[+*?]|\{[0-9]+,[0-9]*\})'  # outer quantifier
)

# Pattern 2: alternation inside a group with outer quantifier AND overlapping alternatives
#   e.g.  (a|ab)+  (ab|b)+  (\d|\d\d)+
_REDOS_ALTERNATION = _re.compile(
    r'\('
    r'([^()|\\]+)'    # first alternative (simple, no nesting)
    r'\|'
    r'([^()|\\]+)'    # second alternative
    r'\)'
    r'[+*]'
)


def _is_redos_pattern(pattern_src: str) -> str | None:
    """Return a short description if *pattern_src* has a ReDoS-risky construct, else None.

    Checks nested quantifiers (highest confidence) and ambiguous alternation.
    Returns the matched snippet so the finding description is concrete.
    """
    m = _REDOS_NESTED.search(pattern_src)
    if m:
        return f"nested quantifier: {m.group()!r}"

    m = _REDOS_ALTERNATION.search(pattern_src)
    if m:
        a1, a2 = m.group(1), m.group(2)
        # Only flag when alternatives share a common prefix (overlap) or one contains the other
        min_len = min(len(a1), len(a2))
        if min_len > 0 and (a1[:min_len] == a2[:min_len] or a1 in a2 or a2 in a1):
            return f"ambiguous alternation: {m.group()!r}"

    return None


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


def _check_redos(
    root,
    file_path: str,
    lines: list[str],
    repo_url: str,
) -> list[Finding]:
    """Scan all regex literals for catastrophic backtracking patterns (no taint needed)."""
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for node in _walk(root):
        if node.type != "regex":
            continue
        # Extract pattern text from /pattern/flags — strip leading/trailing slashes + flags
        full = node.text.decode("utf-8", errors="replace") if node.text else ""
        if full.startswith("/") and full.count("/") >= 2:
            last_slash = full.rfind("/")
            src = full[1:last_slash]
        else:
            # Fallback: try pattern field or first named child
            pn = node.child_by_field_name("pattern")
            if pn is None and node.named_children:
                pn = node.named_children[0]
            src = pn.text.decode("utf-8", errors="replace") if pn else ""
        if not src:
            continue
        issue = _is_redos_pattern(src)
        if issue:
            line = node.start_point[0] + 1
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.REDOS, Severity.MEDIUM,
                  "JSAST-REDOS-001",
                  f"Regex with catastrophic backtracking risk — {issue}")
    return findings


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

        # ── DOM XSS: el.innerHTML = tainted, location.href = tainted ─────────
        if node.type == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs is not None and rhs is not None and lhs.type == "member_expression":
                prop_n = lhs.child_by_field_name("property")
                obj_n = lhs.child_by_field_name("object")
                if prop_n is not None:
                    prop = prop_n.text.decode("utf-8", errors="replace")
                    rhs_u = _unwrap(rhs)
                    if prop in _DOM_ASSIGN_SINKS and (
                        state.is_tainted_node(rhs_u) or _is_request_source(rhs_u)
                    ):
                        _emit(findings, seen, file_path, line, lines, repo_url,
                              VulnType.XSS, Severity.CRITICAL,
                              "JSAST-DOMXSS-001",
                              f"User-controlled data assigned to .{prop} — DOM-based XSS risk")
                    elif prop in _DOM_LOCATION_ASSIGN:
                        obj_chain = _member_chain(obj_n) if obj_n else []
                        if obj_chain and obj_chain[0] == "location" and (
                            state.is_tainted_node(rhs_u) or _is_request_source(rhs_u)
                        ):
                            _emit(findings, seen, file_path, line, lines, repo_url,
                                  VulnType.OPEN_REDIRECT, Severity.MEDIUM,
                                  "JSAST-DOMXSS-002",
                                  "User-controlled URL assigned to location.href — client-side open redirect")
            continue

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

            # Prototype pollution: merge(target, tainted), deepMerge(obj, tainted)
            elif fname in _MERGE_GLOBAL_FUNCS:
                arg_list = list(args_node.named_children)
                if len(arg_list) >= 2 and any(state.is_tainted_node(a) for a in arg_list[1:]):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.PROTOTYPE_POLLUTION, Severity.HIGH,
                          "JSAST-PROTO-001",
                          f"User-controlled data flows into {fname}() — prototype pollution risk")

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

            # Open redirect: res.redirect(tainted_url)
            elif obj_root in ("res", "response") and prop == "redirect":
                if tainted_args(args_node):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.OPEN_REDIRECT, Severity.MEDIUM,
                          "JSAST-REDIR-001",
                          "User-controlled URL in res.redirect() — open redirect risk")

            # NoSQL injection: collection.find(tainted), db.users.findOne(tainted)
            elif prop in _NOSQL_METHOD_SINKS and tainted_args(args_node):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.NOSQL_INJECTION, Severity.HIGH,
                      "JSAST-NOSQL-001",
                      f"User-controlled data flows into .{prop}() — NoSQL injection risk")

            # Log injection: console.log(tainted), logger.error(tainted)
            elif obj_root in _LOG_ROOTS and prop in _LOG_METHODS:
                if tainted_args(args_node):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.LOG_INJECTION, Severity.LOW,
                          "JSAST-LOG-001",
                          f"User-controlled data flows into {obj_root}.{prop}() — log injection risk")

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

            # SSTI: ejs.render(tainted), pug.render(tainted), _.template(tainted), …
            elif obj_root in _SSTI_ROOTS and prop in _SSTI_RENDER_METHODS:
                if tainted_args(args_node):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.SSTI, Severity.CRITICAL,
                          "JSAST-SSTI-001",
                          f"User-controlled data flows into {obj_root}.{prop}() — SSTI risk")

            # Prototype pollution: _.merge(target, tainted), Object.assign(target, tainted)
            elif ((obj_root in _MERGE_ROOTS and prop in _MERGE_METHODS)
                  or (obj_root == "Object" and prop == "assign")):
                arg_list = list(args_node.named_children)
                if len(arg_list) >= 2 and any(state.is_tainted_node(a) for a in arg_list[1:]):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.PROTOTYPE_POLLUTION, Severity.HIGH,
                          "JSAST-PROTO-001",
                          f"User-controlled data flows into {obj_root}.{prop}() — prototype pollution risk")

            # DOM XSS: document.write(tainted), document.writeln(tainted)
            elif obj_root == "document" and prop in _DOM_WRITE_METHODS:
                if tainted_args(args_node):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.XSS, Severity.CRITICAL,
                          "JSAST-DOMXSS-001",
                          f"User-controlled data flows into document.{prop}() — DOM-based XSS risk")

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
    # ReDoS: pure structural analysis — runs even when file has no request sources
    results = _check_redos(tree.root_node, file_path, lines, repo_url)
    state = _build_taint_state(tree.root_node)
    if not state.tainted and not state.tainted_funcs and not state.tainted_attrs:
        return results
    results += _check_sinks(tree.root_node, state, file_path, lines, repo_url)
    return results


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
