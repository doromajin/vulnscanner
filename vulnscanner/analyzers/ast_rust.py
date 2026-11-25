"""Rust AST taint analyzer (tree-sitter-rust).

Detects user-controlled data flowing from CLI args, stdin, and HTTP request
parameters into dangerous sinks via intra-function fixed-point taint propagation.

Rule IDs (RAST-*):
  RAST-SQL-001   SQL injection (sqlx, diesel, rusqlite, tokio-postgres)
  RAST-CMD-001   Command injection (std::process::Command with tainted arg/path)
  RAST-PATH-001  Path traversal (std::fs operations with tainted path)
  RAST-SSRF-001  SSRF (reqwest/ureq/isahc/surf/hyper request with tainted URL)
  RAST-REDIR-001 Open redirect (Location header / Redirect::to with tainted target)
  RAST-XSS-001   XSS (HTML response body / Html() built from tainted data)
  RAST-SQL-002   SQL string built with tainted data (no visible sink in the function)
"""
from __future__ import annotations

import re

try:
    import tree_sitter_rust as _tsr
    from tree_sitter import Language, Parser as _TSParser
    _RUST_LANGUAGE = Language(_tsr.language())
    _rust_parser = _TSParser(_RUST_LANGUAGE)
    _TS_RUST_AVAILABLE = True
except Exception:
    _TS_RUST_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RUST_EXTS = (".rs",)

# ── Web framework parameter types that carry user-controlled data ─────────────
# If a function parameter's type contains any of these keywords, the parameter
# is treated as a taint source (actix-web, axum, warp, rocket patterns).
# Matched as a whole type identifier, never as a substring: std `&Path` / `PathBuf`
# are ordinary filesystem types, and `Params` / `Headers` are arbitrary names.
_WEB_GENERIC_EXTRACTORS: frozenset[str] = frozenset({
    "Query", "Path", "Form", "Json", "Request", "Multipart",
})
_WEB_BARE_EXTRACTORS: frozenset[str] = frozenset({"HttpRequest", "Multipart"})
_GENERIC_TYPE_RE = re.compile(r"(?<![\w])(?:\w+::)*(\w+)\s*<")
_BARE_TYPE_RE = re.compile(r"(?<![\w])(?:\w+::)*(\w+)(?![\w<])")


def _is_web_extractor_type(type_text: str) -> bool:
    """True if the type names an axum/actix/rocket request extractor.

    `Path` only counts in its generic form (`Path<T>`, `web::Path<T>`): std's
    `Path` is unsized and is never generic.
    """
    for m in _GENERIC_TYPE_RE.finditer(type_text):
        if m.group(1) in _WEB_GENERIC_EXTRACTORS:
            return True
    for m in _BARE_TYPE_RE.finditer(type_text):
        if m.group(1) in _WEB_BARE_EXTRACTORS:
            return True
    return False


def _param_pattern_names(pat) -> list[str]:
    """Bound identifiers of a parameter pattern: `p`, `mut p`, `Query(p)`, `Path((a, b))`."""
    if pat is None:
        return []
    t = pat.type
    if t == "identifier":
        return [_txt(pat)]
    if t in ("shorthand_field_identifier",):
        return [_txt(pat)]
    names: list[str] = []
    type_child = pat.child_by_field_name("type") if t == "tuple_struct_pattern" else None
    for child in pat.named_children:
        if type_child is not None and child.id == type_child.id:
            continue
        if t == "field_pattern" and child.type == "field_identifier":
            continue
        names.extend(_param_pattern_names(child))
    return names

# ── Methods that propagate taint from receiver to return value ─────────────────
_PROPAGATING_METHODS: frozenset[str] = frozenset({
    # String / owned conversion
    "clone", "to_string", "to_owned", "into_string", "into_owned",
    "as_str", "as_ref", "as_bytes", "as_slice", "as_deref",
    "to_str", "to_string_lossy",
    # String manipulation (result is still tainted)
    "trim", "trim_start", "trim_end",
    "to_lowercase", "to_uppercase",
    "replace", "replacen",
    "strip_prefix", "strip_suffix",
    "split_once", "rsplit_once",
    "chars", "bytes",
    # Option / Result unwrapping
    "unwrap", "unwrap_or", "unwrap_or_else", "unwrap_or_default",
    "expect",
    "ok", "err", "some",
    # Iterator consumers that collapse to one value
    "collect", "next", "nth",
    "join",
    # Deref / borrow
    "deref", "borrow",
    # Collection access
    "get", "get_or_insert", "get_mut",
    "first", "last", "pop", "remove",
    # Encoding
    "as_encoded_bytes",
    # std::ffi::OsString / PathBuf
    "to_os_string", "into_os_string",
    "to_path_buf", "into_path_buf",
    "display",
    # actix-web / http request accessors: only taint when the receiver is tainted
    "query_string", "uri", "match_info", "headers", "path", "query", "cookie",
    "param", "get_ref", "into_inner",
    # Read
    "lines", "read_line",
})

# ── Free functions that propagate taint ───────────────────────────────────────
# (function_path_suffix → [tainted_arg_indices])
_PROPAGATING_FUNCS: dict[str, list[int]] = {
    "from":    [0],   # String::from(tainted)
    "into":    [0],   # Into::into(tainted)
    "format":  [],    # format!(..., tainted) — handled via macro_invocation
    "concat":  [0, 1, 2, 3],
    # Parse calls (serde_urlencoded::from_str, serde_json::from_str, Query::from_query ...)
    "from_str":   [0],
    "from_query": [0],
    "from_slice": [0],
    "from_bytes": [0],
    "push_str": [1],  # s.push_str(tainted) → s is now tainted
    "push":    [1],
}

# ── SQL sinks ─────────────────────────────────────────────────────────────────
# (arg_index, description)
_SQL_SINKS: dict[str, tuple[int, str]] = {
    # sqlx
    "query":         (0, "SQL injection via sqlx::query() with user-controlled string"),
    "query_as":      (0, "SQL injection via sqlx::query_as() with user-controlled string"),
    "query_scalar":  (0, "SQL injection via sqlx::query_scalar()"),
    "raw":           (0, "SQL injection via diesel::sql_query() or raw SQL"),
    "sql_query":     (0, "SQL injection via diesel::sql_query()"),
    # rusqlite
    "execute":       (1, "SQL injection via rusqlite Connection::execute()"),
    "query_row":     (1, "SQL injection via rusqlite Connection::query_row()"),
    "prepare":       (1, "SQL injection via rusqlite Connection::prepare()"),
    # tokio-postgres
    "simple_query":  (1, "SQL injection via tokio-postgres simple_query()"),
    # postgres crate
    "batch_execute": (1, "SQL injection via postgres batch_execute()"),
}

# ── Command injection sinks ───────────────────────────────────────────────────
_CMD_NEW_FUNCS: frozenset[str] = frozenset({"new"})
_CMD_ARG_FUNCS: frozenset[str] = frozenset({"arg", "args"})
_CMD_EXECUTE_FUNCS: frozenset[str] = frozenset({"output", "spawn", "status"})

# ── Path traversal sinks ──────────────────────────────────────────────────────
# (arg_index, description)
_PATH_SINKS: dict[str, tuple[int, str]] = {
    "open":          (0, "Path traversal via std::fs::File::open() with user-controlled path"),
    "create":        (0, "Path traversal via std::fs::File::create() with user-controlled path"),
    "create_new":    (0, "Path traversal via std::fs::File::create_new()"),
    "read":          (0, "Path traversal via std::fs::read() with user-controlled path"),
    "read_to_string":(0, "Path traversal via std::fs::read_to_string() with user-controlled path"),
    "write":         (0, "Path traversal via std::fs::write() with user-controlled path"),
    "remove_file":   (0, "Path traversal via std::fs::remove_file() with user-controlled path"),
    "copy":          (0, "Path traversal via std::fs::copy() with user-controlled source"),
    "rename":        (0, "Path traversal via std::fs::rename() with user-controlled path"),
    "metadata":      (0, "Path traversal via std::fs::metadata() with user-controlled path"),
    "canonicalize":  (0, "Path traversal via std::fs::canonicalize() with user-controlled path"),
    "read_dir":      (0, "Path traversal via std::fs::read_dir() with user-controlled path"),
    "create_dir":    (0, "Path traversal via std::fs::create_dir() with user-controlled path"),
    "create_dir_all":(0, "Path traversal via std::fs::create_dir_all()"),
    "remove_dir":    (0, "Path traversal via std::fs::remove_dir()"),
    "remove_dir_all":(0, "Path traversal via std::fs::remove_dir_all()"),
}

# ── SSRF / redirect / XSS / SQL-string heuristics ─────────────────────────────
_HTTP_CLIENT_CRATES: frozenset[str] = frozenset({"reqwest", "ureq", "isahc", "surf", "attohttpc", "minreq"})
_HTTP_VERBS: frozenset[str] = frozenset({"get", "post", "put", "delete", "head", "patch"})
_CLIENT_RECV_RE = re.compile(r"(?:Client|Agent|reqwest|ureq|isahc|surf)::")
_CLIENT_NAME_RE = re.compile(r"(?:client|agent)$", re.I)
_REDIRECT_FUNCS: frozenset[str] = frozenset({"to", "temporary", "permanent", "found", "see_other", "moved"})
_HTML_TAG_RE = re.compile(r"<[A-Za-z/!]")
_SQL_BUILD_RE = re.compile(
    r"^\s*(?:select\b.+\bfrom\b|insert\s+into\b|update\b.+\bset\b|delete\s+from\b)",
    re.I | re.S)

# ── AST helpers ───────────────────────────────────────────────────────────────

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _txt(node) -> str:
    if node is None:
        return ""
    try:
        return node.text.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _call_fname(node) -> str:
    """Extract the final segment of the function/method name of a call_expression."""
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    t = fn.type
    if t == "generic_function":  # sqlx::query_as::<_, T>(..), x.collect::<Vec<_>>()
        inner = fn.child_by_field_name("function")
        if inner is not None:
            fn = inner
            t = fn.type
    if t == "identifier":
        return _txt(fn)
    if t == "field_expression":
        field = fn.child_by_field_name("field")
        return _txt(field) if field else ""
    if t == "scoped_identifier":
        raw = _txt(fn)
        return raw.rsplit("::", 1)[-1] if "::" in raw else raw
    # Generic fallback: take last segment, strip call suffix
    raw = _txt(fn)
    last = raw.rsplit("::", 1)[-1]
    return last.split("(")[0].strip()


def _call_recv(node):
    """Return the receiver node for a method call (obj.method(args)) or None."""
    fn = node.child_by_field_name("function")
    if fn is not None and fn.type == "generic_function":
        fn = fn.child_by_field_name("function")
    if fn is not None and fn.type == "field_expression":
        return fn.child_by_field_name("value")
    return None


def _call_args(node) -> list:
    """Return the named argument nodes of a call_expression."""
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return list(args.named_children)


def _pat_identifiers(pattern_node) -> list[str]:
    """Extract all bound identifiers from a let pattern (handles simple and nested)."""
    if pattern_node is None:
        return []
    t = pattern_node.type
    if t == "identifier":
        return [_txt(pattern_node)]
    results: list[str] = []
    for child in pattern_node.named_children:
        if child.type == "identifier":
            results.append(_txt(child))
        elif child.type not in ("type_identifier", "scoped_type_identifier"):
            results.extend(_pat_identifiers(child))
    return results


def _is_literal(node) -> bool:
    return node is not None and node.type in (
        "string_literal", "integer_literal", "float_literal",
        "boolean_literal", "char_literal", "raw_string_literal",
    )


# Combinators that run a closure over the receiver's value; the result is
# tainted when the closure body, with its parameters tainted, is tainted.
_CLOSURE_COMBINATORS: frozenset[str] = frozenset({
    "map", "and_then", "or_else", "map_or", "map_or_else", "filter", "filter_map",
    "inspect", "then",
})


def _closure_result_tainted(closure, tainted: set[str]) -> bool:
    params = closure.child_by_field_name("parameters")
    names: set[str] = set()
    if params is not None:
        for sub in _walk(params):
            if sub.type == "identifier":
                names.add(_txt(sub))
    return _is_tainted(closure.child_by_field_name("body"), tainted | names)


_INLINE_CAPTURE_RE = re.compile(r"(?<!\{)\{([A-Za-z_]\w*)\s*(?::[^{}]*)?\}")


def _format_literal(node) -> tuple[str, bool]:
    """(format-string text, is_format_macro) of a `format!(..)` macro_invocation."""
    if node is None or node.type != "macro_invocation" or not node.named_children:
        return "", False
    if _txt(node.named_children[0]).rsplit("::", 1)[-1] != "format" or len(node.named_children) < 2:
        return "", False
    for child in node.named_children[1].named_children:
        if child.type in ("string_literal", "raw_string_literal"):
            return _txt(child).lstrip("r#").strip('"'), True
        break
    return "", True


def _unwrap_value(node):
    """Strip `&x`, `(x)`, `x.to_string()/into()/clone()` wrappers down to the core expression."""
    while node is not None:
        if node.type in ("reference_expression", "parenthesized_expression"):
            node = next(iter(node.named_children), None)
        elif node.type == "call_expression" and _call_fname(node) in (
                "to_string", "into", "to_owned", "clone", "as_str", "to_str") and _call_recv(node) is not None:
            node = _call_recv(node)
        else:
            break
    return node


def _has_local_prefix(node) -> bool:
    """True for values that begin with a fixed same-site path ("/home/{}", "/a" + x).

    A bare "/" followed by a placeholder is not enough (protocol-relative "//host")."""
    node = _unwrap_value(node)
    if node is None:
        return False
    if node.type == "macro_invocation":
        lit, ok = _format_literal(node)
        prefix = lit.split("{", 1)[0]
        return ok and len(prefix) >= 2 and prefix[0] == "/" and prefix[1] not in "/\\"
    if node.type == "binary_expression":
        left = node.child_by_field_name("left")
        if left is not None and left.type == "string_literal":
            lit = _txt(left).strip('"')
            return len(lit) >= 2 and lit[0] == "/" and lit[1] not in "/\\"
    return False


def _has_fixed_host(node) -> bool:
    """format!("https://api.example.com/{}", x): the host is literal, only the path varies."""
    node = _unwrap_value(node)
    lit, ok = _format_literal(node)
    return ok and re.match(r"^[a-zA-Z][\w+.-]*://[^/{}\s]+/", lit) is not None


# ── Taint expression evaluator ────────────────────────────────────────────────

def _is_tainted(node, tainted: set[str]) -> bool:
    """Return True if this Rust expression carries tainted data."""
    if node is None or _is_literal(node):
        return False
    t = node.type

    if t == "identifier":
        return _txt(node) in tainted

    if t == "field_expression":
        # p.name — tainted if the base value is tainted
        return _is_tainted(node.child_by_field_name("value"), tainted)

    if t == "index_expression":
        # args[1] — tainted if args is tainted
        nc = node.named_children
        return bool(nc) and _txt(nc[0]) in tainted

    if t in ("reference_expression", "try_expression", "await_expression"):
        # &x, x?, x.await — tainted if inner is tainted
        inner = next((c for c in node.named_children), None)
        return _is_tainted(inner, tainted)

    if t == "unary_expression":
        # *x — tainted if x is tainted; !x / -x — not tainted semantically
        children = node.children
        if children and _txt(children[0]) == "*":
            inner = next((c for c in node.named_children), None)
            return _is_tainted(inner, tainted)
        return False

    if t == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return _is_tainted(left, tainted) or _is_tainted(right, tainted)

    if t == "block":
        # Block expression: tainted if last (return) expression is tainted
        stmts = [c for c in node.named_children]
        last = stmts[-1] if stmts else None
        return _is_tainted(last, tainted)

    if t == "if_expression":
        # if cond { a } else { b } — tainted if either branch tainted
        arms = [c for c in node.named_children if c.type == "block"]
        return any(_is_tainted(a, tainted) for a in arms)

    if t in ("parenthesized_expression", "type_cast_expression"):
        inner = next((c for c in node.named_children
                      if c.type not in ("type_identifier", "scoped_type_identifier",
                                        "primitive_type", "generic_type")),
                     None)
        return _is_tainted(inner, tainted)

    if t == "call_expression":
        fname = _call_fname(node)
        args = _call_args(node)
        recv = _call_recv(node)

        # Method on tainted receiver that propagates taint
        if fname in _PROPAGATING_METHODS:
            if recv and _is_tainted(recv, tainted):
                return True

        # opt.map(|s| ...) etc.: tainted receiver whose closure keeps its input
        if fname in _CLOSURE_COMBINATORS and recv and _is_tainted(recv, tainted):
            for a in args:
                if a.type == "closure_expression":
                    if _closure_result_tainted(a, tainted):
                        return True
                elif _is_tainted(a, tainted):
                    return True

        # String::from(tainted), Into::into(tainted)
        if fname in _PROPAGATING_FUNCS:
            src_indices = _PROPAGATING_FUNCS[fname]
            if not src_indices:  # empty = check all args
                return any(_is_tainted(a, tainted) for a in args)
            return any(i < len(args) and _is_tainted(args[i], tainted)
                       for i in src_indices)

        # env::args() always returns tainted iterator
        if fname in ("args", "args_os"):
            fn = node.child_by_field_name("function")
            if fn and "env" in _txt(fn):
                return True

        # stdin().read_line(&mut buf) — return value is result, buf is tainted via propagation
        if fname in ("read_line", "read_to_string", "read"):
            if recv and ("stdin" in _txt(recv) or "reader" in _txt(recv).lower()):
                return True

        return False

    if t == "macro_invocation":
        macro_name = _txt(node.named_children[0]) if node.named_children else ""
        if macro_name in ("format", "write", "writeln", "println", "eprintln",
                          "print", "eprint", "concat"):
            # format!("...", x, y) — tainted if any non-string-literal arg is tainted
            if len(node.named_children) > 1:
                token_tree = node.named_children[1]
                for child in token_tree.named_children:
                    if child.type == "identifier" and _txt(child) in tainted:
                        return True
                # inline captures: format!("{name} ..")
                lit, _ = _format_literal(node)
                if any(n in tainted for n in _INLINE_CAPTURE_RE.findall(lit)):
                    return True
        return False

    return False


# ── Per-function parameter seeding ────────────────────────────────────────────

def _seed_function_params(func_node, tainted: set[str]) -> None:
    """Seed taint for:
    1. main()'s env::args() (handled via call detection, not params)
    2. Web framework handler parameters (actix-web, axum, rocket, warp)
    """
    params = func_node.child_by_field_name("parameters")
    if params is None:
        return
    for param in params.named_children:
        if param.type not in ("parameter", "self_parameter"):
            continue
        # Get the type annotation
        type_node = param.child_by_field_name("type")
        if type_node is None:
            continue
        type_text = _txt(type_node)
        # A request-extractor type means the bound names are user-controlled
        if _is_web_extractor_type(type_text):
            tainted.update(_param_pattern_names(param.child_by_field_name("pattern")))
        # String / &str params in public handlers — too broad, skip


# ── Propagation pass ──────────────────────────────────────────────────────────

def _propagate(body_node, tainted: set[str]) -> bool:
    """One fixed-point propagation pass. Returns True if tainted set grew."""
    changed = False

    for node in _walk(body_node):
        t = node.type

        # let pat = expr;
        if t == "let_declaration":
            pat = node.child_by_field_name("pattern")
            val = node.child_by_field_name("value")
            if val and _is_tainted(val, tainted):
                for name in _pat_identifiers(pat):
                    if name not in tainted:
                        tainted.add(name)
                        changed = True

        # x = expr; (reassignment)
        elif t == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs and lhs.type == "identifier" and rhs and _is_tainted(rhs, tainted):
                name = _txt(lhs)
                if name not in tainted:
                    tainted.add(name)
                    changed = True

        # let args: Vec<_> = env::args().collect(); → args is tainted
        elif t == "call_expression":
            fname = _call_fname(node)
            recv = _call_recv(node)
            args = _call_args(node)

            # read_line(&mut buf) → buf is tainted (buf is a mutable reference arg)
            if fname == "read_line" and args:
                # arg is typically &mut buf → strip & and mut
                arg0 = args[0]
                buf_name = None
                for sub in _walk(arg0):
                    if sub.type == "identifier":
                        buf_name = _txt(sub)
                        break
                if buf_name and buf_name not in tainted:
                    tainted.add(buf_name)
                    changed = True

            # push_str on a var: s.push_str(tainted) → s becomes tainted
            if fname == "push_str" and recv and args:
                if _is_tainted(args[0], tainted):
                    recv_name = _txt(recv) if recv.type == "identifier" else None
                    if recv_name and recv_name not in tainted:
                        tainted.add(recv_name)
                        changed = True

        # cin-like: stdin().read_line(&mut line) — handled above
        # macro: let s = format!("...", user); → s is tainted
        elif t == "macro_invocation":
            pass  # handled via let_declaration value check

    return changed


# ── Sink detection pass ───────────────────────────────────────────────────────

def _detect_sinks(body_node, tainted: set[str], lines: list[str],
                  file_path: str, findings: list[Finding]) -> None:
    """Check all call_expressions against sink definitions."""
    seen: set[tuple] = set()

    for node in _walk(body_node):
        if node.type != "call_expression":
            continue

        fname = _call_fname(node)
        args = _call_args(node)
        recv = _call_recv(node)
        line_no = node.start_point[0] + 1
        line_text = (lines[node.start_point[0]].strip()
                     if node.start_point[0] < len(lines) else "")

        def _emit(rule_id, vtype, sev, desc):
            key = (file_path, line_no, rule_id)
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    vuln_type=vtype, severity=sev,
                    file_path=file_path, line_number=line_no,
                    line_content=line_text, description=desc,
                    rule_id=rule_id,
                ))

        # SQL sinks
        if fname in _SQL_SINKS:
            arg_idx, desc = _SQL_SINKS[fname]
            # Method-call style: conn.execute(sql, params) → arg 0 of args is sql
            # Function-call style: sqlx::query(sql) → arg 0 is sql
            # Determine which arg to check
            if arg_idx == 1 and recv:
                # It's a method call: the sql is args[0]
                check_idx = 0
            else:
                check_idx = arg_idx
            if check_idx < len(args) and _is_tainted(args[check_idx], tainted):
                _emit("RAST-SQL-001", VulnType.SQL_INJECTION, Severity.CRITICAL, desc)

        # Command injection
        fn_full = _txt(node.child_by_field_name("function") or node)
        if "Command" in fn_full:
            if fname in _CMD_NEW_FUNCS:
                # Command::new(tainted_path) — the command path itself is tainted
                if args and _is_tainted(args[0], tainted):
                    _emit("RAST-CMD-001", VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                          "Command injection: tainted string passed as command to Command::new()")
            elif fname in _CMD_ARG_FUNCS:
                # .arg(tainted) in a Command builder chain
                if args and any(_is_tainted(a, tainted) for a in args):
                    _emit("RAST-CMD-001", VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                          "Command injection: user-controlled argument passed to Command::arg()")

        # SSRF (CWE-918)
        fn_text = _txt(node.child_by_field_name("function") or node)
        ssrf_arg = None
        if recv is None:
            crate = fn_text.split("::", 1)[0]
            if "::" in fn_text and crate in _HTTP_CLIENT_CRATES:
                if fname in _HTTP_VERBS and args:
                    ssrf_arg = args[0]
                elif fname == "request" and len(args) > 1:
                    ssrf_arg = args[1]
        else:
            rtxt = _txt(recv)
            last = recv.child_by_field_name("field") if recv.type == "field_expression" else recv
            named_client = recv.type in ("identifier", "field_expression") and \
                _CLIENT_NAME_RE.search(_txt(last) or "") is not None
            if named_client or _CLIENT_RECV_RE.search(rtxt):
                if fname in _HTTP_VERBS and args:
                    ssrf_arg = args[0]
                elif fname == "request" and len(args) > 1:
                    ssrf_arg = args[1]
            if fname == "uri" and args and re.search(r"Request|builder", rtxt, re.I):
                ssrf_arg = args[0]
        if ssrf_arg is not None and _is_tainted(ssrf_arg, tainted) and not _has_fixed_host(ssrf_arg):
            _emit("RAST-SSRF-001", VulnType.SSRF, Severity.HIGH,
                  "SSRF: user-controlled URL passed to an HTTP client request")

        # Open redirect (CWE-601)
        redir_arg = None
        if fname in ("header", "append_header", "insert_header") and args:
            if fname == "header" and len(args) > 1 and "location" in _txt(args[0]).lower():
                redir_arg = args[1]
            elif fname != "header" and args[0].type == "tuple_expression":
                items = list(args[0].named_children)
                if len(items) == 2 and "location" in _txt(items[0]).lower():
                    redir_arg = items[1]
        elif fname in _REDIRECT_FUNCS and args and recv is None and "Redirect" in fn_text:
            redir_arg = args[0]
        if redir_arg is not None and _is_tainted(redir_arg, tainted) \
                and not _has_local_prefix(redir_arg):
            _emit("RAST-REDIR-001", VulnType.OPEN_REDIRECT, Severity.MEDIUM,
                  "Open redirect: user-controlled target used as redirect location")

        # XSS (CWE-79)
        xss_arg = None
        if fname == "body" and recv is not None and args and re.search(r"HttpResponse|Response::build", _txt(recv)):
            ct = re.search(r"content_type\(([^)]*)\)", _txt(recv))
            if ct is not None:
                if "html" in ct.group(1).lower():
                    xss_arg = args[0]
            else:
                lit, ok = _format_literal(_unwrap_value(args[0]))
                if ok and _HTML_TAG_RE.search(lit):
                    xss_arg = args[0]
        elif recv is None and args and (fname in ("Html", "RawHtml") or fn_text.endswith("reply::html")):
            xss_arg = args[0]
        if xss_arg is not None and _is_tainted(xss_arg, tainted):
            _emit("RAST-XSS-001", VulnType.XSS, Severity.HIGH,
                  "XSS: user-controlled data embedded in an HTML response body without escaping")

        # Path traversal
        if fname in _PATH_SINKS:
            arg_idx, desc = _PATH_SINKS[fname]
            # Handle both free function (fs::open(path)) and method call styles
            check_args = args
            if arg_idx < len(check_args) and _is_tainted(check_args[arg_idx], tainted):
                _emit("RAST-PATH-001", VulnType.PATH_TRAVERSAL, Severity.HIGH, desc)
            # Also handle: File::open(path) where the path is the first arg
            elif fname == "open" and args and _is_tainted(args[0], tainted):
                _emit("RAST-PATH-001", VulnType.PATH_TRAVERSAL, Severity.HIGH, desc)


def _detect_sql_strings(body_node, tainted: set[str], lines: list[str],
                        file_path: str, findings: list[Finding]) -> None:
    """format!("SELECT .. {}", tainted): the query is built unsafely even when it is
    executed through a wrapper this analyzer cannot see."""
    if any(f.rule_id == "RAST-SQL-001" for f in findings):
        return
    for node in _walk(body_node):
        if node.type != "macro_invocation":
            continue
        lit, ok = _format_literal(node)
        if ok and _SQL_BUILD_RE.search(lit) and _is_tainted(node, tainted):
            ln = node.start_point[0]
            findings.append(Finding(
                vuln_type=VulnType.SQL_INJECTION, severity=Severity.HIGH,
                file_path=file_path, line_number=ln + 1,
                line_content=lines[ln].strip() if ln < len(lines) else "",
                description="SQL query string built with user-controlled data via format!() "
                            "(use bound parameters instead)",
                rule_id="RAST-SQL-002"))


# ── Top-level analysis ────────────────────────────────────────────────────────

def _analyze_function(func_node, lines: list[str],
                      file_path: str, findings: list[Finding]) -> None:
    tainted: set[str] = set()
    _seed_function_params(func_node, tainted)

    body = func_node.child_by_field_name("body")
    if body is None:
        return

    for _ in range(10):
        if not _propagate(body, tainted):
            break

    local: list[Finding] = []
    _detect_sinks(body, tainted, lines, file_path, local)
    _detect_sql_strings(body, tainted, lines, file_path, local)
    findings.extend(local)


def _is_test_attr(attr_node) -> bool:
    txt = _txt(attr_node).replace(" ", "")
    return "cfg(test)" in txt or txt in ("#[test]", "#[tokio::test]") or txt.startswith("#[tokio::test(")


def _has_test_attr(item) -> bool:
    prev = item.prev_named_sibling
    while prev is not None and prev.type in ("attribute_item", "line_comment", "block_comment"):
        if prev.type == "attribute_item" and _is_test_attr(prev):
            return True
        prev = prev.prev_named_sibling
    return False


def _in_test_code(node) -> bool:
    """True for #[test] fns and anything inside a #[cfg(test)] item."""
    cur = node
    while cur is not None:
        if cur.type in ("function_item", "mod_item", "impl_item") and _has_test_attr(cur):
            return True
        cur = cur.parent
    return False


def _analyze_content(content: str, file_path: str) -> list[Finding]:
    try:
        tree = _rust_parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:
        return []

    lines = content.splitlines()
    findings: list[Finding] = []

    for node in _walk(tree.root_node):
        if node.type == "function_item" and not _in_test_code(node):
            _analyze_function(node, lines, file_path, findings)

    return findings


# ── Analyzer class ────────────────────────────────────────────────────────────

class RustASTAnalyzer(BaseAnalyzer):
    """Rust AST taint analyzer (.rs)."""

    supported_extensions = _RUST_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_RUST_AVAILABLE:
            return []
        return _analyze_content(content, file_path)
