"""Rust AST taint analyzer (tree-sitter-rust).

Detects user-controlled data flowing from CLI args, stdin, and HTTP request
parameters into dangerous sinks via intra-function fixed-point taint propagation.

Rule IDs (RAST-*):
  RAST-SQL-001   SQL injection (sqlx, diesel, rusqlite, tokio-postgres)
  RAST-CMD-001   Command injection (std::process::Command with tainted arg/path)
  RAST-PATH-001  Path traversal (std::fs operations with tainted path)
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
_WEB_PARAM_TYPE_KEYWORDS: frozenset[str] = frozenset({
    "Query", "Path", "Form", "Json", "Body",
    "HttpRequest", "Request", "WebQuery",
    "Params", "Headers",
})

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


# ── Taint expression evaluator ────────────────────────────────────────────────

def _is_tainted(node, tainted: set[str]) -> bool:
    """Return True if this Rust expression carries tainted data."""
    if node is None or _is_literal(node):
        return False
    t = node.type

    if t == "identifier":
        return _txt(node) in tainted

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
        # If type contains any web framework keyword, the param is user-controlled
        if any(kw in type_text for kw in _WEB_PARAM_TYPE_KEYWORDS):
            pat = param.child_by_field_name("pattern")
            name = _txt(pat) if pat else None
            if name:
                tainted.add(name)
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

    _detect_sinks(body, tainted, lines, file_path, findings)


def _analyze_content(content: str, file_path: str) -> list[Finding]:
    try:
        tree = _rust_parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:
        return []

    lines = content.splitlines()
    findings: list[Finding] = []

    for node in _walk(tree.root_node):
        if node.type == "function_item":
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
