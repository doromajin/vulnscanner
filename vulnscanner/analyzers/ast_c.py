"""C/C++ AST taint analyzer (tree-sitter-c / tree-sitter-cpp).

Detects user-controlled data (argv, stdin, network recv) flowing into dangerous
sinks via intra-function fixed-point taint propagation with optional
intra-file interprocedural analysis and macro expansion.

Rule IDs (CAST-*):
  CAST-SQL-001   SQL injection (mysql_query, sqlite3_exec, PQexec, ODBC)
  CAST-CMD-001   Command injection (system, popen, exec* family, ShellExecute)
  CAST-FMT-001   Format string (printf/fprintf/syslog with tainted format arg)
  CAST-PATH-001  Path traversal (fopen/open/unlink/rename with tainted path)
  CAST-BUF-001   Buffer overflow (strcpy/strcat/sprintf with tainted src, no bounds)
  CAST-MEM-001   Inherently unsafe functions (gets, mktemp, tmpnam, getwd)
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

try:
    import tree_sitter_c as _tsc
    import tree_sitter_cpp as _tscpp
    from tree_sitter import Language, Parser as _TSParser
    _C_LANGUAGE = Language(_tsc.language())
    _CPP_LANGUAGE = Language(_tscpp.language())
    _c_parser = _TSParser(_C_LANGUAGE)
    _cpp_parser = _TSParser(_CPP_LANGUAGE)
    _TS_C_AVAILABLE = True
except Exception:
    _TS_C_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_C_EXTS = (".c", ".h")
_CPP_EXTS = (".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx")


# ── Taint propagating functions ───────────────────────────────────────────────
# (dst_arg_index, [src_arg_indices])
# dst_arg_index = -1 means the return value is tainted (caller assigns it to a var)
_PROP_DST_SRC: dict[str, tuple[int, list[int]]] = {
    "strcpy":   (0, [1]),
    "strncpy":  (0, [1]),
    "strcat":   (0, [0, 1]),
    "strncat":  (0, [0, 1]),
    "sprintf":  (0, list(range(1, 8))),
    "snprintf": (0, list(range(2, 9))),
    "vsprintf": (0, [1, 2]),
    "vsnprintf":(0, [2, 3]),
    "memcpy":   (0, [1]),
    "memmove":  (0, [1]),
    "strdup":   (-1, [0]),
    "strndup":  (-1, [0]),
    "strtok":   (-1, [0]),
    "strtok_r": (-1, [0]),
}

# Input-reading functions that taint a buffer argument
# (buf_arg_index,)  — always taint regardless of other args
_INPUT_BUF: dict[str, int] = {
    "gets":      0,  # also CAST-MEM-001
    "fgets":     0,
    "read":      1,
    "recv":      1,
    "recvfrom":  1,
    "recvmsg":   1,
}

# ── Sinks ─────────────────────────────────────────────────────────────────────
# Each value: (tainted_arg_index, rule_id, vuln_type, severity, description)

def _sql(idx, desc):
    return (idx, "CAST-SQL-001", VulnType.SQL_INJECTION, Severity.CRITICAL, desc)

def _cmd(idx, desc):
    return (idx, "CAST-CMD-001", VulnType.COMMAND_INJECTION, Severity.CRITICAL, desc)

def _fmt(idx, desc):
    return (idx, "CAST-FMT-001", VulnType.LOG_INJECTION, Severity.HIGH, desc)

def _path(idx, desc):
    return (idx, "CAST-PATH-001", VulnType.PATH_TRAVERSAL, Severity.HIGH, desc)

def _buf(idx, desc):
    return (idx, "CAST-BUF-001", VulnType.TRUST_BOUNDARY_VIOLATION, Severity.HIGH, desc)

_SINKS: dict[str, tuple] = {
    # SQL
    "mysql_query":        _sql(1, "SQL injection via mysql_query() with user-controlled query"),
    "mysql_real_query":   _sql(1, "SQL injection via mysql_real_query()"),
    "sqlite3_exec":       _sql(1, "SQL injection via sqlite3_exec() with user-controlled query"),
    "sqlite3_prepare":    _sql(1, "SQL injection via sqlite3_prepare()"),
    "sqlite3_prepare_v2": _sql(1, "SQL injection via sqlite3_prepare_v2()"),
    "PQexec":             _sql(1, "SQL injection via libpq PQexec()"),
    "PQexecParams":       _sql(1, "SQL injection via libpq PQexecParams()"),
    "PQprepare":          _sql(2, "SQL injection via libpq PQprepare()"),
    "SQLExecDirect":      _sql(1, "SQL injection via ODBC SQLExecDirect()"),
    "SQLExecDirectW":     _sql(1, "SQL injection via ODBC SQLExecDirectW()"),
    "OCIStmtPrepare":     _sql(1, "SQL injection via Oracle OCI OCIStmtPrepare()"),
    # Command
    "system":        _cmd(0, "Command injection via system() with user-controlled string"),
    "popen":         _cmd(0, "Command injection via popen() with user-controlled string"),
    "execv":         _cmd(0, "Command injection via execv()"),
    "execvp":        _cmd(0, "Command injection via execvp()"),
    "execvpe":       _cmd(0, "Command injection via execvpe()"),
    "execve":        _cmd(0, "Command injection via execve()"),
    "execl":         _cmd(0, "Command injection via execl()"),
    "execlp":        _cmd(0, "Command injection via execlp()"),
    "execle":        _cmd(0, "Command injection via execle()"),
    "wordexp":       _cmd(0, "Command injection via wordexp() shell word expansion"),
    "ShellExecute":  _cmd(2, "Command injection via Win32 ShellExecute()"),
    "ShellExecuteA": _cmd(2, "Command injection via Win32 ShellExecuteA()"),
    "ShellExecuteW": _cmd(2, "Command injection via Win32 ShellExecuteW()"),
    "CreateProcessA":_cmd(1, "Command injection via Win32 CreateProcessA()"),
    "CreateProcessW":_cmd(1, "Command injection via Win32 CreateProcessW()"),
    "WinExec":       _cmd(0, "Command injection via Win32 WinExec()"),
    # Format string (tainted format argument)
    "printf":    _fmt(0, "Format string: user-controlled format in printf()"),
    "vprintf":   _fmt(0, "Format string: user-controlled format in vprintf()"),
    "fprintf":   _fmt(1, "Format string: user-controlled format in fprintf()"),
    "vfprintf":  _fmt(1, "Format string: user-controlled format in vfprintf()"),
    "dprintf":   _fmt(1, "Format string: user-controlled format in dprintf()"),
    "sprintf":   _fmt(1, "Format string: user-controlled format in sprintf()"),
    "snprintf":  _fmt(2, "Format string: user-controlled format in snprintf()"),
    "vsprintf":  _fmt(1, "Format string: user-controlled format in vsprintf()"),
    "vsnprintf": _fmt(2, "Format string: user-controlled format in vsnprintf()"),
    "syslog":    _fmt(1, "Format string: user-controlled format in syslog()"),
    "vsyslog":   _fmt(1, "Format string: user-controlled format in vsyslog()"),
    "wprintf":   _fmt(0, "Format string: user-controlled format in wprintf()"),
    "fwprintf":  _fmt(1, "Format string: user-controlled format in fwprintf()"),
    "swprintf":  _fmt(2, "Format string: user-controlled format in swprintf()"),
    # Path traversal
    "fopen":    _path(0, "Path traversal via fopen() with user-controlled path"),
    "freopen":  _path(0, "Path traversal via freopen() with user-controlled path"),
    "open":     _path(0, "Path traversal via open() with user-controlled path"),
    "openat":   _path(1, "Path traversal via openat() with user-controlled path"),
    "creat":    _path(0, "Path traversal via creat() with user-controlled path"),
    "unlink":   _path(0, "Path traversal via unlink() with user-controlled path"),
    "unlinkat": _path(1, "Path traversal via unlinkat()"),
    "rename":   _path(0, "Path traversal via rename() with user-controlled source"),
    "mkdir":    _path(0, "Path traversal via mkdir() with user-controlled path"),
    "rmdir":    _path(0, "Path traversal via rmdir() with user-controlled path"),
    "stat":     _path(0, "Path traversal via stat() with user-controlled path"),
    "lstat":    _path(0, "Path traversal via lstat() with user-controlled path"),
    "access":   _path(0, "Path traversal via access() with user-controlled path"),
    "chmod":    _path(0, "Path traversal via chmod() with user-controlled path"),
    "chown":    _path(0, "Path traversal via chown() with user-controlled path"),
    "remove":   _path(0, "Path traversal via remove() with user-controlled path"),
    "link":     _path(0, "Path traversal via link()"),
    "symlink":  _path(0, "Path traversal via symlink()"),
    "CreateFileA": _path(0, "Path traversal via Win32 CreateFileA()"),
    "CreateFileW": _path(0, "Path traversal via Win32 CreateFileW()"),
    "DeleteFileA": _path(0, "Path traversal via Win32 DeleteFileA()"),
    "DeleteFileW": _path(0, "Path traversal via Win32 DeleteFileW()"),
    # Buffer overflow (tainted source, no bounds check)
    "strcpy":    _buf(1, "Buffer overflow: strcpy() copies unbounded user-controlled src"),
    "strcat":    _buf(1, "Buffer overflow: strcat() appends unbounded user-controlled src"),
    "gets":      _buf(0, "Buffer overflow: gets() reads unbounded input (always unsafe)"),
    "scanf":     _buf(1, "Buffer overflow: scanf() with %s reads unbounded user input"),
    "sscanf":    _buf(2, "Buffer overflow: sscanf() with %s reads unbounded user input"),
}

# Functions that are always dangerous regardless of taint
# (rule_id, severity, vuln_type, description)
_ALWAYS_UNSAFE: dict[str, tuple] = {
    "gets":   ("CAST-MEM-001", Severity.CRITICAL, VulnType.TRUST_BOUNDARY_VIOLATION,
               "Inherently unsafe: gets() has no bounds check — use fgets() instead"),
    "getwd":  ("CAST-MEM-001", Severity.MEDIUM, VulnType.TRUST_BOUNDARY_VIOLATION,
               "Inherently unsafe: getwd() may overflow fixed-size buffer — use getcwd()"),
    "mktemp": ("CAST-MEM-001", Severity.MEDIUM, VulnType.RACE_CONDITION,
               "Inherently unsafe: mktemp() has TOCTOU race condition — use mkstemp()"),
    "tmpnam": ("CAST-MEM-001", Severity.MEDIUM, VulnType.RACE_CONDITION,
               "Inherently unsafe: tmpnam() has TOCTOU race condition — use mkstemp()"),
}


# ── Macro expansion / preprocessing ──────────────────────────────────────────

_CLANG_AVAIL: bool | None = None


def _expand_defines(content: str) -> str:
    """Expand simple #define UPPER lower portability aliases (no external deps).

    Handles patterns like:  #define SYSTEM system
    Does NOT handle function-like macros or multi-token replacements.
    """
    defines: dict[str, str] = {}
    for m in re.finditer(
        r'^[ \t]*#[ \t]*define[ \t]+([A-Z_][A-Z0-9_]*)[ \t]+([a-z_][a-z0-9_]*)[ \t]*(?:#.*)?$',
        content, re.MULTILINE
    ):
        defines[m.group(1)] = m.group(2)
    for macro, repl in defines.items():
        content = re.sub(r'\b' + re.escape(macro) + r'\b', repl, content)
    return content


def _try_clang_preprocess(content: str, lang: str = "c") -> str | None:
    """Run `clang -E -P` to expand macros. Returns None if clang is unavailable."""
    global _CLANG_AVAIL
    if _CLANG_AVAIL is False:
        return None
    # Strip #include lines so clang doesn't need header search paths
    stripped = re.sub(r'^[ \t]*#[ \t]*include\b.*$', '', content, flags=re.MULTILINE)
    try:
        r = subprocess.run(
            ["clang", "-E", "-P", "-w", "-ferror-limit=0",
             "-Wno-everything", "-x", lang, "-"],
            input=stripped.encode("utf-8", errors="replace"),
            capture_output=True, timeout=15,
        )
        if _CLANG_AVAIL is None:
            _CLANG_AVAIL = True
        if r.stdout:
            return r.stdout.decode("utf-8", errors="replace")
    except FileNotFoundError:
        _CLANG_AVAIL = False
    except Exception:
        pass
    return None


def _preprocess(content: str, lang: str = "c") -> str:
    """Preprocess C/C++ source: try clang -E, fall back to regex define expansion."""
    result = _try_clang_preprocess(content, lang)
    if result:
        return result
    return _expand_defines(content)


# ── Interprocedural function summaries ────────────────────────────────────────

@dataclass
class _FuncSummary:
    """Per-function taint summary built during intra-file interprocedural analysis."""
    returns_tainted: bool = False
    # Indices of parameters observed to receive tainted arguments at call sites
    param_tainted: set[int] = field(default_factory=set)


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
    """Return the base function name of a call_expression."""
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    raw = _txt(fn)
    # Strip namespace prefix: std::system → system, ns::func → func
    if "::" in raw:
        return raw.rsplit("::", 1)[-1]
    # obj->method or obj.field_expression — return last segment
    if fn.type in ("field_expression", "qualified_identifier"):
        field = fn.child_by_field_name("field") or fn.child_by_field_name("name")
        return _txt(field) if field else raw
    return raw


def _call_receiver(node):
    """Return the receiver node for a method call obj.method(args) / obj->method(args)."""
    fn = node.child_by_field_name("function")
    if fn is not None and fn.type == "field_expression":
        return fn.child_by_field_name("argument")
    return None


# C++ member functions that propagate taint from receiver to return value.
# Conservative: only data-returning accessors, not size/empty/find queries.
_CPP_DATA_ACCESSORS: frozenset[str] = frozenset({
    "c_str", "data", "get", "str",
    "substr", "append", "insert", "replace",
    "begin", "end", "front", "back",
})


def _call_args(node) -> list:
    """Return the named argument nodes of a call_expression."""
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.named_children]


def _first_identifier(node) -> str | None:
    """Walk node tree and return the first identifier text found."""
    if node is None:
        return None
    if node.type == "identifier":
        return _txt(node)
    for child in node.named_children:
        result = _first_identifier(child)
        if result:
            return result
    return None


def _is_literal(node) -> bool:
    return node is not None and node.type in (
        "string_literal", "number_literal", "char_literal",
        "true", "false", "null", "nullptr",
        "integer_literal", "float_literal",
    )


# ── Taint expression evaluator ────────────────────────────────────────────────

def _is_tainted(node, tainted: set[str],
                summaries: dict[str, _FuncSummary] | None = None) -> bool:
    """Return True if the AST expression node carries tainted data."""
    if node is None or _is_literal(node):
        return False
    t = node.type

    if t == "identifier":
        return _txt(node) in tainted

    if t == "subscript_expression":
        # argv[1] — tainted if base variable is tainted
        nc = node.named_children
        return bool(nc) and _txt(nc[0]) in tainted

    if t in ("parenthesized_expression",):
        inner = next((c for c in node.named_children), None)
        return _is_tainted(inner, tainted, summaries)

    if t == "cast_expression":
        # (char *)expr — tainted if inner expr is tainted
        inner = next(
            (c for c in node.named_children
             if c.type not in ("type_descriptor", "abstract_type_specifier",
                               "abstract_declarator", "type_qualifier")),
            None,
        )
        return _is_tainted(inner, tainted, summaries)

    if t == "pointer_expression":
        # *expr — tainted if expr is tainted; &expr is NOT tainted data
        op = node.children[0]
        if _txt(op) == "&":
            return False
        inner = next((c for c in node.named_children), None)
        return _is_tainted(inner, tainted, summaries)

    if t in ("binary_expression", "comma_expression"):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return _is_tainted(left, tainted, summaries) or _is_tainted(right, tainted, summaries)

    if t == "conditional_expression":
        nc = node.named_children
        return any(_is_tainted(c, tainted, summaries) for c in nc[1:])

    if t in ("field_expression",):
        # obj->field or obj.field
        obj = node.child_by_field_name("argument")
        return _is_tainted(obj, tainted, summaries)

    if t == "call_expression":
        fname = _call_fname(node)
        args = _call_args(node)
        # C++ method on tainted object: path.c_str(), str.data(), etc.
        receiver = _call_receiver(node)
        if receiver and fname in _CPP_DATA_ACCESSORS and _is_tainted(receiver, tainted, summaries):
            return True
        # propagating: strdup(tainted) → tainted return
        if fname in _PROP_DST_SRC:
            dst_idx, src_indices = _PROP_DST_SRC[fname]
            if dst_idx == -1:
                return any(i < len(args) and _is_tainted(args[i], tainted, summaries)
                           for i in src_indices)
        if fname in ("strdup", "strndup", "strtok", "strtok_r", "strchr", "strrchr",
                     "strpbrk", "index", "rindex"):
            return bool(args) and _is_tainted(args[0], tainted, summaries)
        # Input calls always return tainted
        if fname in _INPUT_BUF:
            return True
        # Interprocedural: known-tainted return value from intra-file function
        if summaries and fname in summaries and summaries[fname].returns_tainted:
            return True
        return False

    return False


# ── Per-function analysis ─────────────────────────────────────────────────────

def _seed_main_argv(func_node: object, tainted: set[str]) -> None:
    """If this is main(), seed argv as tainted."""
    decl = func_node.child_by_field_name("declarator")
    if decl is None:
        return
    # Find function name
    fname = _first_identifier(decl)
    if fname != "main":
        return
    # Find parameter list
    param_list = next(
        (n for n in _walk(decl) if n.type == "parameter_list"), None
    )
    if param_list is None:
        return
    params = [c for c in param_list.named_children
              if c.type == "parameter_declaration"]
    if len(params) < 2:
        return
    # argv is the second parameter — find its identifier
    argv_name = None
    for n in _walk(params[1]):
        if n.type == "identifier":
            argv_name = _txt(n)
            break
    if argv_name:
        tainted.add(argv_name)


def _propagate(body_node, tainted: set[str],
               summaries: dict[str, _FuncSummary] | None = None,
               call_sites: dict[str, set[int]] | None = None) -> bool:
    """One propagation pass; returns True if tainted set grew.

    summaries: optional intra-file function taint summaries.
    call_sites: optional dict to accumulate which param indices of each
                callee receive tainted args (for interprocedural seeding).
    """
    changed = False

    for node in _walk(body_node):
        t = node.type

        # type var = expr;
        if t == "init_declarator":
            decl = node.child_by_field_name("declarator")
            val = node.child_by_field_name("value")
            var = _first_identifier(decl)
            if var and val and _is_tainted(val, tainted, summaries):
                if var not in tainted:
                    tainted.add(var)
                    changed = True

        # var = expr;
        elif t == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs and lhs.type == "identifier" and rhs and _is_tainted(rhs, tainted, summaries):
                var = _txt(lhs)
                if var not in tainted:
                    tainted.add(var)
                    changed = True

        # call_expression — propagate buffer-copy sinks into destination
        elif t == "call_expression":
            fname = _call_fname(node)
            args = _call_args(node)

            # fgets(buf, n, fp) / gets(buf) / recv(s,buf,n,f) / read(fd,buf,n)
            if fname in _INPUT_BUF:
                buf_idx = _INPUT_BUF[fname]
                if buf_idx < len(args):
                    buf_name = (_txt(args[buf_idx])
                                if args[buf_idx].type == "identifier"
                                else _first_identifier(args[buf_idx]))
                    if buf_name and buf_name not in tainted:
                        tainted.add(buf_name)
                        changed = True

            # strcpy(dst, src) etc. → dst tainted if src tainted
            if fname in _PROP_DST_SRC:
                dst_idx, src_indices = _PROP_DST_SRC[fname]
                if dst_idx >= 0 and dst_idx < len(args):
                    if any(i < len(args) and _is_tainted(args[i], tainted, summaries)
                           for i in src_indices):
                        dst = (args[dst_idx].type == "identifier"
                               and _txt(args[dst_idx])
                               or _first_identifier(args[dst_idx]))
                        if dst and dst not in tainted:
                            tainted.add(dst)
                            changed = True

            # Interprocedural: record which param indices receive tainted args
            if call_sites is not None and summaries is not None and fname in summaries:
                for i, arg in enumerate(args):
                    if _is_tainted(arg, tainted, summaries):
                        call_sites[fname].add(i)

        # C++: cin >> var
        elif t == "binary_expression":
            op = node.child_by_field_name("operator")
            if op and _txt(op) == ">>":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and "cin" in _txt(left) and right and right.type == "identifier":
                    var = _txt(right)
                    if var not in tainted:
                        tainted.add(var)
                        changed = True

    return changed


def _detect_sinks(body_node, tainted: set[str], lines: list[str],
                  file_path: str, findings: list[Finding],
                  summaries: dict[str, _FuncSummary] | None = None) -> None:
    """Walk body and emit findings for tainted sinks and always-unsafe calls."""
    seen: set[tuple] = set()

    for node in _walk(body_node):
        if node.type != "call_expression":
            continue
        fname = _call_fname(node)
        if not fname:
            continue
        args = _call_args(node)
        line_no = node.start_point[0] + 1
        line_text = (lines[node.start_point[0]].strip()
                     if node.start_point[0] < len(lines) else "")

        # Always-unsafe functions (no taint check needed)
        if fname in _ALWAYS_UNSAFE:
            rule_id, sev, vtype, desc = _ALWAYS_UNSAFE[fname]
            key = (file_path, line_no, rule_id)
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    vuln_type=vtype,
                    severity=sev,
                    file_path=file_path,
                    line_number=line_no,
                    line_content=line_text,
                    description=desc,
                    rule_id=rule_id,
                ))

        # Taint-sensitive sinks
        if fname in _SINKS:
            arg_idx, rule_id, vtype, sev, desc = _SINKS[fname]
            if arg_idx < len(args) and _is_tainted(args[arg_idx], tainted, summaries):
                key = (file_path, line_no, rule_id)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        vuln_type=vtype,
                        severity=sev,
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line_text,
                        description=desc,
                        rule_id=rule_id,
                    ))


# ── Interprocedural helpers ───────────────────────────────────────────────────

def _collect_funcs(root_node) -> dict[str, object]:
    """Return {func_name: func_node} for all top-level function definitions."""
    funcs: dict[str, object] = {}
    for node in _walk(root_node):
        if node.type != "function_definition":
            continue
        decl = node.child_by_field_name("declarator")
        if decl is None:
            continue
        name = _first_identifier(decl)
        if name and name not in funcs:
            funcs[name] = node
    return funcs


def _get_param_names(func_node) -> list[str]:
    """Return parameter identifier names for a function definition."""
    decl = func_node.child_by_field_name("declarator")
    if decl is None:
        return []
    param_list = next((n for n in _walk(decl) if n.type == "parameter_list"), None)
    if param_list is None:
        return []
    names: list[str] = []
    for param in param_list.named_children:
        if param.type not in ("parameter_declaration", "variadic_parameter"):
            continue
        # Find the deepest identifier that's the variable name
        for n in _walk(param):
            if n.type == "identifier":
                names.append(_txt(n))
                break
    return names


def _check_returns_tainted(func_node, tainted: set[str],
                           summaries: dict[str, _FuncSummary] | None) -> bool:
    """Return True if any return statement carries a tainted expression."""
    body = func_node.child_by_field_name("body")
    if body is None:
        return False
    for node in _walk(body):
        if node.type == "return_statement":
            ret_val = next((c for c in node.named_children), None)
            if ret_val and _is_tainted(ret_val, tainted, summaries):
                return True
    return False


def _seed_with_summaries(func_node, summary: _FuncSummary | None) -> set[str]:
    """Seed initial taint set for a function, including interprocedural params."""
    tainted: set[str] = set()
    _seed_main_argv(func_node, tainted)
    if summary:
        param_names = _get_param_names(func_node)
        for idx in summary.param_tainted:
            if idx < len(param_names):
                tainted.add(param_names[idx])
    return tainted


def _analyze_func_with_summaries(
    func_node,
    summaries: dict[str, _FuncSummary],
    call_sites: dict[str, set[int]] | None,
) -> set[str]:
    """Propagate taint through one function using current summaries. Return final tainted set."""
    fname = _first_identifier(func_node.child_by_field_name("declarator") or func_node)
    tainted = _seed_with_summaries(func_node, summaries.get(fname))
    body = func_node.child_by_field_name("body")
    if body is None:
        return tainted
    for _ in range(10):
        if not _propagate(body, tainted, summaries, call_sites):
            break
    return tainted


def _analyze_with_parser(parser, content: str, file_path: str) -> list[Finding]:
    # Step 1: Preprocess (macro expansion / clang -E)
    lang = "c++" if any(file_path.endswith(e) for e in _CPP_EXTS) else "c"
    processed = _preprocess(content, lang)

    try:
        tree = parser.parse(processed.encode("utf-8", errors="replace"))
    except Exception:
        return []

    # Use original lines for accurate line-number reporting
    lines = content.splitlines()
    findings: list[Finding] = []

    # Step 2: Collect all function definitions
    funcs = _collect_funcs(tree.root_node)
    if not funcs:
        return []

    # Step 3: Interprocedural fixed-point analysis
    summaries: dict[str, _FuncSummary] = {name: _FuncSummary() for name in funcs}

    for _outer in range(5):
        changed = False
        call_sites: dict[str, set[int]] = {name: set() for name in funcs}

        for fname, func_node in funcs.items():
            tainted = _analyze_func_with_summaries(func_node, summaries, call_sites)

            # Update return-taint summary
            if not summaries[fname].returns_tainted:
                if _check_returns_tainted(func_node, tainted, summaries):
                    summaries[fname].returns_tainted = True
                    changed = True

        # Propagate call-site taint to callee param summaries
        for callee, tainted_indices in call_sites.items():
            new_indices = tainted_indices - summaries[callee].param_tainted
            if new_indices:
                summaries[callee].param_tainted |= new_indices
                changed = True

        if not changed:
            break

    # Step 4: Final pass — emit findings
    for func_node in funcs.values():
        tainted = _analyze_func_with_summaries(func_node, summaries, None)
        body = func_node.child_by_field_name("body")
        if body:
            _detect_sinks(body, tainted, lines, file_path, findings, summaries)

    return findings


# ── Analyzer classes ──────────────────────────────────────────────────────────

class CASTAnalyzer(BaseAnalyzer):
    """C AST taint analyzer (.c / .h)."""

    supported_extensions = _C_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_C_AVAILABLE:
            return []
        return _analyze_with_parser(_c_parser, content, file_path)


class CPPASTAnalyzer(BaseAnalyzer):
    """C++ AST taint analyzer (.cc / .cpp / .cxx / etc.)."""

    supported_extensions = _CPP_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_C_AVAILABLE:
            return []
        return _analyze_with_parser(_cpp_parser, content, file_path)
