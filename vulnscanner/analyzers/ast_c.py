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
    # Narrow string copy/append
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
    # Wide string copy/append (wchar_t)
    "wcscpy":   (0, [1]),
    "wcsncpy":  (0, [1]),
    "wcscat":   (0, [0, 1]),
    "wcsncat":  (0, [0, 1]),
    "wmemcpy":  (0, [1]),
    "wmemmove": (0, [1]),
    "wcsdup":   (-1, [0]),
    "swprintf": (0, list(range(2, 8))),
    "vswprintf":(0, [2, 3]),
}

# Input-reading functions that taint a buffer argument
# (buf_arg_index,)  — always taint regardless of other args
_INPUT_BUF: dict[str, int] = {
    "gets":      0,  # also CAST-MEM-001
    "fgets":     0,
    "fgetws":    0,  # wide-char fgets
    "fread":     0,  # fread(ptr, size, count, stream) → ptr tainted
    "pread":     1,  # pread(fd, buf, n, offset) → buf tainted
    "read":      1,
    "recv":      1,
    "recvfrom":  1,
    "recvmsg":   1,
    "getline":   0,  # POSIX getline(*lineptr, *n, fp) → lineptr tainted
    "__getline": 0,
}

# Functions whose return value is always tainted (env vars, credentials, etc.)
_INPUT_RET: frozenset[str] = frozenset({
    "getenv", "secure_getenv",
    "_wgetenv", "_tgetenv", "__wgetenv",  # Windows wide/TCHAR variants
    "getpass",   # password prompt
    "getlogin", "cuserid",  # login name
    "readline",  # GNU readline
})

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
    # Command (single-string sinks: any taint in arg N is sufficient)
    "system":        _cmd(0, "Command injection via system() with user-controlled string"),
    "popen":         _cmd(0, "Command injection via popen() with user-controlled string"),
    "wordexp":       _cmd(0, "Command injection via wordexp() shell word expansion"),
    "_wsystem":  _cmd(0, "Command injection via _wsystem() with user-controlled wide string"),
    "_wpopen":   _cmd(0, "Command injection via _wpopen() with user-controlled wide string"),
    "ShellExecute":  _cmd(2, "Command injection via Win32 ShellExecute()"),
    "ShellExecuteA": _cmd(2, "Command injection via Win32 ShellExecuteA()"),
    "ShellExecuteW": _cmd(2, "Command injection via Win32 ShellExecuteW()"),
    "CreateProcessA":_cmd(1, "Command injection via Win32 CreateProcessA()"),
    "CreateProcessW":_cmd(1, "Command injection via Win32 CreateProcessW()"),
    "WinExec":       _cmd(0, "Command injection via Win32 WinExec()"),
    # NOTE: exec*/wexec* moved to _EXEC_SINKS (any-arg check) — see below
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
    "vwprintf":  _fmt(0, "Format string: user-controlled format in vwprintf()"),
    "vfwprintf": _fmt(1, "Format string: user-controlled format in vfwprintf()"),
    "vswprintf": _fmt(2, "Format string: user-controlled format in vswprintf()"),
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
    "wcscpy":    _buf(1, "Buffer overflow: wcscpy() copies unbounded user-controlled wide src"),
    "wcscat":    _buf(1, "Buffer overflow: wcscat() appends unbounded user-controlled wide src"),
    "gets":      _buf(0, "Buffer overflow: gets() reads unbounded input (always unsafe)"),
    "scanf":     _buf(1, "Buffer overflow: scanf() with %s reads unbounded user input"),
    "sscanf":    _buf(2, "Buffer overflow: sscanf() with %s reads unbounded user input"),
    "fscanf":    _buf(1, "Buffer overflow: fscanf() with %s reads unbounded input"),
}

# exec* / _exec* / _wexec* family: path is arg 0, but tainted data may appear at any arg position.
# Juliet patterns: execl(fixed_path, fixed_path, "/c", data, NULL) — taint at arg 3.
# We check all args for taint (any tainted arg triggers CAST-CMD-001).
_EXEC_SINKS: frozenset[str] = frozenset({
    # POSIX exec variants
    "execl", "execle", "execlp",
    "execv", "execve", "execvp", "execvpe",
    # Windows _exec variants
    "_execl", "_execle", "_execlp", "_execlpe",
    "_execv", "_execve", "_execvp", "_execvpe",
    # Windows wide-char _wexec variants
    "_wexecl", "_wexecle", "_wexeclp", "_wexeclpe",
    "_wexecv", "_wexecve", "_wexecvp", "_wexecvpe",
})

# Windows _spawn* / _wspawn* functions: first arg is mode, rest may carry tainted data.
# We check args[1:] for taint (any tainted arg triggers CAST-CMD-001).
_SPAWN_SINKS: frozenset[str] = frozenset({
    "_spawnl",   "_spawnle",  "_spawnlp",  "_spawnlpe",
    "_spawnv",   "_spawnve",  "_spawnvp",  "_spawnvpe",
    "_wspawnl",  "_wspawnle", "_wspawnlp", "_wspawnlpe",
    "_wspawnv",  "_wspawnve", "_wspawnvp", "_wspawnvpe",
    "spawnl",    "spawnle",   "spawnlp",   "spawnlpe",
    "spawnv",    "spawnve",   "spawnvp",   "spawnvpe",
})

# ── Integer-overflow → allocation size (CWE-190 → CWE-787) ──────────────────
# These functions take a size/count argument derived from user-controlled data.
# When tainted integer arithmetic flows here, the allocation may be undersized.

# Allocation functions: argument positions that carry the byte-count.
#   key → (count_arg_idx, size_arg_idx or -1)
#   For calloc(count, size), count_arg_idx=0 is the user-multiplied dimension.
#   For malloc/realloc etc., count_arg_idx=0 is the direct byte count.
_ALLOC_SIZE_ARGS: dict[str, int] = {
    "malloc": 0, "alloca": 0, "_alloca": 0, "__builtin_alloca": 0,
    "realloc": 1, "reallocarray": 1,
    "HeapAlloc": 2, "LocalAlloc": 1, "GlobalAlloc": 1, "VirtualAlloc": 1,
    "VirtualAllocEx": 3,
    "operator new": 0,
}
_CALLOC_FUNCS: frozenset[str] = frozenset({"calloc"})

# Checked-math patterns that suppress CAST-INT-001 (recognise safe alternatives).
_CHECKED_MATH_FUNCS: frozenset[str] = frozenset({
    "CheckedNumeric", "base::CheckMul", "base::CheckAdd",
    "__builtin_mul_overflow", "__builtin_add_overflow", "__builtin_umul_overflow",
    "safe_add", "safe_mul", "SafeInt", "checked_add", "checked_mul",
    "overflow_safe_add", "overflow_safe_mul",
    "MulDiv",  # Windows MulDiv uses 64-bit arithmetic internally
})

# ── C++ container taint (CWE-787 via std::vector etc.) ───────────────────────
# When tainted data is pushed into a container, the container itself is tainted.
# Reads from it (vec[i], vec.front(), vec.back()) then propagate taint further.

_CONTAINER_MUTATORS: frozenset[str] = frozenset({
    "push_back", "push_front", "emplace_back", "emplace_front", "emplace",
    "insert", "assign", "append", "replace", "set",
    "add", "offer", "enqueue", "put",
})

# ── Functions that are always dangerous regardless of taint ───────────────────
# (rule_id, severity, vuln_type, description)
_ALWAYS_UNSAFE: dict[str, tuple] = {
    "gets":    ("CAST-MEM-001", Severity.CRITICAL, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Inherently unsafe: gets() has no bounds check — use fgets() instead"),
    "getwd":   ("CAST-MEM-001", Severity.MEDIUM, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Inherently unsafe: getwd() may overflow fixed-size buffer — use getcwd()"),
    "mktemp":  ("CAST-MEM-001", Severity.MEDIUM, VulnType.RACE_CONDITION,
                "Inherently unsafe: mktemp() has TOCTOU race condition — use mkstemp()"),
    "tmpnam":  ("CAST-MEM-001", Severity.MEDIUM, VulnType.RACE_CONDITION,
                "Inherently unsafe: tmpnam() has TOCTOU race condition — use mkstemp()"),
    # Unbounded copy/append — always require bounds-safe alternatives
    "strcpy":  ("CAST-BUF-001", Severity.HIGH, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Unsafe: strcpy() has no bounds check — use strncpy() or strlcpy()"),
    "strcat":  ("CAST-BUF-001", Severity.MEDIUM, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Unsafe: strcat() has no bounds check — use strncat() or strlcat()"),
    "wcscpy":  ("CAST-BUF-001", Severity.HIGH, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Unsafe: wcscpy() has no bounds check — use wcsncpy()"),
    "wcscat":  ("CAST-BUF-001", Severity.MEDIUM, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Unsafe: wcscat() has no bounds check — use wcsncat()"),
    "swprintf":("CAST-BUF-001", Severity.MEDIUM, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Unsafe: swprintf() may overflow fixed buffer — use snwprintf()"),
    "sprintf": ("CAST-BUF-001", Severity.MEDIUM, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Unsafe: sprintf() may overflow fixed buffer — use snprintf()"),
    "vsprintf":("CAST-BUF-001", Severity.MEDIUM, VulnType.TRUST_BOUNDARY_VIOLATION,
                "Unsafe: vsprintf() may overflow fixed buffer — use vsnprintf()"),
}


# ── Macro expansion / preprocessing ──────────────────────────────────────────

_CLANG_AVAIL: bool | None = None


def _expand_defines(content: str) -> str:
    """Expand simple #define UPPER lower portability aliases (no external deps).

    Handles patterns like:  #define SYSTEM system
    Does NOT handle function-like macros or multi-token replacements.
    """
    # Normalise CRLF so $ in MULTILINE anchors correctly on Windows files.
    normalised = content.replace('\r\n', '\n').replace('\r', '\n')
    defines: dict[str, str] = {}
    for m in re.finditer(
        r'^[ \t]*#[ \t]*define[ \t]+([A-Z_][A-Z0-9_]*)[ \t]+([a-z_][a-z0-9_]*)[ \t]*(?:#.*)?$',
        normalised, re.MULTILINE
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
    # Global/static variable names this function writes with tainted data
    global_writes: set[str] = field(default_factory=set)
    # Indices of parameters that this function writes with tainted data (output params).
    # Used for reference/pointer output params: after f(&x), x becomes tainted if
    # output_param_tainted contains the index for &x.
    output_param_tainted: set[int] = field(default_factory=set)


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

    if t == "initializer_list":
        # {a, b, c} array/struct literal — tainted if any element is tainted
        return any(_is_tainted(c, tainted, summaries) for c in node.named_children)

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
        # String-to-number converters: tainted string → tainted integer/float.
        # Enables integer-overflow-to-allocation detection (CWE-190).
        if fname in ("atoi", "atol", "atoll", "atof",
                     "strtol", "strtoul", "strtoll", "strtoull",
                     "strtof", "strtod", "strtold",
                     "wcstol", "wcstoul", "wcstoll", "wcstoull",
                     "_wtoi", "_wtol", "_wtoll", "_ttoi", "_ttol"):
            return bool(args) and _is_tainted(args[0], tainted, summaries)
        # Input calls always return tainted
        if fname in _INPUT_BUF:
            return True
        # Environment / credential sources always return tainted
        if fname in _INPUT_RET:
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


def _collect_funcptr_map(func_node) -> dict[str, str]:
    """Return {fp_var: actual_func_name} for simple function pointer assignments.

    Handles:
      void (*fp)(char*) = real_func;   // init_declarator
      fp = real_func;                  // assignment_expression
    """
    result: dict[str, str] = {}
    body = func_node.child_by_field_name("body")
    if body is None:
        return result
    for node in _walk(body):
        if node.type == "init_declarator":
            decl = node.child_by_field_name("declarator")
            val = node.child_by_field_name("value")
            if decl and val and val.type == "identifier":
                var = _first_identifier(decl)
                if var:
                    result[var] = _txt(val)
        elif node.type == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if (lhs and rhs
                    and lhs.type == "identifier"
                    and rhs.type == "identifier"):
                result[_txt(lhs)] = _txt(rhs)
    return result


def _propagate(body_node, tainted: set[str],
               summaries: dict[str, _FuncSummary] | None = None,
               call_sites: dict[str, set[int]] | None = None,
               local_vars: set[str] | None = None,
               global_writes: set[str] | None = None,
               funcptr_map: dict[str, str] | None = None) -> bool:
    """One propagation pass; returns True if tainted set grew.

    summaries: optional intra-file function taint summaries.
    call_sites: optional dict to accumulate which param indices of each
                callee receive tainted args (for interprocedural seeding).
    local_vars: set of locally declared variable names in the current function.
    global_writes: set to accumulate global variable names written with tainted data.
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

        # var = expr;  (also struct field and array element assignment)
        elif t == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs and rhs and _is_tainted(rhs, tainted, summaries):
                if lhs.type == "identifier":
                    var = _txt(lhs)
                    if var not in tainted:
                        tainted.add(var)
                        changed = True
                    # Track global writes: if var is not locally declared it's a global
                    if global_writes is not None and local_vars is not None:
                        if var not in local_vars:
                            global_writes.add(var)
                elif lhs.type == "field_expression":
                    # s.a = tainted → mark parent struct s as tainted (field-insensitive)
                    obj = lhs.child_by_field_name("argument")
                    if obj and obj.type == "identifier":
                        var = _txt(obj)
                        if var not in tainted:
                            tainted.add(var)
                            changed = True
                        if global_writes is not None and local_vars is not None:
                            if var not in local_vars:
                                global_writes.add(var)
                elif lhs.type == "subscript_expression":
                    # buf[i] = tainted → mark buf as tainted
                    base = next((c for c in lhs.named_children), None)
                    if base and base.type == "identifier":
                        var = _txt(base)
                        if var not in tainted:
                            tainted.add(var)
                            changed = True
                elif lhs.type == "pointer_expression":
                    # *ptr = tainted → mark ptr as tainted
                    inner = next((c for c in lhs.named_children), None)
                    if inner and inner.type == "identifier":
                        var = _txt(inner)
                        if var not in tainted:
                            tainted.add(var)
                            changed = True

        # call_expression — propagate buffer-copy sinks into destination
        elif t == "call_expression":
            fname = _call_fname(node)
            # Resolve function pointer: funcPtr(data) → resolve to actual function
            if funcptr_map and fname in funcptr_map:
                fname = funcptr_map[fname]
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

            # Interprocedural: record which param indices receive tainted args.
            # Also handle &data (address-of tainted var passed to pointer/ref param).
            if call_sites is not None and summaries is not None and fname in summaries:
                for i, arg in enumerate(args):
                    if _is_tainted(arg, tainted, summaries):
                        call_sites[fname].add(i)
                    elif (arg.type == "pointer_expression"
                          and arg.children and _txt(arg.children[0]) == "&"):
                        inner = next((c for c in arg.named_children), None)
                        if inner and _is_tainted(inner, tainted, summaries):
                            call_sites[fname].add(i)

            # C++ container mutation: v.push_back(tainted), v.insert(pos, tainted), etc.
            # When any argument to a mutator is tainted, the container itself is tainted.
            if fname in _CONTAINER_MUTATORS:
                receiver = _call_receiver(node)
                if receiver and any(_is_tainted(a, tainted, summaries) for a in args):
                    recv_var = (_txt(receiver) if receiver.type == "identifier"
                                else _first_identifier(receiver))
                    if recv_var and recv_var not in tainted:
                        tainted.add(recv_var)
                        changed = True

            # Output-param propagation: if the callee writes tainted data to a
            # reference/pointer param (e.g. badSource(char *&data)), the corresponding
            # caller variable becomes tainted after the call.
            if summaries is not None and fname in summaries:
                for i in summaries[fname].output_param_tainted:
                    if i < len(args):
                        arg_var = (_txt(args[i])
                                   if args[i].type == "identifier"
                                   else _first_identifier(args[i]))
                        if arg_var and arg_var not in tainted:
                            tainted.add(arg_var)
                            changed = True

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


def _is_struct_memcpy_overrun(args: list) -> bool:
    """Detect memcpy(var.field, src, sizeof(var)) — dst is a member but size is the parent.

    BAD:  memcpy(s.charBuf, src, sizeof(s))          ← copies sizeof(struct) into charBuf
    GOOD: memcpy(s.charBuf, src, sizeof(s.charBuf))  ← correct: sizeof member
    """
    if len(args) < 3:
        return False
    dst = args[0]
    size = args[2]
    if dst.type != "field_expression":
        return False
    parent = dst.child_by_field_name("argument")
    if parent is None:
        return False
    parent_name = _txt(parent)
    if size.type != "sizeof_expression":
        return False
    # Find what's inside sizeof() — may be wrapped in parenthesized_expression
    size_content = next((c for c in size.named_children
                         if c.type not in ("comment",)), None)
    if size_content is None:
        return False
    # Unwrap parenthesized_expression: sizeof(x) → x
    if size_content.type == "parenthesized_expression":
        size_content = next((c for c in size_content.named_children), None)
    if size_content is None:
        return False
    # BAD case: sizeof(var) → just an identifier matching parent
    if size_content.type == "identifier" and _txt(size_content) == parent_name:
        return True
    # BAD case: sizeof(*ptr) where ptr == parent_name
    if size_content.type == "pointer_expression":
        inner = next((c for c in size_content.named_children), None)
        if inner and inner.type == "identifier" and _txt(inner) == parent_name:
            return True
    return False


def _detect_sinks(body_node, tainted: set[str], lines: list[str],
                  file_path: str, findings: list[Finding],
                  summaries: dict[str, _FuncSummary] | None = None,
                  funcptr_map: dict[str, str] | None = None) -> None:
    """Walk body and emit findings for tainted sinks and always-unsafe calls."""
    seen: set[tuple] = set()

    for node in _walk(body_node):
        if node.type != "call_expression":
            continue
        fname = _call_fname(node)
        if not fname:
            continue
        if funcptr_map and fname in funcptr_map:
            fname = funcptr_map[fname]
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

        # Structural buffer overrun: memcpy/memmove(s.field, src, sizeof(s))
        if fname in ("memcpy", "memmove") and _is_struct_memcpy_overrun(args):
            key = (file_path, line_no, "CAST-BUF-002")
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_no,
                    line_content=line_text,
                    description=(
                        "Buffer overflow: memcpy/memmove uses sizeof(parent_struct) "
                        "instead of sizeof(member_field) — overwrites adjacent memory"
                    ),
                    rule_id="CAST-BUF-002",
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

        # exec* / _exec* / _wexec*: path at arg 0, but ANY arg may carry tainted data
        if fname in _EXEC_SINKS and args:
            if any(_is_tainted(a, tainted, summaries) for a in args):
                key = (file_path, line_no, "CAST-CMD-001")
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line_text,
                        description=f"Command injection via {fname}() with user-controlled argument",
                        rule_id="CAST-CMD-001",
                    ))

        # Windows _spawn* family: mode is arg 0, any subsequent tainted arg is dangerous
        if fname in _SPAWN_SINKS and len(args) > 1:
            if any(_is_tainted(a, tainted, summaries) for a in args[1:]):
                key = (file_path, line_no, "CAST-CMD-001")
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line_text,
                        description=f"Command injection via {fname}() with user-controlled argument",
                        rule_id="CAST-CMD-001",
                    ))

        # Integer overflow → allocation size (CWE-190 → CWE-787)
        # malloc/realloc/alloca with tainted size argument.
        if fname in _ALLOC_SIZE_ARGS:
            idx = _ALLOC_SIZE_ARGS[fname]
            if idx < len(args) and _is_tainted(args[idx], tainted, summaries):
                # Skip if the size expression uses a checked-math function
                size_text = args[idx].text.decode(errors="replace") if hasattr(args[idx], "text") else ""
                if not any(cm in size_text for cm in _CHECKED_MATH_FUNCS):
                    key = (file_path, line_no, "CAST-INT-001")
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_no,
                            line_content=line_text,
                            description=(
                                f"Integer overflow → allocation: {fname}() size argument "
                                "derived from user-controlled value — integer overflow may "
                                "produce undersized buffer (CWE-190/787); use checked arithmetic"
                            ),
                            rule_id="CAST-INT-001",
                        ))

        if fname in _CALLOC_FUNCS and len(args) >= 1:
            # calloc(count, size): tainted count → overflow when count*size wraps
            if _is_tainted(args[0], tainted, summaries):
                key = (file_path, line_no, "CAST-INT-001")
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line_text,
                        description=(
                            "Integer overflow → allocation: calloc() count argument "
                            "derived from user-controlled value — count*size overflow may "
                            "produce undersized buffer (CWE-190/787); use checked arithmetic"
                        ),
                        rule_id="CAST-INT-001",
                    ))

    # C++: new T[tainted_n] (new_expression) — allocation size from user data
    for node in _walk(body_node):
        if node.type != "new_expression":
            continue
        # Find array size: new T[expr] — tree-sitter puts it in the declarator field
        # or directly in the arguments
        size_node = None
        for child in node.named_children:
            if child.type == "argument_list":
                # new T(n) — not array allocation
                cargs = [c for c in child.named_children]
                if cargs and _is_tainted(cargs[0], tainted, summaries):
                    size_node = cargs[0]
                break
            if child.type in ("abstract_array_declarator", "array_declarator"):
                # new T[n]
                for sub in child.named_children:
                    if sub.type not in ("[", "]", "comment"):
                        size_node = sub
                        break
                break
        if size_node is None:
            continue
        if not _is_tainted(size_node, tainted, summaries):
            continue
        line_no = node.start_point[0] + 1
        line_text = lines[node.start_point[0]].strip() if node.start_point[0] < len(lines) else ""
        key = (file_path, line_no, "CAST-INT-001")
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_no,
                line_content=line_text,
                description=(
                    "Integer overflow → allocation: new[] size derived from user-controlled "
                    "value — integer overflow may produce undersized buffer (CWE-190/787)"
                ),
                rule_id="CAST-INT-001",
            ))


# ── Interprocedural helpers ───────────────────────────────────────────────────

def _collect_local_decls(func_node) -> set[str]:
    """Return set of all locally declared variable names in a function (incl. params)."""
    locals_: set[str] = set(_get_param_names(func_node))
    body = func_node.child_by_field_name("body")
    if body is None:
        return locals_
    for node in _walk(body):
        if node.type == "declaration":
            for n in _walk(node):
                if n.type == "init_declarator":
                    decl = n.child_by_field_name("declarator")
                    ident = _first_identifier(decl or n)
                    if ident:
                        locals_.add(ident)
                elif n.type in ("pointer_declarator", "array_declarator", "function_declarator"):
                    ident = _first_identifier(n)
                    if ident:
                        locals_.add(ident)
                elif n.type == "identifier" and n.parent and n.parent.type == "declaration":
                    locals_.add(_txt(n))
    return locals_


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
    global_tainted: set[str] | None = None,
) -> set[str]:
    """Propagate taint through one function using current summaries. Return final tainted set."""
    fname = _first_identifier(func_node.child_by_field_name("declarator") or func_node)
    tainted = _seed_with_summaries(func_node, summaries.get(fname))
    # Seed from globally tainted variables
    if global_tainted:
        tainted |= global_tainted
    body = func_node.child_by_field_name("body")
    if body is None:
        return tainted
    # Collect local declarations for global-write tracking
    local_vars = _collect_local_decls(func_node)
    summary = summaries.get(fname)
    global_writes = summary.global_writes if summary is not None else None
    funcptr_map = _collect_funcptr_map(func_node)
    for _ in range(10):
        if not _propagate(body, tainted, summaries, call_sites, local_vars, global_writes, funcptr_map):
            break
    return tainted


def _get_class_method_info(func_node) -> tuple[str, str] | None:
    """If func_node is a C++ qualified method (Class::method), return (class_name, method_name).

    Distinguishes constructor (name==class), destructor (name starts with ~), and
    regular methods — enabling cross-method taint propagation within a class.
    """
    decl = func_node.child_by_field_name("declarator")
    if decl is None:
        return None
    # Walk to find the innermost function_declarator
    func_decl = next((n for n in _walk(decl) if n.type == "function_declarator"), None)
    if func_decl is None:
        return None
    inner = func_decl.child_by_field_name("declarator")
    if inner is None or inner.type != "qualified_identifier":
        return None
    # qualified_identifier children: [scope, ::, name]
    scope = inner.child_by_field_name("scope")
    name = inner.child_by_field_name("name")
    if scope is None or name is None:
        children = [c for c in inner.named_children]
        if len(children) >= 2:
            scope, name = children[0], children[-1]
    if scope is None or name is None:
        return None
    class_name = _txt(scope)
    method_name = _txt(name)  # "ClassName", "~ClassName", or "methodName"
    return class_name, method_name


def _collect_class_methods(root_node) -> dict[str, list[tuple[str, object]]]:
    """Return {class_name: [(method_name, func_node), ...]} for C++ class methods."""
    result: dict[str, list] = {}
    for node in _walk(root_node):
        if node.type != "function_definition":
            continue
        cm = _get_class_method_info(node)
        if cm:
            cls, method = cm
            result.setdefault(cls, []).append((method, node))
    return result


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

    # Step 3: Interprocedural fixed-point analysis (with global variable taint)
    summaries: dict[str, _FuncSummary] = {name: _FuncSummary() for name in funcs}
    global_tainted: set[str] = set()  # file-scope variables written with tainted data

    for _outer in range(7):
        changed = False
        call_sites: dict[str, set[int]] = {name: set() for name in funcs}

        for fname, func_node in funcs.items():
            tainted = _analyze_func_with_summaries(
                func_node, summaries, call_sites, global_tainted
            )

            # Update return-taint summary
            if not summaries[fname].returns_tainted:
                if _check_returns_tainted(func_node, tainted, summaries):
                    summaries[fname].returns_tainted = True
                    changed = True

            # Update output-param summary: params tainted by the function body
            # (not from input param seeding) — e.g. badSource(char *&data) fills data
            param_names = _get_param_names(func_node)
            for i, pname in enumerate(param_names):
                if pname in tainted and i not in summaries[fname].param_tainted:
                    if i not in summaries[fname].output_param_tainted:
                        summaries[fname].output_param_tainted.add(i)
                        changed = True

        # Propagate call-site taint to callee param summaries
        for callee, tainted_indices in call_sites.items():
            new_indices = tainted_indices - summaries[callee].param_tainted
            if new_indices:
                summaries[callee].param_tainted |= new_indices
                changed = True

        # Accumulate globally tainted variables from all function summaries
        new_globals: set[str] = set()
        for s in summaries.values():
            new_globals |= s.global_writes
        if new_globals - global_tainted:
            global_tainted |= new_globals
            changed = True

        if not changed:
            break

    # Step 4: Final pass — emit findings
    for func_node in funcs.values():
        tainted = _analyze_func_with_summaries(func_node, summaries, None, global_tainted)
        body = func_node.child_by_field_name("body")
        if body:
            _detect_sinks(body, tainted, lines, file_path, findings, summaries,
                          _collect_funcptr_map(func_node))

    # Step 5: C++ class member cross-method taint (constructor→destructor, etc.)
    # For each class, collect "free variables" (tainted but not locally declared) from
    # every method, then re-analyze all methods with those member names seeded as tainted.
    class_methods = _collect_class_methods(tree.root_node)
    for cls_methods in class_methods.values():
        if len(cls_methods) < 2:
            continue  # need ≥ 2 methods for cross-method propagation

        # Pass A: accumulate member taint from every method
        member_tainted: set[str] = set()
        for _mname, func_node in cls_methods:
            local = _collect_local_decls(func_node)
            tainted = _analyze_func_with_summaries(
                func_node, summaries, None, global_tainted
            )
            member_tainted |= (tainted - local)

        if not member_tainted:
            continue

        # Pass B: re-analyze each method with member taint injected, emit findings.
        # Also scan helper functions called from class methods (e.g. badVaSink(data))
        # whose summaries were built before class member taint was known.
        for _mname, func_node in cls_methods:
            local = _collect_local_decls(func_node)
            extra = member_tainted - local  # don't shadow legitimate locals
            if not extra:
                continue
            new_call_sites: dict[str, set[int]] = {name: set() for name in funcs}
            tainted = _analyze_func_with_summaries(
                func_node, summaries, new_call_sites, global_tainted | extra
            )
            tainted |= extra
            fpm = _collect_funcptr_map(func_node)
            body = func_node.child_by_field_name("body")
            if body:
                _detect_sinks(body, tainted, lines, file_path, findings, summaries, fpm)
            # Also scan helpers that received newly-tainted args via the class member
            for callee, tainted_idxs in new_call_sites.items():
                if not tainted_idxs or callee not in funcs:
                    continue
                helper_node = funcs[callee]
                helper_param_names = _get_param_names(helper_node)
                helper_tainted: set[str] = set()
                for idx in tainted_idxs:
                    if idx < len(helper_param_names):
                        helper_tainted.add(helper_param_names[idx])
                if not helper_tainted:
                    continue
                helper_body = helper_node.child_by_field_name("body")
                if helper_body:
                    _detect_sinks(helper_body, helper_tainted, lines, file_path,
                                  findings, summaries, _collect_funcptr_map(helper_node))

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
