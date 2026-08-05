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
import threading
from dataclasses import dataclass, field

try:
    import tree_sitter_c as _tsc
    import tree_sitter_cpp as _tscpp
    from tree_sitter import Language, Parser as _TSParser
    _C_LANGUAGE = Language(_tsc.language())
    _CPP_LANGUAGE = Language(_tscpp.language())
    _TS_C_AVAILABLE = True
    _parser_local = threading.local()

    def _get_c_parser() -> _TSParser:
        p = getattr(_parser_local, "c", None)
        if p is None:
            p = _TSParser(_C_LANGUAGE)
            _parser_local.c = p
        return p

    def _get_cpp_parser() -> _TSParser:
        p = getattr(_parser_local, "cpp", None)
        if p is None:
            p = _TSParser(_CPP_LANGUAGE)
            _parser_local.cpp = p
        return p
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
    # scanf family: first output arg (after stream+format or just format)
    # The *first* non-literal arg carries user-supplied data.
    "scanf":     1,   # scanf(fmt, arg0, …)
    "wscanf":    1,   # wide-char scanf
    "fscanf":    2,   # fscanf(fp, fmt, arg0, …)
    "fwscanf":   2,
    "sscanf":    2,   # sscanf(str, fmt, arg0, …) – marks first output
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
    # Windows-specific format string variants
    "_printf":   _fmt(0, "Format string: user-controlled format in _printf()"),
    "_fprintf":  _fmt(1, "Format string: user-controlled format in _fprintf()"),
    "_sprintf":  _fmt(1, "Format string: user-controlled format in _sprintf()"),
    "_snprintf": _fmt(2, "Format string: user-controlled format in _snprintf()"),
    "_vsprintf": _fmt(1, "Format string: user-controlled format in _vsprintf()"),
    "_vsnprintf":_fmt(2, "Format string: user-controlled format in _vsnprintf()"),
    "_wprintf":  _fmt(0, "Format string: user-controlled format in _wprintf()"),
    "_fwprintf": _fmt(1, "Format string: user-controlled format in _fwprintf()"),
    "_swprintf": _fmt(1, "Format string: user-controlled format in _swprintf()"),
    "_snwprintf":_fmt(2, "Format string: user-controlled format in _snwprintf()"),
    "_vswprintf":_fmt(2, "Format string: user-controlled format in _vswprintf()"),
    "_vsnwprintf":_fmt(2, "Format string: user-controlled format in _vsnwprintf()"),
    "snwprintf": _fmt(2, "Format string: user-controlled format in snwprintf()"),
    "vsnwprintf":_fmt(2, "Format string: user-controlled format in vsnwprintf()"),
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
    # Minimum element count returned by this function (via `return var` where var has
    # a known allocation size). Used to propagate alloc_counts through call sites.
    returns_alloc_count: int | None = None
    # Minimum element count for each parameter index (for interprocedural size tracking).
    param_alloc_counts: dict[int, int] = field(default_factory=dict)
    # Minimum element count for parameters receiving pointer-to-buffer (&var where var has alloc).
    # Enables V63: &data passed where data is small → callee does *dataPtr[i] OOB.
    param_ptr_alloc_counts: dict[int, int] = field(default_factory=dict)
    # Parameter indices that receive underpointed pointers (= buf - N) at call sites.
    param_underpointed: set[int] = field(default_factory=set)
    # True if this function returns an underpointed pointer (return var where var = buf - N).
    returns_underpointed: bool = False
    # Parameter indices that receive untrusted integer values (from rand/atoi) at call sites.
    # Used to propagate CWE-129 detection interprocedurally (V41/V42 patterns).
    untrusted_int_params: set[int] = field(default_factory=set)
    # True if the function returns an untrusted integer (rand or atoi).
    # Enables V42 (rand-source): data = badSource() where badSource returns RAND32().
    returns_untrusted_int: bool = False
    # Parameter indices that receive pointers to untrusted integers (&var where var is untrusted_int).
    # Enables V63/V64/V65/V66/V67: data passed as pointer from one function to another.
    untrusted_int_ptr_params: set[int] = field(default_factory=set)


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

# B-3: Smart pointer accessor methods — propagate taint from the smart pointer
# wrapper to the raw pointer/reference it manages.
_SMART_PTR_ACCESSORS: frozenset[str] = frozenset({
    # unique_ptr / shared_ptr / weak_ptr
    "get", "release", "operator*", "operator->",
    # scoped_refptr<T> (Chromium), raw_ptr<T> (Chromium MiraclePtr)
    "get", "release", "lock",
    # absl::optional / std::optional
    "value", "operator*",
    # base::WeakPtr<T>
    "get",
    # span / base::span
    "data", "begin",
})

# B-4: Move/forward semantics — ownership transfer preserves taint
_MOVE_FUNCS: frozenset[str] = frozenset({
    "std::move", "move", "std::forward", "forward",
    "std::exchange", "exchange",
})

# B-3b: Smart pointer / wrapper constructor base names (strip template args + namespace).
# Constructing a smart pointer from a tainted raw pointer → the wrapper is also tainted.
_SMART_CTOR_BASES: frozenset[str] = frozenset({
    "shared_ptr", "unique_ptr", "weak_ptr", "scoped_ptr", "scoped_refptr",
    "raw_ptr", "intrusive_ptr", "RefPtr", "WeakPtr", "StrongPtr",
    "make_shared", "make_unique", "make_scoped_ptr", "make_intrusive",
    "optional", "variant", "expected",
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
        # B-3: Smart pointer accessor: ptr.get(), ptr.value(), ptr.release()
        if receiver and fname in _SMART_PTR_ACCESSORS and _is_tainted(receiver, tainted, summaries):
            return True
        # B-4: Move/forward: std::move(tainted) → tainted
        if fname in _MOVE_FUNCS:
            return bool(args) and _is_tainted(args[0], tainted, summaries)
        # B-3b: Smart pointer constructor: shared_ptr<T>(tainted) → tainted wrapper
        _fname_base = fname.split("<")[0].rsplit("::", 1)[-1]
        if _fname_base in _SMART_CTOR_BASES and any(
                _is_tainted(a, tainted, summaries) for a in args):
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
            # B-4: Reference alias: T& ref = obj  →  ref aliases obj → tainted if obj is
            # Reference declarator is wrapped in reference_declarator node inside decl
            if (decl and val and var
                    and any(n.type in ("reference_declarator", "rvalue_reference_declarator")
                            for n in _walk(decl))
                    and _is_tainted(val, tainted, summaries)):
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


_SIZEOF_APPROX: tuple[tuple[str, int], ...] = (
    # longest/most-specific patterns first to avoid substring false-matches
    ("long long", 8), ("long_long", 8), ("int64_t", 8), ("uint64_t", 8),
    ("int64", 8), ("uint64", 8), ("double", 8), ("intptr_t", 8),
    ("uintptr_t", 8), ("ptrdiff_t", 8), ("ssize_t", 8), ("size_t", 8),
    ("int32_t", 4), ("uint32_t", 4), ("int32", 4), ("uint32", 4),
    ("long", 4), ("float", 4), ("unsigned int", 4), ("unsigned", 4), ("int", 4),
    ("wchar_t", 2), ("char16_t", 2), ("char32_t", 4),
    ("int16_t", 2), ("uint16_t", 2), ("int16", 2), ("uint16", 2), ("short", 2),
    ("int8_t", 1), ("uint8_t", 1), ("int8", 1), ("uint8", 1),
    ("char", 1), ("byte", 1), ("bool", 1),
)


def _sizeof_type_text(type_text: str) -> int:
    """Approximate sizeof(T) in bytes for a type string."""
    t = type_text.strip().lower()
    for kw, sz in _SIZEOF_APPROX:
        if kw in t:
            return sz
    return 4


def _eval_const(node) -> int | None:
    """Evaluate a constant-foldable size expression to an integer byte count.

    Handles: number_literal, sizeof_expression, binary_expression (*,+,-),
    cast_expression, parenthesized_expression, subscript_expression (sizeof).
    Returns None when the expression is not statically evaluable.
    """
    if node is None:
        return None
    t = node.type
    if t == "number_literal":
        raw = _txt(node).rstrip("uUlL")
        try:
            return int(raw, 0)
        except ValueError:
            return None
    if t in ("cast_expression", "parenthesized_expression"):
        for c in node.named_children:
            if c.type not in ("type_descriptor", "comment"):
                v = _eval_const(c)
                if v is not None:
                    return v
        return None
    if t == "sizeof_expression":
        for c in node.named_children:
            if c.type not in ("comment",):
                inner = c
                if inner.type == "parenthesized_expression":
                    inner = next((x for x in inner.named_children), inner)
                return _sizeof_type_text(_txt(inner))
        return 1
    if t == "binary_expression":
        op_node = node.child_by_field_name("operator")
        op = _txt(op_node) if op_node else None
        lnode = node.child_by_field_name("left")
        rnode = node.child_by_field_name("right")
        if op and lnode and rnode:
            lv = _eval_const(lnode)
            rv = _eval_const(rnode)
            if lv is not None and rv is not None:
                if op == "*":
                    return lv * rv
                if op == "+":
                    return lv + rv
                if op == "-" and lv >= rv:
                    return lv - rv
    return None


def _decl_leaf_id(declarator_node) -> str | None:
    """Recursively extract the leaf identifier name from a complex declarator."""
    if declarator_node is None:
        return None
    if declarator_node.type == "identifier":
        return _txt(declarator_node)
    for child in declarator_node.named_children:
        result = _decl_leaf_id(child)
        if result:
            return result
    return None


def _extract_elem_count(size_node) -> int | None:
    """Extract element count N from malloc-size expressions like N*sizeof(T) or sizeof(T)*N."""
    if size_node is None:
        return None
    if size_node.type == "binary_expression":
        op_n = size_node.child_by_field_name("operator")
        if op_n and _txt(op_n) == "*":
            lv = size_node.child_by_field_name("left")
            rv = size_node.child_by_field_name("right")
            if lv and lv.type == "sizeof_expression":
                return _eval_const(rv)
            if rv and rv.type == "sizeof_expression":
                return _eval_const(lv)
    return None


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


def _compute_alloc_counts(body_node) -> dict[str, int]:
    """Return var → element_count from malloc/alloca/array declarations in body_node.

    Uses take-minimum semantics so if/else branches with different sizes resolve
    to the smallest allocation seen (worst-case for overflow detection).
    """
    alloc_counts: dict[str, int] = {}
    _ALLOC_FUNCS = frozenset({"malloc", "alloca", "ALLOCA", "_alloca",
                               "VirtualAlloc", "HeapAlloc", "LocalAlloc", "GlobalAlloc"})

    def _set(var: str, count: int) -> None:
        ex = alloc_counts.get(var)
        if ex is None or count < ex:
            alloc_counts[var] = count

    for sn in _walk(body_node):
        st = sn.type
        if st == "declaration":
            type_node = sn.child_by_field_name("type")
            if type_node is None:
                for tc in sn.named_children:
                    if tc.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                        type_node = tc
                        break
            elem_sz = _sizeof_type_text(_txt(type_node)) if type_node else 4
            for dc in sn.named_children:
                if dc.type == "array_declarator":
                    var = _decl_leaf_id(dc)
                    arr_n = None
                    for ac in dc.named_children:
                        if ac.type not in ("comment",) and ac != dc.named_children[0]:
                            arr_n = _eval_const(ac)
                            if arr_n is not None:
                                break
                    if var and arr_n:
                        _set(var, arr_n)
                elif dc.type == "init_declarator":
                    _decl_node2 = dc.child_by_field_name("declarator")
                    iv = _decl_leaf_id(_decl_node2)
                    val = dc.child_by_field_name("value")
                    if iv:
                        # int buf[10] = {0} → declarator is array_declarator; extract size
                        if _decl_node2 is not None and _decl_node2.type == "array_declarator":
                            _arr_n2 = None
                            for _ac2 in _decl_node2.named_children:
                                if (_ac2.type not in ("comment",)
                                        and _ac2 != _decl_node2.named_children[0]):
                                    _arr_n2 = _eval_const(_ac2)
                                    if _arr_n2 is not None:
                                        break
                            if _arr_n2:
                                _set(iv, _arr_n2)
                    if iv and val:
                        val_u = val
                        for _ in range(3):
                            if val_u.type in ("cast_expression", "parenthesized_expression"):
                                inner = next((c for c in val_u.named_children
                                              if c.type not in ("type_descriptor", "comment")), None)
                                if inner:
                                    val_u = inner
                                else:
                                    break
                            else:
                                break
                        if val_u.type == "call_expression":
                            fn2 = _call_fname(val_u); a2 = _call_args(val_u)
                            if fn2 in _ALLOC_FUNCS and a2:
                                cnt2 = _extract_elem_count(a2[0])
                                if cnt2:
                                    _set(iv, cnt2)
                            elif fn2 == "calloc" and len(a2) >= 2:
                                n2 = _eval_const(a2[0])
                                if n2:
                                    _set(iv, n2)
                        elif val_u.type == "identifier":
                            src = alloc_counts.get(_txt(val_u))
                            if src:
                                _set(iv, src)
                        elif val_u.type == "new_expression":
                            # new T[N] → element count N
                            _new_decl_c = next((c for c in val_u.named_children
                                                if c.type == "new_declarator"), None)
                            if _new_decl_c is not None:
                                _nd_child = next((c for c in _new_decl_c.named_children), None)
                                if _nd_child is not None:
                                    _cnt_ne = _eval_const(_nd_child)
                                    if _cnt_ne:
                                        _set(iv, _cnt_ne)
        elif st == "assignment_expression":
            lhs = sn.child_by_field_name("left"); rhs = sn.child_by_field_name("right")
            if lhs and rhs and lhs.type == "identifier":
                lvar = _txt(lhs)
                if rhs.type == "identifier":
                    src = alloc_counts.get(_txt(rhs))
                    if src:
                        _set(lvar, src)
                else:
                    rhs_u = rhs
                    for _ in range(3):
                        if rhs_u.type in ("cast_expression", "parenthesized_expression"):
                            inner = next((c for c in rhs_u.named_children
                                          if c.type not in ("type_descriptor", "comment")), None)
                            if inner:
                                rhs_u = inner
                            else:
                                break
                        else:
                            break
                    if rhs_u.type == "call_expression":
                        fn2 = _call_fname(rhs_u); a2 = _call_args(rhs_u)
                        if fn2 in _ALLOC_FUNCS and a2:
                            cnt2 = _extract_elem_count(a2[0])
                            if cnt2:
                                _set(lvar, cnt2)
                        elif fn2 == "calloc" and len(a2) >= 2:
                            n2 = _eval_const(a2[0])
                            if n2:
                                _set(lvar, n2)
                    elif rhs_u.type == "new_expression":
                        # new T[N] in assignment: data = new char[50]
                        _new_decl_a = next((c for c in rhs_u.named_children
                                            if c.type == "new_declarator"), None)
                        if _new_decl_a is not None:
                            _nd_child_a = next((c for c in _new_decl_a.named_children), None)
                            if _nd_child_a is not None:
                                _cnt_nea = _eval_const(_nd_child_a)
                                if _cnt_nea:
                                    _set(lvar, _cnt_nea)
            elif lhs and rhs and lhs.type == "field_expression":
                # struct.field = ptr_var → field-insensitive: mark struct with alloc_count
                _fe_base67 = lhs.child_by_field_name("argument")
                if _fe_base67 and _fe_base67.type == "identifier" and rhs.type == "identifier":
                    src67 = alloc_counts.get(_txt(rhs))
                    if src67:
                        _set(_txt(_fe_base67), src67)
    return alloc_counts


def _compute_underpointed(body_node) -> set[str]:
    """Return set of variables known to be underpointed (assigned buf - N) in body_node."""
    up: set[str] = set()

    def _check(lvar: str, rhs_expr) -> None:
        if rhs_expr is None:
            return
        node = rhs_expr
        for _ in range(3):
            if node.type in ("cast_expression", "parenthesized_expression"):
                nxt = next((c for c in node.named_children
                             if c.type not in ("type_descriptor", "comment")), None)
                if nxt:
                    node = nxt
                else:
                    break
            else:
                break
        if node.type != "binary_expression":
            return
        op_n = node.child_by_field_name("operator")
        if not op_n or _txt(op_n) != "-":
            return
        bl = node.child_by_field_name("left")
        br = node.child_by_field_name("right")
        if bl and br and bl.type == "identifier" and _eval_const(br) is not None:
            up.add(lvar)

    for sn in _walk(body_node):
        if sn.type == "assignment_expression":
            lhs = sn.child_by_field_name("left")
            rhs = sn.child_by_field_name("right")
            if lhs and lhs.type == "identifier":
                _check(_txt(lhs), rhs)
        elif sn.type == "init_declarator":
            iv = _decl_leaf_id(sn.child_by_field_name("declarator"))
            val = sn.child_by_field_name("value")
            if iv and val:
                _check(iv, val)
    return up


def _update_alloc_summaries(funcs: dict, summaries: dict[str, "_FuncSummary"]) -> None:
    """Propagate alloc_counts and underpointed info through function call sites.

    Two passes:
      Pass 1: Compute per-function alloc_counts + underpointed sets + returns_alloc_count.
      Pass 2: At each call site propagate alloc counts and underpointed info to callees.
    """
    # Pass 1: local alloc_counts + underpointed sets + return value alloc_count
    func_counts: dict[str, dict[str, int]] = {}
    func_underpointed: dict[str, set[str]] = {}
    for fname, func_node in funcs.items():
        body = func_node.child_by_field_name("body")
        if body is None:
            continue
        counts = _compute_alloc_counts(body)
        func_counts[fname] = counts
        func_underpointed[fname] = _compute_underpointed(body)
        # Infer returns_alloc_count: scan for `return var` where var has known count
        for ret_node in _walk(body):
            if ret_node.type != "return_statement":
                continue
            ret_val = next((c for c in ret_node.named_children
                            if c.type not in ("comment",)), None)
            if ret_val is None:
                continue
            rv = ret_val
            # Unwrap casts
            for _ in range(3):
                if rv.type in ("cast_expression", "parenthesized_expression"):
                    inner = next((c for c in rv.named_children
                                  if c.type not in ("type_descriptor", "comment")), None)
                    if inner:
                        rv = inner
                    else:
                        break
                else:
                    break
            cnt = None
            if rv.type == "identifier":
                cnt = counts.get(_txt(rv))
            elif rv.type == "call_expression":
                # return malloc(N*sizeof(T)) directly
                fn2 = _call_fname(rv); a2 = _call_args(rv)
                if fn2 in {"malloc", "alloca", "ALLOCA", "_alloca"} and a2:
                    cnt = _extract_elem_count(a2[0])
            if cnt is not None:
                existing = summaries[fname].returns_alloc_count
                if existing is None or cnt < existing:
                    summaries[fname].returns_alloc_count = cnt

        # Infer returns_underpointed: return var where var = buf - N
        _up_set = func_underpointed.get(fname, set())
        if _up_set and not summaries[fname].returns_underpointed:
            for _rn in _walk(body):
                if _rn.type != "return_statement":
                    continue
                _rv = next((c for c in _rn.named_children if c.type != "comment"), None)
                if _rv is None:
                    continue
                for _ in range(3):
                    if _rv.type in ("cast_expression", "parenthesized_expression"):
                        _inner = next((c for c in _rv.named_children
                                       if c.type not in ("type_descriptor", "comment")), None)
                        if _inner:
                            _rv = _inner
                        else:
                            break
                    else:
                        break
                if _rv.type == "identifier" and _txt(_rv) in _up_set:
                    summaries[fname].returns_underpointed = True
                    break

    # Pass 2: fixpoint propagation of alloc_counts/underpointed/ptr_alloc through call sites.
    # Iterates until stable so multi-level chains (V52/53/54: a→b→c) are handled correctly.
    _a2_changed = True
    while _a2_changed:
        _a2_changed = False
        for fname, func_node in funcs.items():
            body = func_node.child_by_field_name("body")
            if body is None:
                continue
            # Merge local alloc_counts with interprocedural param_alloc_counts.
            # This lets intermediate pass-through functions propagate counts they received
            # as parameters (V52: 52b receives data from 52a, passes to 52c).
            local_counts: dict[str, int] = dict(func_counts.get(fname, {}))
            _pnames = _get_param_names(func_node)
            for _pidx2, _pcnt2 in summaries[fname].param_alloc_counts.items():
                if _pidx2 < len(_pnames):
                    _pn2 = _pnames[_pidx2]
                    if _pn2 not in local_counts or local_counts[_pn2] > _pcnt2:
                        local_counts[_pn2] = _pcnt2
            # Also propagate pointer-to-buffer: deref from param_ptr_alloc_counts
            for _pidx2, _pcnt2 in summaries[fname].param_ptr_alloc_counts.items():
                if _pidx2 < len(_pnames):
                    _pn2 = _pnames[_pidx2]
                    # param is char** dataPtr; inside function: char* data = *dataPtr
                    # Track deref: if we see `id = *pname`, mark id with cnt
                    _fbody2 = func_node.child_by_field_name("body")
                    if _fbody2:
                        for _ps2 in _walk(_fbody2):
                            _lhs2 = None; _rhs2 = None
                            if _ps2.type == "declaration":
                                for _dc2 in _ps2.named_children:
                                    if _dc2.type == "init_declarator":
                                        _lhs2 = _decl_leaf_id(_dc2.child_by_field_name("declarator"))
                                        _rhs2 = _dc2.child_by_field_name("value")
                            elif _ps2.type == "assignment_expression":
                                _lhsn2 = _ps2.child_by_field_name("left")
                                if _lhsn2 and _lhsn2.type == "identifier":
                                    _lhs2 = _txt(_lhsn2)
                                _rhs2 = _ps2.child_by_field_name("right")
                            if _lhs2 and _rhs2:
                                _rhs2u = _rhs2
                                for _ in range(2):
                                    if _rhs2u.type in ("cast_expression", "parenthesized_expression"):
                                        _i2 = next((c for c in _rhs2u.named_children
                                                    if c.type not in ("type_descriptor", "comment")), None)
                                        if _i2: _rhs2u = _i2
                                        else: break
                                    else: break
                                if (_rhs2u.type == "pointer_expression"
                                        and _rhs2u.children
                                        and _txt(_rhs2u.children[0]) == "*"):
                                    _inner2 = next((c for c in _rhs2u.named_children), None)
                                    if (_inner2 and _inner2.type == "identifier"
                                            and _txt(_inner2) == _pn2):
                                        if _lhs2 not in local_counts or local_counts[_lhs2] > _pcnt2:
                                            local_counts[_lhs2] = _pcnt2
            local_up = func_underpointed.get(fname, set())
            # Fixpoint: also update returns_alloc_count from augmented local_counts
            body2 = func_node.child_by_field_name("body")
            if body2:
                for _ret2 in _walk(body2):
                    if _ret2.type != "return_statement":
                        continue
                    _rv2 = next((c for c in _ret2.named_children
                                 if c.type not in ("comment",)), None)
                    if _rv2 is None:
                        continue
                    for _ in range(3):
                        if _rv2.type in ("cast_expression", "parenthesized_expression"):
                            _i2 = next((c for c in _rv2.named_children
                                        if c.type not in ("type_descriptor", "comment")), None)
                            if _i2: _rv2 = _i2
                            else: break
                        else: break
                    if _rv2.type == "identifier":
                        _rcnt2 = local_counts.get(_txt(_rv2))
                        if _rcnt2 is not None:
                            ex2 = summaries[fname].returns_alloc_count
                            if ex2 is None or _rcnt2 < ex2:
                                summaries[fname].returns_alloc_count = _rcnt2
                                _a2_changed = True
            for call_node in _walk(body):
                if call_node.type != "call_expression":
                    continue
                callee = _call_fname(call_node)
                if not callee:
                    continue
                # Resolve function pointer (V65: funcPtr = badSink; funcPtr(data))
                if callee not in summaries:
                    _fpm65 = _collect_funcptr_map(func_node)
                    callee = _fpm65.get(callee, callee)
                if callee not in summaries:
                    continue
                args = _call_args(call_node)
                for idx, arg in enumerate(args):
                    if arg.type == "identifier":
                        aname = _txt(arg)
                        cnt = local_counts.get(aname)
                        if cnt is not None:
                            existing = summaries[callee].param_alloc_counts.get(idx)
                            if existing is None or cnt < existing:
                                summaries[callee].param_alloc_counts[idx] = cnt
                                _a2_changed = True
                        if aname in local_up:
                            if idx not in summaries[callee].param_underpointed:
                                summaries[callee].param_underpointed.add(idx)
                                _a2_changed = True
                    elif (arg.type == "pointer_expression"
                            and arg.children
                            and _txt(arg.children[0]) == "&"):
                        # &var → pointer-to-buffer: propagate param_ptr_alloc_counts (V63)
                        _pai = next((c for c in arg.named_children), None)
                        if _pai and _pai.type == "identifier":
                            _pac = local_counts.get(_txt(_pai))
                            if _pac is not None:
                                existing2 = summaries[callee].param_ptr_alloc_counts.get(idx)
                                if existing2 is None or _pac < existing2:
                                    summaries[callee].param_ptr_alloc_counts[idx] = _pac
                                    _a2_changed = True
                # Also propagate return value alloc_count: `var = callee()` → var gets alloc
                if summaries[callee].returns_alloc_count is not None:
                    _call_parent = call_node.parent
                    if _call_parent is not None:
                        _ret_var = None
                        if _call_parent.type == "assignment_expression":
                            _lhsn3 = _call_parent.child_by_field_name("left")
                            if _lhsn3 and _lhsn3.type == "identifier":
                                _ret_var = _txt(_lhsn3)
                        elif _call_parent.type == "init_declarator":
                            _ret_var = _decl_leaf_id(_call_parent.child_by_field_name("declarator"))
                        if _ret_var:
                            _rc2 = summaries[callee].returns_alloc_count
                            if _ret_var not in local_counts or local_counts[_ret_var] > _rc2:
                                local_counts[_ret_var] = _rc2
                                # also update func_counts so next iteration sees it
                                fc2 = func_counts.setdefault(fname, {})
                                if _ret_var not in fc2 or fc2[_ret_var] > _rc2:
                                    fc2[_ret_var] = _rc2
                                    _a2_changed = True


def _detect_sinks(body_node, tainted: set[str], lines: list[str],
                  file_path: str, findings: list[Finding],
                  summaries: dict[str, _FuncSummary] | None = None,
                  funcptr_map: dict[str, str] | None = None,
                  extra_alloc_counts: dict[str, int] | None = None,
                  extra_underpointed: set[str] | None = None,
                  global_untrusted_int: set[str] | None = None,
                  untrusted_int_ptr_names: set[str] | None = None,
                  extra_ptr_alloc_counts: dict[str, int] | None = None) -> None:
    """Walk body and emit findings for tainted sinks and always-unsafe calls."""
    seen: set[tuple] = set()

    # ── Pre-scan: build constant allocation-size map for CWE805 detection ───
    # Maps variable name → allocated byte count when statically determinable.
    _alloc_sizes: dict[str, int] = {}
    _alloc_counts: dict[str, int] = {}  # variable → element count (stack arrays only)
    _const_ints: dict[str, int] = {}   # variable → constant integer value (for OOB detection)
    _strlen_vars: dict[str, str] = {}  # variable → identifier whose strlen it stores

    # Seed from interprocedural parameter/return-value alloc counts
    if extra_alloc_counts:
        for _ev, _ec in extra_alloc_counts.items():
            _alloc_counts[_ev] = _ec
            # Also seed _alloc_sizes so identifier propagation fires for `x = seeded_var`.
            _alloc_sizes[_ev] = _ec

    # Seed pointer-to-buffer alloc counts: propagate deref `x = *ptr` where ptr is in extra_ptr_alloc.
    # Enables V63: char** dataPtr param where *dataPtr has alloc_count N → char* data = *dataPtr.
    if extra_ptr_alloc_counts:
        for _psn in _walk(body_node):
            _plhs: str | None = None; _prhs = None
            if _psn.type == "declaration":
                for _pdc in _psn.named_children:
                    if _pdc.type == "init_declarator":
                        _plhs = _decl_leaf_id(_pdc.child_by_field_name("declarator"))
                        _prhs = _pdc.child_by_field_name("value")
            elif _psn.type == "assignment_expression":
                _plhsn = _psn.child_by_field_name("left")
                if _plhsn and _plhsn.type == "identifier":
                    _plhs = _txt(_plhsn)
                _prhs = _psn.child_by_field_name("right")
            if _plhs and _prhs:
                _prhs_u = _prhs
                for _ in range(2):
                    if _prhs_u.type in ("cast_expression", "parenthesized_expression"):
                        _pi = next((c for c in _prhs_u.named_children
                                    if c.type not in ("type_descriptor", "comment")), None)
                        if _pi: _prhs_u = _pi
                        else: break
                    else: break
                if (_prhs_u.type == "pointer_expression"
                        and _prhs_u.children
                        and _txt(_prhs_u.children[0]) == "*"):
                    _pinner = next((c for c in _prhs_u.named_children), None)
                    if (_pinner and _pinner.type == "identifier"):
                        _pcnt = extra_ptr_alloc_counts.get(_txt(_pinner))
                        if _pcnt is not None and (_plhs not in _alloc_counts
                                                   or _alloc_counts[_plhs] > _pcnt):
                            _alloc_counts[_plhs] = _pcnt

    def _set_alloc(var: str, bytes_: int, count: int | None = None) -> None:
        """Update alloc maps taking minimum seen — handles if/else with different sizes."""
        ex_b = _alloc_sizes.get(var)
        if ex_b is None or bytes_ < ex_b:
            _alloc_sizes[var] = bytes_
        # Fall back to bytes_ as element count when no sizeof info available.
        # Enables CWE-129 detection for malloc(N) (e.g. malloc(10)) in addition
        # to malloc(N*sizeof(T)).
        eff_count = count if count is not None else bytes_
        ex_c = _alloc_counts.get(var)
        if ex_c is None or eff_count < ex_c:
            _alloc_counts[var] = eff_count

    _ALLOC_FUNCS_SZ = frozenset({"malloc", "alloca", "ALLOCA", "_alloca",
                                  "VirtualAlloc", "HeapAlloc", "LocalAlloc",
                                  "GlobalAlloc"})
    for _sn in _walk(body_node):
        _st = _sn.type
        if _st == "declaration":
            # Derive element size from type specifier
            _type_node = _sn.child_by_field_name("type")
            if _type_node is None:
                for _tc in _sn.named_children:
                    if _tc.type in ("primitive_type", "type_identifier",
                                    "sized_type_specifier"):
                        _type_node = _tc
                        break
            _elem_sz = _sizeof_type_text(_txt(_type_node)) if _type_node else 4
            for _dc in _sn.named_children:
                if _dc.type == "array_declarator":
                    # int buf[50] → 50 * sizeof(int)
                    _var = _decl_leaf_id(_dc)
                    _arr_n = None
                    for _ac in _dc.named_children:
                        if _ac.type not in ("comment",) and _ac != _dc.named_children[0]:
                            _arr_n = _eval_const(_ac)
                            if _arr_n is not None:
                                break
                    if _var and _arr_n:
                        _set_alloc(_var, _arr_n * _elem_sz, _arr_n)
                elif _dc.type == "init_declarator":
                    # char *p = malloc(N) / (type*)ALLOCA(N) / calloc(N, M)
                    _dc_decl = _dc.child_by_field_name("declarator")
                    _iv = _decl_leaf_id(_dc_decl)
                    _val = _dc.child_by_field_name("value")
                    # int buf[10] = {0} → declarator is array_declarator; extract size
                    if _iv and _dc_decl is not None and _dc_decl.type == "array_declarator":
                        _arr_n_id = None
                        for _ac_id in _dc_decl.named_children:
                            if (_ac_id.type not in ("comment",)
                                    and _ac_id != _dc_decl.named_children[0]):
                                _arr_n_id = _eval_const(_ac_id)
                                if _arr_n_id is not None:
                                    break
                        if _arr_n_id:
                            _set_alloc(_iv, _arr_n_id * _elem_sz, _arr_n_id)
                    if _iv and _val:
                        # Track constant integer declarations: int data = 10
                        _ci_v2 = _eval_const(_val)
                        if _ci_v2 is not None:
                            _const_ints[_iv] = _ci_v2
                        # Unwrap cast layers: (wchar_t *)ALLOCA(...) → ALLOCA(...)
                        _val_u = _val
                        for _ in range(3):
                            if _val_u.type in ("cast_expression",
                                               "parenthesized_expression"):
                                _inner = next(
                                    (c for c in _val_u.named_children
                                     if c.type not in ("type_descriptor",
                                                       "comment")), None)
                                if _inner:
                                    _val_u = _inner
                                else:
                                    break
                            else:
                                break
                        if _val_u.type == "call_expression":
                            _fn2 = _call_fname(_val_u)
                            _a2 = _call_args(_val_u)
                            if _fn2 in _ALLOC_FUNCS_SZ and _a2:
                                _sz2 = _eval_const(_a2[0])
                                _cnt2 = _extract_elem_count(_a2[0])
                                if _sz2:
                                    _set_alloc(_iv, _sz2, _cnt2)
                            elif _fn2 == "calloc" and len(_a2) >= 2:
                                _n2 = _eval_const(_a2[0])
                                _s2 = _eval_const(_a2[1])
                                if _n2 and _s2:
                                    _set_alloc(_iv, _n2 * _s2, _n2)
                            elif _fn2 in {"strlen", "wcslen", "_tcslen", "_mbslen"} and _a2 and _a2[0].type == "identifier":
                                _strlen_vars[_iv] = _txt(_a2[0])
                        elif _val_u.type == "identifier":
                            # char *p = existingBuffer → inherit size and count
                            _src_sz = _alloc_sizes.get(_txt(_val_u))
                            _src_cnt = _alloc_counts.get(_txt(_val_u))
                            if _src_sz:
                                _set_alloc(_iv, _src_sz, _src_cnt)
                        elif _val_u.type == "field_expression":
                            # char *data = myStruct.field → field-insensitive: inherit struct alloc
                            _fe_base_r = _val_u.child_by_field_name("argument")
                            if _fe_base_r and _fe_base_r.type == "identifier":
                                _src_sz = _alloc_sizes.get(_txt(_fe_base_r))
                                _src_cnt = _alloc_counts.get(_txt(_fe_base_r))
                                if _src_sz:
                                    _set_alloc(_iv, _src_sz, _src_cnt)
                        elif _val_u.type == "new_expression":
                            # new T[N] in init_declarator: char *data = new char[50]
                            _new_t = next((c for c in _val_u.named_children
                                           if c.type in ("primitive_type", "type_identifier",
                                                         "qualified_identifier")), None)
                            _new_d = next((c for c in _val_u.named_children
                                           if c.type == "new_declarator"), None)
                            if _new_d is not None:
                                _nd_c = next((c for c in _new_d.named_children), None)
                                if _nd_c is not None:
                                    _cnt_ne2 = _eval_const(_nd_c)
                                    if _cnt_ne2:
                                        _esz = _sizeof_type_text(_txt(_new_t)) if _new_t else 1
                                        _set_alloc(_iv, _cnt_ne2 * _esz, _cnt_ne2)
        elif _st == "assignment_expression":
            _lhs = _sn.child_by_field_name("left")
            _rhs = _sn.child_by_field_name("right")
            if _lhs and _rhs and _lhs.type == "identifier":
                _lvar = _txt(_lhs)
                # Constant integer tracking (CWE-129/large: data=10; buffer[data]=1)
                _ci_v = _eval_const(_rhs)
                if _ci_v is not None:
                    _const_ints[_lvar] = _ci_v
                else:
                    _const_ints.pop(_lvar, None)
                if _rhs.type == "identifier":
                    # data = dataBadBuffer → propagate known allocation size and count
                    _src_sz = _alloc_sizes.get(_txt(_rhs))
                    _src_cnt = _alloc_counts.get(_txt(_rhs))
                    if _src_sz:
                        _set_alloc(_lvar, _src_sz, _src_cnt)
                elif _rhs.type == "field_expression":
                    # data = myStruct.field → field-insensitive: inherit struct alloc
                    _fe_base_ar = _rhs.child_by_field_name("argument")
                    if _fe_base_ar and _fe_base_ar.type == "identifier":
                        _src_sz = _alloc_sizes.get(_txt(_fe_base_ar))
                        _src_cnt = _alloc_counts.get(_txt(_fe_base_ar))
                        if _src_sz:
                            _set_alloc(_lvar, _src_sz, _src_cnt)
                else:
                    # data = (type*)malloc(N) — unwrap cast layers first
                    _rhs_u = _rhs
                    for _ in range(3):
                        if _rhs_u.type in ("cast_expression",
                                           "parenthesized_expression"):
                            _inner = next(
                                (c for c in _rhs_u.named_children
                                 if c.type not in ("type_descriptor", "comment")),
                                None)
                            if _inner:
                                _rhs_u = _inner
                            else:
                                break
                        else:
                            break
                    if _rhs_u.type == "call_expression":
                        _fn2 = _call_fname(_rhs_u)
                        _a2 = _call_args(_rhs_u)
                        if _fn2 in _ALLOC_FUNCS_SZ and _a2:
                            _sz2 = _eval_const(_a2[0])
                            _cnt2 = _extract_elem_count(_a2[0])
                            if _sz2:
                                _set_alloc(_lvar, _sz2, _cnt2)
                        elif _fn2 == "calloc" and len(_a2) >= 2:
                            _n2 = _eval_const(_a2[0])
                            _s2 = _eval_const(_a2[1])
                            if _n2 and _s2:
                                _set_alloc(_lvar, _n2 * _s2, _n2)
                        elif summaries and _fn2 in summaries:
                            # data = badSource(data) where badSource returns alloc'd ptr
                            _ret_cnt = summaries[_fn2].returns_alloc_count
                            if _ret_cnt is not None:
                                # Use _set_alloc so both _alloc_sizes AND _alloc_counts are set
                                _set_alloc(_lvar, _ret_cnt, _ret_cnt)
                        elif _fn2 in {"strlen", "wcslen", "_tcslen", "_mbslen"} and _a2 and _a2[0].type == "identifier":
                            _strlen_vars[_lvar] = _txt(_a2[0])
                    elif _rhs_u.type == "new_expression":
                        # data = new T[N] — C++ heap allocation
                        _new_t2 = next((c for c in _rhs_u.named_children
                                        if c.type in ("primitive_type", "type_identifier",
                                                      "qualified_identifier")), None)
                        _new_d2 = next((c for c in _rhs_u.named_children
                                        if c.type == "new_declarator"), None)
                        if _new_d2 is not None:
                            _nd_c2 = next((c for c in _new_d2.named_children), None)
                            if _nd_c2 is not None:
                                _cnt_ne3 = _eval_const(_nd_c2)
                                if _cnt_ne3:
                                    _esz2 = _sizeof_type_text(_txt(_new_t2)) if _new_t2 else 1
                                    _set_alloc(_lvar, _cnt_ne3 * _esz2, _cnt_ne3)
            elif _lhs and _rhs and _lhs.type == "field_expression":
                # myStruct.field = ptr_var → field-insensitive: mark struct with alloc
                _fe_base_w = _lhs.child_by_field_name("argument")
                if _fe_base_w and _fe_base_w.type == "identifier" and _rhs.type == "identifier":
                    _src_sz = _alloc_sizes.get(_txt(_rhs))
                    _src_cnt = _alloc_counts.get(_txt(_rhs))
                    if _src_sz:
                        _set_alloc(_txt(_fe_base_w), _src_sz, _src_cnt)

    # Pointer underwrite tracking: data = buffer - N → "underpointed"
    # Any write/read through such a pointer accesses memory before the allocation.
    _underpointed: set[str] = set(extra_underpointed) if extra_underpointed else set()

    def _check_underpointed(lvar: str, rhs_expr) -> None:
        """Check if rhs_expr is 'identifier - constant' and mark lvar underpointed."""
        if rhs_expr is None:
            return
        # Unwrap casts/parens
        node = rhs_expr
        for _ in range(3):
            if node.type in ("cast_expression", "parenthesized_expression"):
                nxt = next(
                    (c for c in node.named_children
                     if c.type not in ("type_descriptor", "comment")), None)
                if nxt:
                    node = nxt
                else:
                    break
            else:
                break
        if node.type != "binary_expression":
            return
        _op_n = node.child_by_field_name("operator")
        if not _op_n or _txt(_op_n) != "-":
            return
        _bl = node.child_by_field_name("left")
        _br = node.child_by_field_name("right")
        if _bl and _br and _bl.type == "identifier" and _eval_const(_br) is not None:
            _underpointed.add(lvar)

    for _sn in _walk(body_node):
        if _sn.type == "assignment_expression":
            _lhs = _sn.child_by_field_name("left")
            _rhs = _sn.child_by_field_name("right")
            if _lhs and _lhs.type == "identifier":
                _check_underpointed(_txt(_lhs), _rhs)
                # Propagate returns_underpointed: data = badSource(data)
                if _rhs and summaries:
                    _rhs_uu = _rhs
                    for _ in range(3):
                        if _rhs_uu.type in ("cast_expression", "parenthesized_expression"):
                            _uu_inner = next((c for c in _rhs_uu.named_children
                                              if c.type not in ("type_descriptor", "comment")), None)
                            if _uu_inner:
                                _rhs_uu = _uu_inner
                            else:
                                break
                        else:
                            break
                    if _rhs_uu.type == "call_expression":
                        _fn_uu = _call_fname(_rhs_uu)
                        if _fn_uu and _fn_uu in summaries and summaries[_fn_uu].returns_underpointed:
                            _underpointed.add(_txt(_lhs))
        elif _sn.type == "init_declarator":
            _iv = _decl_leaf_id(_sn.child_by_field_name("declarator"))
            _val = _sn.child_by_field_name("value")
            if _iv and _val:
                _check_underpointed(_iv, _val)
                # Propagate returns_underpointed: char *data = badSource(data)
                if summaries:
                    _val_uu = _val
                    for _ in range(3):
                        if _val_uu.type in ("cast_expression", "parenthesized_expression"):
                            _uu_inner2 = next((c for c in _val_uu.named_children
                                               if c.type not in ("type_descriptor", "comment")), None)
                            if _uu_inner2:
                                _val_uu = _uu_inner2
                            else:
                                break
                        else:
                            break
                    if _val_uu.type == "call_expression":
                        _fn_uu2 = _call_fname(_val_uu)
                        if _fn_uu2 and _fn_uu2 in summaries and summaries[_fn_uu2].returns_underpointed:
                            _underpointed.add(_iv)

    # CWE-129: untrusted integer index tracking
    # Tracks integers derived from rand() / RAND32() / atoi(tainted) etc.
    _INT_TAINT_FUNCS: frozenset[str] = frozenset({
        "rand", "RAND32", "rand_r", "random", "lrand48", "mrand48",
    })
    _INT_CONV_FUNCS: frozenset[str] = frozenset({
        "atoi", "atol", "atoll", "atof",
        "strtol", "strtoll", "strtoul", "strtoull",
        "wcstol", "wcstoll", "_wtoi", "_wtol",
    })
    _untrusted_int: set[str] = set(global_untrusted_int) if global_untrusted_int else set()
    # Pointer params that point to untrusted_int values (V63/V64/V65 pattern)
    _untrusted_int_ptrs: set[str] = set(untrusted_int_ptr_names) if untrusted_int_ptr_names else set()

    def _check_untrusted_int(lvar: str, rhs_expr) -> None:
        """Mark lvar as untrusted_int if rhs comes from rand/conversion of tainted."""
        if rhs_expr is None:
            return
        node = rhs_expr
        for _ in range(3):
            if node.type in ("cast_expression", "parenthesized_expression"):
                nxt = next((c for c in node.named_children
                             if c.type not in ("type_descriptor", "comment")), None)
                if nxt:
                    node = nxt
                else:
                    break
            else:
                break
        if node.type == "identifier":
            # Propagation: var = another_untrusted_int (global or local)
            src = _txt(node)
            if (src in _untrusted_int
                    or (global_untrusted_int and src in global_untrusted_int)):
                _untrusted_int.add(lvar)
            elif src in _untrusted_int_ptrs:
                # Pointer alias propagation: int *p2 = p1 where p1 is ptr-to-untrusted_int
                # (V64: int *dataPtr = (int *)dataVoidPtr after cast is unwrapped)
                _untrusted_int_ptrs.add(lvar)
            return
        if node.type == "field_expression":
            # V67: data = myStruct.structFirst where myStruct is untrusted_int
            _fe_obj = node.child_by_field_name("argument")
            if _fe_obj and _fe_obj.type == "identifier" and _txt(_fe_obj) in _untrusted_int:
                _untrusted_int.add(lvar)
            return
        if node.type == "pointer_expression":
            # *ptr where ptr points to an untrusted_int (V63/V64 pattern: int data = *dataPtr)
            _ptr_op = node.children[0] if node.children else None
            if _ptr_op and _txt(_ptr_op) == "*":
                _ptr_inner = next((c for c in node.named_children), None)
                if (_ptr_inner and _ptr_inner.type == "identifier"
                        and _txt(_ptr_inner) in _untrusted_int_ptrs):
                    _untrusted_int.add(lvar)
            return
        if node.type != "call_expression":
            return
        fn3 = _call_fname(node)
        if not fn3:
            return
        if fn3 in _INT_TAINT_FUNCS:
            _untrusted_int.add(lvar)
        elif fn3 in _INT_CONV_FUNCS:
            a3 = _call_args(node)
            if a3 and a3[0].type == "identifier" and _txt(a3[0]) in tainted:
                _untrusted_int.add(lvar)
        elif summaries and fn3 in summaries and (
                summaries[fn3].returns_tainted or summaries[fn3].returns_untrusted_int):
            # User-defined function returning tainted/untrusted int (V42 pattern)
            _untrusted_int.add(lvar)

    for _sn in _walk(body_node):
        if _sn.type == "assignment_expression":
            _lhs3 = _sn.child_by_field_name("left")
            _rhs3 = _sn.child_by_field_name("right")
            if _lhs3 and _lhs3.type == "identifier":
                _check_untrusted_int(_txt(_lhs3), _rhs3)
        elif _sn.type == "init_declarator":
            _iv3 = _decl_leaf_id(_sn.child_by_field_name("declarator"))
            _val3 = _sn.child_by_field_name("value")
            if _iv3 and _val3:
                _check_untrusted_int(_iv3, _val3)
        # V67: struct.field = untrusted_int_var → mark struct as untrusted_int
        # This propagates the taint to the whole struct (field-insensitive).
        if (_sn.type == "assignment_expression"):
            _lhs3f = _sn.child_by_field_name("left")
            _rhs3f = _sn.child_by_field_name("right")
            if (_lhs3f and _lhs3f.type == "field_expression"
                    and _rhs3f and _rhs3f.type == "identifier"
                    and _txt(_rhs3f) in _untrusted_int):
                _base3f = _lhs3f.child_by_field_name("argument")
                if _base3f and _base3f.type == "identifier":
                    _untrusted_int.add(_txt(_base3f))

    # scanf/fscanf family: &var args receive user-controlled integers
    _SCANF_UNTRUSTED: dict[str, int] = {
        "scanf": 1, "wscanf": 1, "fscanf": 2, "fwscanf": 2, "sscanf": 2,
    }
    for _sn in _walk(body_node):
        if _sn.type == "call_expression":
            _fn_sc = _call_fname(_sn)
            if _fn_sc in _SCANF_UNTRUSTED:
                _base_sc = _SCANF_UNTRUSTED[_fn_sc]
                _args_sc = _call_args(_sn)
                for _arg_sc in _args_sc[_base_sc:]:
                    # &var → var receives integer from user
                    if (_arg_sc.type == "pointer_expression"
                            and _arg_sc.children
                            and _txt(_arg_sc.children[0]) == "&"):
                        _inner_sc = next((c for c in _arg_sc.named_children), None)
                        if _inner_sc and _inner_sc.type == "identifier":
                            _untrusted_int.add(_txt(_inner_sc))

    # (size_arg_index, bytes_per_element)
    # Element size is 1 for byte-based functions, 2 for wchar_t-based functions.
    # For snprintf/sprintf_s family: size is args[1] (destination byte count).
    _BOUNDED_COPY_SINKS: dict[str, tuple[int, int]] = {
        "memcpy":    (2, 1), "memmove":   (2, 1),
        "wmemcpy":   (2, 2), "wmemmove":  (2, 2),
        "memset":    (2, 1), "wmemset":   (2, 2),
        "strncpy":   (2, 1), "wcsncpy":   (2, 2),
        "strncat":   (2, 1), "wcsncat":   (2, 2),
        "memcpy_s":  (1, 1),
        # snprintf-family: dst at 0, dstSize at 1 (in chars, byte-sized)
        "snprintf":   (1, 1), "_snprintf":  (1, 1),
        "vsnprintf":  (1, 1), "_vsnprintf": (1, 1),
        # wchar_t snprintf variants: dstSize is in wchar_t elements (×2 bytes)
        "swprintf":   (1, 2), "_swprintf":  (1, 2),
        "vswprintf":  (1, 2), "_vswprintf": (1, 2),
        "_snwprintf": (1, 2), "_vsnwprintf": (1, 2),
    }

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

        # Constant-size buffer overflow: copy size > known destination allocation
        if fname in _BOUNDED_COPY_SINKS and len(args) >= 3:
            _csi, _bpe = _BOUNDED_COPY_SINKS[fname]
            _copy_n = _eval_const(args[_csi]) if _csi < len(args) else None
            # CWE-806: strncat/snprintf(dst, strlen(src), ...) — estimate strlen from alloc_size
            if _copy_n is None and _csi < len(args):
                _cnt_arg = args[_csi]
                if _cnt_arg.type == "call_expression":
                    _cnt_fn = _call_fname(_cnt_arg)
                    _cnt_a = _call_args(_cnt_arg)
                    if (_cnt_fn in {"strlen", "wcslen", "_tcslen", "_mbslen"}
                            and _cnt_a and _cnt_a[0].type == "identifier"):
                        _src_sz = _alloc_sizes.get(_txt(_cnt_a[0]))
                        if _src_sz is not None:
                            _copy_n = _src_sz - 1  # strlen(buf) ≈ alloc_size - 1
            _copy_sz = _copy_n * _bpe if _copy_n is not None else None
            _dst_arg = args[0]
            _dst_var = (_txt(_dst_arg) if _dst_arg.type == "identifier"
                        else _first_identifier(_dst_arg))
            _dst_alloc = _alloc_sizes.get(_dst_var) if _dst_var else None
            if _copy_sz and _dst_alloc and _copy_sz > _dst_alloc:
                _key = (file_path, line_no, "CAST-BUF-001")
                if _key not in seen:
                    seen.add(_key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line_text,
                        description=(
                            f"Buffer overflow: {fname}() copies {_copy_sz} bytes "
                            f"into '{_dst_var}' ({_dst_alloc}-byte buffer) — CWE-805"
                        ),
                        rule_id="CAST-BUF-001",
                    ))
            # Pointer underwrite (CWE-124): dst was derived from buffer - N
            if _dst_var and _dst_var in _underpointed:
                _key = (file_path, line_no, "CAST-BUF-001")
                if _key not in seen:
                    seen.add(_key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_no,
                        line_content=line_text,
                        description=(
                            f"Buffer underwrite: '{_dst_var}' points before its allocation "
                            f"(set via pointer arithmetic '= buf - N'); {fname}() writes "
                            "before the buffer start — CWE-124"
                        ),
                        rule_id="CAST-BUF-001",
                    ))
            # Pointer under-read (CWE-127): src was derived from buffer - N
            if len(args) >= 2:
                _src_arg = args[1]
                _src_var = (_txt(_src_arg) if _src_arg.type == "identifier"
                            else _first_identifier(_src_arg))
                if _src_var and _src_var in _underpointed:
                    _key = (file_path, line_no, "CAST-BUF-001")
                    if _key not in seen:
                        seen.add(_key)
                        findings.append(Finding(
                            vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_no,
                            line_content=line_text,
                            description=(
                                f"Buffer under-read: '{_src_var}' points before its allocation "
                                f"(set via pointer arithmetic '= buf - N'); {fname}() reads "
                                "before the buffer start — CWE-127"
                            ),
                            rule_id="CAST-BUF-001",
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

    # CWE-124/127 via loop: data[i] = src[i] where data is underpointed (write=124)
    # or src[i] = data[i] where data is underpointed (read=127)
    if _underpointed:
        for _loop_n in _walk(body_node):
            if _loop_n.type != "assignment_expression":
                continue
            _loop_lhs = _loop_n.child_by_field_name("left")
            _loop_rhs = _loop_n.child_by_field_name("right")
            _loop_ln = _loop_n.start_point[0] + 1
            _loop_txt = (lines[_loop_n.start_point[0]].strip()
                         if _loop_n.start_point[0] < len(lines) else "")
            # CWE-124: write to underpointed dst: data[i] = ...
            if _loop_lhs and _loop_lhs.type == "subscript_expression":
                _la = _loop_lhs.child_by_field_name("argument")
                if _la and _la.type == "identifier" and _txt(_la) in _underpointed:
                    _lkey = (file_path, _loop_ln, "CAST-BUF-001")
                    if _lkey not in seen:
                        seen.add(_lkey)
                        findings.append(Finding(
                            vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=_loop_ln,
                            line_content=_loop_txt,
                            description=(
                                f"Buffer underwrite: loop writes to '{_txt(_la)}[i]' which "
                                "points before its allocation — CWE-124"
                            ),
                            rule_id="CAST-BUF-001",
                        ))
            # CWE-127: read from underpointed src: ... = data[i]
            if _loop_rhs and _loop_rhs.type == "subscript_expression":
                _ra = _loop_rhs.child_by_field_name("argument")
                if _ra and _ra.type == "identifier" and _txt(_ra) in _underpointed:
                    _lkey = (file_path, _loop_ln, "CAST-BUF-001")
                    if _lkey not in seen:
                        seen.add(_lkey)
                        findings.append(Finding(
                            vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=_loop_ln,
                            line_content=_loop_txt,
                            description=(
                                f"Buffer under-read: loop reads from '{_txt(_ra)}[i]' which "
                                "points before its allocation — CWE-127"
                            ),
                            rule_id="CAST-BUF-001",
                        ))

    # CWE-121: loop-based buffer overflow — for(i=0; i<N; i++) { data[i]=...; }
    # where N > alloc_count(data). Detects element-count overflow on stack arrays.
    if _alloc_counts:
        for _fs in _walk(body_node):
            if _fs.type != "for_statement":
                continue
            _cond = _fs.child_by_field_name("condition")
            if _cond is None or _cond.type != "binary_expression":
                continue
            _op_n = _cond.child_by_field_name("operator")
            if _op_n is None:
                continue
            _op = _txt(_op_n)
            if _op not in ("<", "<="):
                continue
            _rbound_node = _cond.child_by_field_name("right")
            _loop_bound = _eval_const(_rbound_node) if _rbound_node else None
            if _loop_bound is None:
                continue
            if _op == "<=":
                _loop_bound += 1
            _for_body = _fs.child_by_field_name("body")
            if _for_body is None:
                continue
            for _bn in _walk(_for_body):
                if _bn.type != "assignment_expression":
                    continue
                _blhs = _bn.child_by_field_name("left")
                if _blhs is None or _blhs.type != "subscript_expression":
                    continue
                _barg = _blhs.child_by_field_name("argument")
                if _barg is None or _barg.type != "identifier":
                    continue
                _bvar = _txt(_barg)
                _bcount = _alloc_counts.get(_bvar)
                if _bcount is None or _loop_bound <= _bcount:
                    continue
                _bln = _bn.start_point[0] + 1
                _btxt = (lines[_bn.start_point[0]].strip()
                         if _bn.start_point[0] < len(lines) else "")
                _bkey = (file_path, _bln, "CAST-BUF-001")
                if _bkey not in seen:
                    seen.add(_bkey)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=_bln,
                        line_content=_btxt,
                        description=(
                            f"Buffer overflow: loop writes {_loop_bound} elements into "
                            f"'{_bvar}' ({_bcount}-element buffer) — CWE-121"
                        ),
                        rule_id="CAST-BUF-001",
                    ))

    # CWE-121/122: constant-index out-of-bounds — data[99]=x where alloc_count=50
    # Catches direct subscript accesses with a compile-time constant index >= alloc_count.
    if _alloc_counts:
        for _sn in _walk(body_node):
            if _sn.type != "assignment_expression":
                continue
            # Check LHS subscript (write out of bounds)
            _slhs = _sn.child_by_field_name("left")
            if _slhs and _slhs.type == "subscript_expression":
                _sarg = _slhs.child_by_field_name("argument")
                _sidx_raw = (_slhs.child_by_field_name("index")
                             or _slhs.child_by_field_name("indices"))
                _sidx = (next((c for c in _sidx_raw.named_children), None)
                         if _sidx_raw and _sidx_raw.type == "subscript_argument_list"
                         else _sidx_raw)
                if (_sarg and _sarg.type == "identifier" and _sidx is not None):
                    _svar = _txt(_sarg)
                    _sidx_v = _eval_const(_sidx)
                    # Constant propagation: data=10; buffer[data]=1 (CWE-129_large)
                    if _sidx_v is None and _sidx.type == "identifier":
                        _sidx_v = _const_ints.get(_txt(_sidx))
                    _scnt = _alloc_counts.get(_svar)
                    if _sidx_v is not None and _scnt is not None and (_sidx_v >= _scnt or _sidx_v < 0):
                        _sln = _sn.start_point[0] + 1
                        _stxt = (lines[_sn.start_point[0]].strip()
                                 if _sn.start_point[0] < len(lines) else "")
                        _skey = (file_path, _sln, "CAST-BUF-001")
                        if _skey not in seen:
                            seen.add(_skey)
                            findings.append(Finding(
                                vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=_sln,
                                line_content=_stxt,
                                description=(
                                    f"Buffer overflow: write to '{_svar}[{_sidx_v}]' "
                                    f"exceeds {_scnt}-element allocation — CWE-121/122"
                                ),
                                rule_id="CAST-BUF-001",
                            ))

    # CWE-129: untrusted integer array index — buffer[rand_derived] = val
    # where buffer has a statically known element count.
    if _untrusted_int and _alloc_counts:
        def _emit_cwe129(subscript_node, parent_stmt_node, var_n: str, idx_n: str, cnt_n: int) -> None:
            _ln = parent_stmt_node.start_point[0] + 1
            _tx = (lines[parent_stmt_node.start_point[0]].strip()
                   if parent_stmt_node.start_point[0] < len(lines) else "")
            _k = (file_path, _ln, "CAST-BUF-001")
            if _k not in seen:
                seen.add(_k)
                findings.append(Finding(
                    vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=_ln,
                    line_content=_tx,
                    description=(
                        f"Buffer access: array '{var_n}[{idx_n}]' "
                        f"accessed with unvalidated index from rand/atoi "
                        f"(CWE-129/126, alloc_count={cnt_n})"
                    ),
                    rule_id="CAST-BUF-001",
                ))

        # Walk ALL subscript expressions: catches both writes (lhs) and reads
        # (rhs of assignment, function args, return values, etc.)
        # CWE-129: OOB write;  CWE-126: OOB read
        for _sn in _walk(body_node):
            if _sn.type != "subscript_expression":
                continue
            _sarg = _sn.child_by_field_name("argument")
            _sidx_raw2 = (_sn.child_by_field_name("index")
                          or _sn.child_by_field_name("indices"))
            _sidx = (next((c for c in _sidx_raw2.named_children), None)
                     if _sidx_raw2 and _sidx_raw2.type == "subscript_argument_list"
                     else _sidx_raw2)
            if (_sarg and _sarg.type == "identifier" and
                    _sidx is not None and _sidx.type == "identifier"):
                _svar_n = _txt(_sarg)
                _sidx_n = _txt(_sidx)
                _scnt_u = _alloc_counts.get(_svar_n)
                if _scnt_u is not None and _sidx_n in _untrusted_int:
                    _emit_cwe129(_sn, _sn, _svar_n, _sidx_n, _scnt_u)
                # Negative constant index: data = -5; buf[data] (CWE-124/127)
                _neg_cv = _const_ints.get(_sidx_n)
                if _scnt_u is not None and _neg_cv is not None and _neg_cv < 0:
                    _nln = _sn.start_point[0] + 1
                    _ntx = (lines[_sn.start_point[0]].strip()
                            if _sn.start_point[0] < len(lines) else "")
                    _nkey = (file_path, _nln, "CAST-BUF-001")
                    if _nkey not in seen:
                        seen.add(_nkey)
                        findings.append(Finding(
                            vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=_nln,
                            line_content=_ntx,
                            description=(
                                f"Buffer underwrite/under-read: negative index {_neg_cv} "
                                f"into '{_svar_n}' via '{_sidx_n}' (CWE-124/127)"
                            ),
                            rule_id="CAST-BUF-001",
                        ))

    # Constant-index OOB reads (CWE-126/127): data=10; buf[data] read where alloc=10
    # Also negative index reads (CWE-127 under-read, CWE-124 underwrite via read)
    # Note: writes are already caught by the assignment-LHS check above.
    if _const_ints and _alloc_counts:
        for _nr in _walk(body_node):
            if _nr.type != "subscript_expression":
                continue
            _nr_arr = _nr.child_by_field_name("argument")
            _nr_idx_raw = (_nr.child_by_field_name("index")
                           or _nr.child_by_field_name("indices"))
            if _nr_arr is None or _nr_idx_raw is None:
                continue
            if _nr_idx_raw.type == "subscript_argument_list":
                _nr_idx = next((c for c in _nr_idx_raw.named_children), _nr_idx_raw)
            else:
                _nr_idx = _nr_idx_raw
            if _nr_arr.type != "identifier" or _nr_idx.type != "identifier":
                continue
            _nr_arr_n = _txt(_nr_arr)
            _nr_idx_n = _txt(_nr_idx)
            _nr_cnt = _alloc_counts.get(_nr_arr_n)
            if _nr_cnt is None:
                continue
            _nr_cv = _const_ints.get(_nr_idx_n)
            if _nr_cv is None:
                continue
            if _nr_cv < 0 or _nr_cv >= _nr_cnt:
                _nr_ln = _nr.start_point[0] + 1
                _nr_tx = (lines[_nr.start_point[0]].strip()
                          if _nr.start_point[0] < len(lines) else "")
                _nr_key = (file_path, _nr_ln, "CAST-BUF-001")
                if _nr_key not in seen:
                    seen.add(_nr_key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=_nr_ln,
                        line_content=_nr_tx,
                        description=(
                            f"Buffer OOB read: index {_nr_cv} "
                            f"into '{_nr_arr_n}' ({_nr_cnt}-element buffer)"
                            f" (CWE-124/126/127)"
                        ),
                        rule_id="CAST-BUF-001",
                    ))

    # CWE-193: Off-by-one — dest = malloc(N); memcpy(dest, src, strlen(src)+1)
    # where alloc_size["dest"] < alloc_size["src"] (no room for null terminator).
    # Covers memcpy/memmove/strncpy/wcsncpy with strlen/wcslen+1 count.
    if _alloc_sizes:
        _STRLEN193 = frozenset({"strlen", "wcslen", "_mbslen", "_tcslen"})
        _COPY193 = frozenset({"memcpy", "memmove", "strncpy", "wcsncpy",
                               "wmemcpy", "wmemmove"})

        def _strlen_arg(count_node) -> str | None:
            """Return identifier X if count_node matches strlen(X)+1 or (wcslen(X)+1)*k."""
            if count_node is None:
                return None
            n = count_node
            for _ in range(3):
                if n.type == "parenthesized_expression":
                    n = next((c for c in n.named_children), None)
                    if n is None:
                        return None
                else:
                    break
            if n.type != "binary_expression":
                return None
            op = _txt(n.child_by_field_name("operator"))
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if op == "*":
                return _strlen_arg(left) or _strlen_arg(right)
            if op == "+":
                rv = _eval_const(right)
                if rv is not None and rv >= 1 and left and left.type == "call_expression":
                    fn = _call_fname(left)
                    if fn in _STRLEN193:
                        a = _call_args(left)
                        if a and a[0].type == "identifier":
                            return _txt(a[0])
            return None

        for _c193 in _walk(body_node):
            if _c193.type != "call_expression":
                continue
            if _call_fname(_c193) not in _COPY193:
                continue
            _c193_args = _call_args(_c193)
            if len(_c193_args) < 3:
                continue
            _c193_dest = _c193_args[0]
            _c193_src = _c193_args[2]  # count arg
            if _c193_dest.type != "identifier":
                continue
            _c193_dest_n = _txt(_c193_dest)
            _src_var = _strlen_arg(_c193_src)
            if _src_var is None:
                continue
            _d_sz = _alloc_sizes.get(_c193_dest_n)
            _s_sz = _alloc_sizes.get(_src_var)
            if _d_sz is not None and _s_sz is not None and _d_sz < _s_sz:
                _c193_ln = _c193.start_point[0] + 1
                _c193_tx = (lines[_c193.start_point[0]].strip()
                            if _c193.start_point[0] < len(lines) else "")
                _c193_key = (file_path, _c193_ln, "CAST-BUF-001")
                if _c193_key not in seen:
                    seen.add(_c193_key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=_c193_ln,
                        line_content=_c193_tx,
                        description=(
                            f"Off-by-one: '{_c193_dest_n}' allocated {_d_sz}B but "
                            f"'{_src_var}' has {_s_sz}B — no room for null terminator "
                            f"(CWE-193)"
                        ),
                        rule_id="CAST-BUF-001",
                    ))

        # CWE-193/121/122: strcpy/wcscpy(dest, src) where alloc_size[dest] < alloc_size[src]
        _STRCPY_FUNCS = frozenset({"strcpy", "wcscpy", "_tcscpy", "lstrcpy",
                                    "strcat", "wcscat", "_tcscat"})
        for _sc193 in _walk(body_node):
            if _sc193.type != "call_expression":
                continue
            if _call_fname(_sc193) not in _STRCPY_FUNCS:
                continue
            _sc193_args = _call_args(_sc193)
            if len(_sc193_args) < 2:
                continue
            _sc193_dest = _sc193_args[0]
            _sc193_src = _sc193_args[1]
            if _sc193_dest.type != "identifier" or _sc193_src.type != "identifier":
                continue
            _sc193_dest_n = _txt(_sc193_dest)
            _sc193_src_n = _txt(_sc193_src)
            _sc_d_sz = _alloc_sizes.get(_sc193_dest_n)
            _sc_s_sz = _alloc_sizes.get(_sc193_src_n)
            if _sc_d_sz is not None and _sc_s_sz is not None and _sc_d_sz < _sc_s_sz:
                _sc193_ln = _sc193.start_point[0] + 1
                _sc193_tx = (lines[_sc193.start_point[0]].strip()
                             if _sc193.start_point[0] < len(lines) else "")
                _sc193_key = (file_path, _sc193_ln, "CAST-BUF-001")
                if _sc193_key not in seen:
                    seen.add(_sc193_key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=_sc193_ln,
                        line_content=_sc193_tx,
                        description=(
                            f"Buffer overflow: '{_sc193_dest_n}' ({_sc_d_sz}B) too small "
                            f"for '{_sc193_src_n}' ({_sc_s_sz}B) — no null terminator space "
                            f"(CWE-193/122)"
                        ),
                        rule_id="CAST-BUF-001",
                    ))

    # CWE-126: Buffer Overread — memcpy(dest, src, strlen(dest)*sizeof)
    # where alloc_size[src] < alloc_size[dest]: reads past end of src.
    if _alloc_sizes:
        def _count_uses_strlen_of(node, vid: str) -> bool:
            """Return True if node contains strlen/wcslen(vid) as a subexpression."""
            if node is None:
                return False
            n = node
            for _ in range(4):
                if n.type == "parenthesized_expression":
                    inner = next((c for c in n.named_children), None)
                    if inner:
                        n = inner
                    else:
                        return False
                else:
                    break
            if n.type == "call_expression":
                fn = _call_fname(n)
                if fn in _STRLEN193:
                    a = _call_args(n)
                    if a and a[0].type == "identifier" and _txt(a[0]) == vid:
                        return True
            if n.type == "binary_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                return (_count_uses_strlen_of(left, vid) or
                        _count_uses_strlen_of(right, vid))
            return False

        for _c126 in _walk(body_node):
            if _c126.type != "call_expression":
                continue
            if _call_fname(_c126) not in _COPY193:
                continue
            _c126_args = _call_args(_c126)
            if len(_c126_args) < 3:
                continue
            _c126_dest = _c126_args[0]
            _c126_src = _c126_args[1]
            _c126_cnt = _c126_args[2]
            if _c126_dest.type != "identifier" or _c126_src.type != "identifier":
                continue
            _c126_dest_n = _txt(_c126_dest)
            _c126_src_n = _txt(_c126_src)
            if not _count_uses_strlen_of(_c126_cnt, _c126_dest_n):
                continue
            _c126_src_sz = _alloc_sizes.get(_c126_src_n)
            _c126_dest_sz = _alloc_sizes.get(_c126_dest_n)
            if _c126_src_sz is not None and _c126_dest_sz is not None and _c126_src_sz < _c126_dest_sz:
                _c126_ln = _c126.start_point[0] + 1
                _c126_tx = (lines[_c126.start_point[0]].strip()
                            if _c126.start_point[0] < len(lines) else "")
                _c126_key = (file_path, _c126_ln, "CAST-BUF-001")
                if _c126_key not in seen:
                    seen.add(_c126_key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=_c126_ln,
                        line_content=_c126_tx,
                        description=(
                            f"Buffer overread: '{_c126_src_n}' ({_c126_src_sz}B) is smaller "
                            f"than '{_c126_dest_n}' ({_c126_dest_sz}B) but copy count uses "
                            f"length of dest (CWE-126)"
                        ),
                        rule_id="CAST-BUF-001",
                    ))

        # CWE-806: Buffer Overflow — memcpy(dest, src, wcslen(src)*sizeof)
        # where alloc_size[src] > alloc_size[dest]: src longer than dest.
        for _c806 in _walk(body_node):
            if _c806.type != "call_expression":
                continue
            if _call_fname(_c806) not in _COPY193:
                continue
            _c806_args = _call_args(_c806)
            if len(_c806_args) < 3:
                continue
            _c806_dest = _c806_args[0]
            _c806_src = _c806_args[1]
            _c806_cnt = _c806_args[2]
            if _c806_dest.type != "identifier" or _c806_src.type != "identifier":
                continue
            _c806_dest_n = _txt(_c806_dest)
            _c806_src_n = _txt(_c806_src)
            if not _count_uses_strlen_of(_c806_cnt, _c806_src_n):
                continue
            _c806_src_sz = _alloc_sizes.get(_c806_src_n)
            _c806_dest_sz = _alloc_sizes.get(_c806_dest_n)
            if _c806_src_sz is not None and _c806_dest_sz is not None and _c806_src_sz > _c806_dest_sz:
                _c806_ln = _c806.start_point[0] + 1
                _c806_tx = (lines[_c806.start_point[0]].strip()
                            if _c806.start_point[0] < len(lines) else "")
                _c806_key = (file_path, _c806_ln, "CAST-BUF-001")
                if _c806_key not in seen:
                    seen.add(_c806_key)
                    findings.append(Finding(
                        vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=_c806_ln,
                        line_content=_c806_tx,
                        description=(
                            f"Buffer overflow: copy count uses wcslen/strlen of "
                            f"'{_c806_src_n}' ({_c806_src_sz}B) but dest '{_c806_dest_n}' "
                            f"is only {_c806_dest_sz}B (CWE-806)"
                        ),
                        rule_id="CAST-BUF-001",
                    ))

    # CWE-121/122/126/805: Loop-based buffer overflow/overread
    # Detects: for (i=0; i<BOUND; i++) buf[i]=... where alloc_counts[buf] < BOUND
    # Also handles: destLen = strlen(X); for (i=0; i<destLen; i++) smallBuf[i]=...
    if _alloc_counts:
        for _lp in _walk(body_node):
            if _lp.type != "for_statement":
                continue
            _lp_cond_st = _lp.child_by_field_name("condition")
            if _lp_cond_st is None:
                continue
            # condition field is expression_statement wrapping the actual expr
            if _lp_cond_st.type == "expression_statement":
                _lp_cond = next(
                    (c for c in _lp_cond_st.named_children if c.type != "comment"),
                    None)
            else:
                _lp_cond = _lp_cond_st
            if _lp_cond is None:
                continue
            # Peel outer parentheses
            while _lp_cond.type == "parenthesized_expression":
                _lp_cond = next((c for c in _lp_cond.named_children
                                 if c.type != "comment"), _lp_cond)
            if _lp_cond.type != "binary_expression":
                continue
            _lp_op_nd = _lp_cond.child_by_field_name("operator")
            _lp_op = _txt(_lp_op_nd) if _lp_op_nd else None
            if _lp_op not in ("<", "<="):
                continue
            _lp_lch = _lp_cond.child_by_field_name("left")
            _lp_rch = _lp_cond.child_by_field_name("right")
            if _lp_lch is None or _lp_lch.type != "identifier":
                continue
            _lp_var = _txt(_lp_lch)  # loop variable, e.g. "i"

            # Evaluate upper bound from the right side
            _lp_bound = _eval_const(_lp_rch)
            if _lp_bound is None and _lp_rch is not None:
                if _lp_rch.type == "identifier":
                    _lp_bv = _txt(_lp_rch)
                    _lp_bound = _const_ints.get(_lp_bv)
                    if _lp_bound is None:
                        # destLen = strlen(X) → bound ≈ alloc_counts[X] (upper bound approx)
                        _lp_sv = _strlen_vars.get(_lp_bv)
                        if _lp_sv is not None:
                            _lp_bound = _alloc_counts.get(_lp_sv)
            if _lp_bound is None:
                continue
            # For <=: iterates 0..bound inclusive → effective element count = bound+1
            _lp_eff = _lp_bound + 1 if _lp_op == "<=" else _lp_bound

            _lp_body = _lp.child_by_field_name("body")
            if _lp_body is None:
                continue
            for _lp_sub in _walk(_lp_body):
                if _lp_sub.type != "subscript_expression":
                    continue
                _lp_arr = _lp_sub.child_by_field_name("argument")
                _lp_idx = (_lp_sub.child_by_field_name("index")
                           or _lp_sub.child_by_field_name("indices"))
                if _lp_arr is None or _lp_idx is None:
                    continue
                if _lp_idx.type == "subscript_argument_list":
                    _lp_idx = next((c for c in _lp_idx.named_children), _lp_idx)
                if _lp_arr.type != "identifier" or _lp_idx.type != "identifier":
                    continue
                if _txt(_lp_idx) != _lp_var:
                    continue
                _lp_buf = _txt(_lp_arr)
                _lp_cnt = _alloc_counts.get(_lp_buf)
                if _lp_cnt is not None and _lp_cnt < _lp_eff:
                    _lp_ln = _lp.start_point[0] + 1
                    _lp_tx = (lines[_lp.start_point[0]].strip()
                              if _lp.start_point[0] < len(lines) else "")
                    _lp_key = (file_path, _lp_ln, "CAST-BUF-001")
                    if _lp_key not in seen:
                        seen.add(_lp_key)
                        findings.append(Finding(
                            vuln_type=VulnType.TRUST_BOUNDARY_VIOLATION,
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=_lp_ln,
                            line_content=_lp_tx,
                            description=(
                                f"Buffer overflow/overread: loop iterates '{_lp_var}' "
                                f"0..{_lp_eff - 1} but '{_lp_buf}' has only "
                                f"{_lp_cnt} element(s) (CWE-121/122/126)"
                            ),
                            rule_id="CAST-BUF-001",
                        ))

    # C-7: Scoped UAF — free(p)/delete p followed by use in same function
    _freed: dict[str, int] = {}
    _FREE_FUNCS_UAF = frozenset({"free", "cfree", "_free", "kfree",
                                 "HeapFree", "LocalFree", "GlobalFree",
                                 "operator delete", "operator delete[]"})
    for _uaf_node in _walk(body_node):
        _uaf_t = _uaf_node.type
        if _uaf_t == "call_expression":
            _uaf_fn = _call_fname(_uaf_node)
            _uaf_args = _call_args(_uaf_node)
            if _uaf_fn in _FREE_FUNCS_UAF and _uaf_args:
                _uaf_var = _txt(_uaf_args[0]).strip("() \t")
                if _uaf_var and _uaf_var not in _freed:
                    _freed[_uaf_var] = _uaf_node.start_point[0] + 1
        elif _uaf_t in ("delete_expression", "delete_expression_statement"):
            _del_inner = next(
                (c for c in _uaf_node.named_children if c.type != "comment"), None
            )
            if _del_inner and _del_inner.type == "identifier":
                _del_var = _txt(_del_inner)
                if _del_var and _del_var not in _freed:
                    _freed[_del_var] = _uaf_node.start_point[0] + 1

    if _freed:
        for _uaf_node in _walk(body_node):
            _uaf_t = _uaf_node.type
            if _uaf_t in ("pointer_expression", "subscript_expression", "field_expression"):
                _cand = _uaf_node.child_by_field_name("argument") or (
                    _uaf_node.named_children[0] if _uaf_node.named_children else None
                )
                if _cand and _cand.type == "identifier":
                    _cvar = _txt(_cand)
                    _free_ln = _freed.get(_cvar)
                    if _free_ln and _uaf_node.start_point[0] + 1 > _free_ln:
                        _uaf_ln = _uaf_node.start_point[0] + 1
                        _key = (file_path, _uaf_ln, "CAST-UAF-001")
                        if _key not in seen:
                            seen.add(_key)
                            _uaf_text = (lines[_uaf_node.start_point[0]].strip()
                                         if _uaf_node.start_point[0] < len(lines) else "")
                            findings.append(Finding(
                                vuln_type=VulnType.RACE_CONDITION,
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=_uaf_ln,
                                line_content=_uaf_text,
                                description=(
                                    f"Use-after-free: '{_cvar}' is used at line {_uaf_ln} "
                                    f"after being freed at line {_free_ln} (CWE-416)"
                                ),
                                rule_id="CAST-UAF-001",
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


def _analyze_with_parser(parser_fn, content: str, file_path: str) -> list[Finding]:
    # Step 1: Preprocess (macro expansion / clang -E)
    lang = "c++" if any(file_path.endswith(e) for e in _CPP_EXTS) else "c"
    processed = _preprocess(content, lang)

    try:
        parser = parser_fn()
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
    global_untrusted_int: set[str] = set()  # file-scope vars assigned from rand/atoi
    _INT_TAINT_G: frozenset[str] = frozenset({
        "rand", "RAND32", "rand_r", "random", "lrand48", "mrand48",
    })
    _INT_CONV_G: frozenset[str] = frozenset({
        "atoi", "atol", "atoll", "atof",
        "strtol", "strtoll", "strtoul", "strtoull",
        "wcstol", "wcstoll", "_wtoi", "_wtol",
    })
    _INT_SCANF_G: dict[str, int] = {
        "scanf": 1, "wscanf": 1, "fscanf": 2, "fwscanf": 2, "sscanf": 2,
    }

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

            # Collect global variables assigned from rand/atoi → global_untrusted_int
            # Also tracks per-function locals (for V45: local = atoi(); global = local)
            _fbody = func_node.child_by_field_name("body")
            _flocals = _collect_local_decls(func_node)
            if _fbody:
                # _flocalui: all untrusted-integer vars within this function (local OR global)
                _flocalui: set[str] = set(global_untrusted_int)
                # Seed from this function's untrusted_int_params → param variable names
                for _fui_pi, _fui_pn in enumerate(_get_param_names(func_node)):
                    if _fui_pi in summaries[fname].untrusted_int_params:
                        _flocalui.add(_fui_pn)
                for _fsn in _walk(_fbody):
                    if _fsn.type == "assignment_expression":
                        _flhs = _fsn.child_by_field_name("left")
                        _frhs = _fsn.child_by_field_name("right")
                        if _flhs and _flhs.type == "identifier":
                            _fvar = _txt(_flhs)
                            _fnode = _frhs
                            for _ in range(3):
                                if _fnode and _fnode.type in (
                                        "cast_expression", "parenthesized_expression"):
                                    _fnode = next((c for c in _fnode.named_children
                                                   if c.type not in ("type_descriptor",)),
                                                  None)
                                else:
                                    break
                            _fmarked = False
                            if _fnode and _fnode.type == "call_expression":
                                _ffn = _call_fname(_fnode)
                                if _ffn in _INT_TAINT_G:
                                    _fmarked = True
                                elif _ffn in _INT_CONV_G:
                                    _fargs = _call_args(_fnode)
                                    if (_fargs and _fargs[0].type == "identifier"
                                            and _txt(_fargs[0]) in tainted):
                                        _fmarked = True
                            elif (_fnode and _fnode.type == "identifier"
                                    and _txt(_fnode) in _flocalui):
                                # Propagation: var = untrusted_int_var (V45: global = local_ui)
                                _fmarked = True
                            if _fmarked:
                                _flocalui.add(_fvar)
                                if _fvar not in _flocals and _fvar not in global_untrusted_int:
                                    global_untrusted_int.add(_fvar)
                                    changed = True
                    elif _fsn.type == "call_expression":
                        _fscfn = _call_fname(_fsn)
                        if _fscfn in _INT_SCANF_G:
                            _fsc_base = _INT_SCANF_G[_fscfn]
                            _fsc_args = _call_args(_fsn)
                            for _fsc_arg in _fsc_args[_fsc_base:]:
                                if (_fsc_arg.type == "pointer_expression"
                                        and _fsc_arg.children
                                        and _txt(_fsc_arg.children[0]) == "&"):
                                    _fsc_inner = next(
                                        (c for c in _fsc_arg.named_children), None)
                                    if _fsc_inner and _fsc_inner.type == "identifier":
                                        _fsc_vn = _txt(_fsc_inner)
                                        _flocalui.add(_fsc_vn)
                                        if (_fsc_vn not in _flocals
                                                and _fsc_vn not in global_untrusted_int):
                                            global_untrusted_int.add(_fsc_vn)
                                            changed = True

        # Propagate untrusted-integer values interprocedurally (V41/V42/etc.)
        # For each function, compute its local _func_untrusted_int set, then mark any
        # call argument that is in that set as untrusted_int_params in the callee summary.
        for _ui_fname, _ui_func_node in funcs.items():
            _ui_fbody = _ui_func_node.child_by_field_name("body")
            if not _ui_fbody:
                continue
            _ui_tainted = _analyze_func_with_summaries(
                _ui_func_node, summaries, None, global_tainted
            )
            _ui_pnames = _get_param_names(_ui_func_node)
            _ui_flocals = _collect_local_decls(_ui_func_node)
            _func_ui: set[str] = set(global_untrusted_int)
            # Seed from this function's own untrusted_int_params (params received as untrusted int)
            for _ui_pi, _ui_pn in enumerate(_ui_pnames):
                if _ui_pi in summaries[_ui_fname].untrusted_int_params:
                    _func_ui.add(_ui_pn)
            # Collect local assignments: var = rand/RAND32() or var = atoi(tainted)
            for _ui_sn in _walk(_ui_fbody):
                if _ui_sn.type in ("assignment_expression", "init_declarator"):
                    if _ui_sn.type == "assignment_expression":
                        _ui_lhs = _ui_sn.child_by_field_name("left")
                        _ui_rhs = _ui_sn.child_by_field_name("right")
                        _ui_lv = _txt(_ui_lhs) if _ui_lhs and _ui_lhs.type == "identifier" else None
                    else:
                        _ui_dl = _ui_sn.child_by_field_name("declarator")
                        _ui_rhs = _ui_sn.child_by_field_name("value")
                        _ui_lv = _decl_leaf_id(_ui_dl) if _ui_dl else None
                    if _ui_lv and _ui_rhs:
                        _ui_n = _ui_rhs
                        for _ in range(3):
                            if _ui_n and _ui_n.type in (
                                    "cast_expression", "parenthesized_expression"):
                                _ui_n = next((c for c in _ui_n.named_children
                                              if c.type not in ("type_descriptor",)), None)
                            else:
                                break
                        if _ui_n and _ui_n.type == "call_expression":
                            _ui_fn = _call_fname(_ui_n)
                            if _ui_fn in _INT_TAINT_G:
                                _func_ui.add(_ui_lv)
                            elif _ui_fn in _INT_CONV_G:
                                _ui_fa = _call_args(_ui_n)
                                if (_ui_fa and _ui_fa[0].type == "identifier"
                                        and _txt(_ui_fa[0]) in _ui_tainted):
                                    _func_ui.add(_ui_lv)
                            elif (summaries and _call_fname(_ui_n) in summaries
                                    and (summaries[_call_fname(_ui_n)].returns_tainted
                                         or summaries[_call_fname(_ui_n)].returns_untrusted_int)):
                                _func_ui.add(_ui_lv)
                        elif (_ui_n and _ui_n.type == "identifier"
                                and _txt(_ui_n) in _func_ui):
                            # Propagation: x = func_ui_var (V31 copy chain, V67 struct read)
                            _func_ui.add(_ui_lv)
                        elif (_ui_n and _ui_n.type == "field_expression"):
                            # V67 read: data = struct.field where struct ∈ _func_ui
                            _fe_obj = _ui_n.child_by_field_name("argument")
                            if (_fe_obj and _fe_obj.type == "identifier"
                                    and _txt(_fe_obj) in _func_ui):
                                _func_ui.add(_ui_lv)
                # V67 write: struct.field = func_ui_var → struct ∈ _func_ui
                if _ui_sn.type == "assignment_expression":
                    _ui_lhsf = _ui_sn.child_by_field_name("left")
                    _ui_rhsf = _ui_sn.child_by_field_name("right")
                    if (_ui_lhsf and _ui_lhsf.type == "field_expression"
                            and _ui_rhsf and _ui_rhsf.type == "identifier"
                            and _txt(_ui_rhsf) in _func_ui):
                        _ui_base = _ui_lhsf.child_by_field_name("argument")
                        if _ui_base and _ui_base.type == "identifier":
                            _func_ui.add(_txt(_ui_base))
                elif _ui_sn.type == "call_expression":
                    _ui_scfn = _call_fname(_ui_sn)
                    if _ui_scfn in _INT_SCANF_G:
                        _ui_sc_base = _INT_SCANF_G[_ui_scfn]
                        _ui_sc_args = _call_args(_ui_sn)
                        for _ui_sc_arg in _ui_sc_args[_ui_sc_base:]:
                            if (_ui_sc_arg.type == "pointer_expression"
                                    and _ui_sc_arg.children
                                    and _txt(_ui_sc_arg.children[0]) == "&"):
                                _ui_sc_in = next(
                                    (c for c in _ui_sc_arg.named_children), None)
                                if _ui_sc_in and _ui_sc_in.type == "identifier":
                                    _func_ui.add(_txt(_ui_sc_in))
            # Check if this function returns an untrusted int (V42 rand-source pattern)
            if _func_ui and not summaries[_ui_fname].returns_untrusted_int:
                for _ui_sn in _walk(_ui_fbody):
                    if _ui_sn.type == "return_statement":
                        _ui_ret = next((c for c in _ui_sn.named_children
                                        if c.type not in ("comment",)), None)
                        if _ui_ret and _ui_ret.type == "identifier" and _txt(_ui_ret) in _func_ui:
                            summaries[_ui_fname].returns_untrusted_int = True
                            changed = True
                            break
            # Propagate: any call arg that is an untrusted_int → callee.untrusted_int_params
            if _func_ui:
                _ui_fpm = _collect_funcptr_map(_ui_func_node)
                for _ui_sn in _walk(_ui_fbody):
                    if _ui_sn.type == "call_expression":
                        _ui_cn = _call_fname(_ui_sn)
                        # Resolve function pointer (V44 pattern: funcPtr = badSink; funcPtr(data))
                        if _ui_cn and _ui_cn in _ui_fpm:
                            _ui_cn = _ui_fpm[_ui_cn]
                        if _ui_cn and _ui_cn in summaries:
                            _ui_ca = _call_args(_ui_sn)
                            for _ui_ci, _ui_carg in enumerate(_ui_ca):
                                if (_ui_carg.type == "identifier"
                                        and _txt(_ui_carg) in _func_ui
                                        and _ui_ci not in summaries[_ui_cn].untrusted_int_params):
                                    summaries[_ui_cn].untrusted_int_params.add(_ui_ci)
                                    changed = True
                                elif (_ui_carg.type == "pointer_expression"
                                        and _ui_carg.children
                                        and _txt(_ui_carg.children[0]) == "&"):
                                    # &var passed as arg → mark callee param as untrusted_int_ptr
                                    _ui_inner = next(
                                        (c for c in _ui_carg.named_children), None)
                                    if (_ui_inner and _ui_inner.type == "identifier"
                                            and _txt(_ui_inner) in _func_ui
                                            and _ui_ci not in summaries[_ui_cn].untrusted_int_ptr_params):
                                        summaries[_ui_cn].untrusted_int_ptr_params.add(_ui_ci)
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

    # Interprocedural alloc_count propagation: return values and parameters
    _update_alloc_summaries(funcs, summaries)

    # Collect global alloc_counts for V68: global_ptr = local_small_buf in one function,
    # then other function reads global_ptr and uses it with large index → OOB.
    _global_alloc_counts: dict[str, int] = {}
    for _g68_fname, _g68_fn in funcs.items():
        _g68_body = _g68_fn.child_by_field_name("body")
        if _g68_body is None:
            continue
        _g68_flocals = _collect_local_decls(_g68_fn)
        _g68_counts: dict[str, int] = _compute_alloc_counts(_g68_body)
        # Augment with param_alloc_counts
        _g68_pnames = _get_param_names(_g68_fn)
        for _g68_pi, _g68_pc in summaries[_g68_fname].param_alloc_counts.items():
            if _g68_pi < len(_g68_pnames):
                _pn68 = _g68_pnames[_g68_pi]
                if _pn68 not in _g68_counts or _g68_counts[_pn68] > _g68_pc:
                    _g68_counts[_pn68] = _g68_pc
        for _g68_sn in _walk(_g68_body):
            if _g68_sn.type == "assignment_expression":
                _g68_lhs = _g68_sn.child_by_field_name("left")
                _g68_rhs = _g68_sn.child_by_field_name("right")
                if (_g68_lhs and _g68_lhs.type == "identifier"
                        and _g68_rhs and _g68_rhs.type == "identifier"):
                    _g68_lvar = _txt(_g68_lhs)
                    _g68_rvar = _txt(_g68_rhs)
                    if _g68_lvar not in _g68_flocals:  # it's a global/static
                        _g68_cnt = _g68_counts.get(_g68_rvar)
                        if _g68_cnt is not None:
                            _g68_ex = _global_alloc_counts.get(_g68_lvar)
                            if _g68_ex is None or _g68_cnt < _g68_ex:
                                _global_alloc_counts[_g68_lvar] = _g68_cnt

    # Step 4: Final pass — emit findings
    for fname, func_node in funcs.items():
        tainted = _analyze_func_with_summaries(func_node, summaries, None, global_tainted)
        body = func_node.child_by_field_name("body")
        if body:
            # Seed extra alloc_counts and underpointed from interprocedural param summaries
            _extra: dict[str, int] = {}
            _extra_up: set[str] = set()
            param_names = _get_param_names(func_node)
            for _pidx, _pcnt in summaries[fname].param_alloc_counts.items():
                if _pidx < len(param_names):
                    _extra[param_names[_pidx]] = _pcnt
            for _pidx in summaries[fname].param_underpointed:
                if _pidx < len(param_names):
                    _extra_up.add(param_names[_pidx])
            # Also seed untrusted_int from interprocedural param tracking (V41/V42/V45)
            _extra_ui: set[str] = set()
            _extra_ui_ptrs: set[str] = set()
            for _pidx in summaries[fname].untrusted_int_params:
                if _pidx < len(param_names):
                    _extra_ui.add(param_names[_pidx])
            for _pidx in summaries[fname].untrusted_int_ptr_params:
                if _pidx < len(param_names):
                    _extra_ui_ptrs.add(param_names[_pidx])
            _merged_ui = (global_untrusted_int | _extra_ui) if _extra_ui else global_untrusted_int
            # Seed pointer-to-buffer alloc counts for V63 (char** dataPtr pattern)
            _extra_ptr: dict[str, int] = {}
            for _pidx, _pcnt in summaries[fname].param_ptr_alloc_counts.items():
                if _pidx < len(param_names):
                    _extra_ptr[param_names[_pidx]] = _pcnt
            # Merge global alloc_counts (V68: global_ptr = small_buf in caller) into _extra
            if _global_alloc_counts:
                for _g68v, _g68c in _global_alloc_counts.items():
                    if _g68v not in _extra or _extra[_g68v] > _g68c:
                        _extra[_g68v] = _g68c
            _detect_sinks(body, tainted, lines, file_path, findings, summaries,
                          _collect_funcptr_map(func_node),
                          extra_alloc_counts=_extra if _extra else None,
                          extra_underpointed=_extra_up if _extra_up else None,
                          global_untrusted_int=_merged_ui or None,
                          untrusted_int_ptr_names=_extra_ui_ptrs or None,
                          extra_ptr_alloc_counts=_extra_ptr if _extra_ptr else None)

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
        return _analyze_with_parser(_get_c_parser, content, file_path)


class CPPASTAnalyzer(BaseAnalyzer):
    """C++ AST taint analyzer (.cc / .cpp / .cxx / etc.)."""

    supported_extensions = _CPP_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_C_AVAILABLE:
            return []
        return _analyze_with_parser(_get_cpp_parser, content, file_path)
