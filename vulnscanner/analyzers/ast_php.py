"""PHP AST taint analyzer (tree-sitter-php) — multi-vuln, multi-hop taint tracking.

Improvements over regex-based analysis:
  - True AST parsing: no false matches in comments or string literals
  - Multi-hop taint: $_GET['id'] → $q = "SELECT...".$id → $pdo->query($q)
  - Fixed-point propagation: handles reassignment, concatenation (.=), functions
  - Recursive statement processing: if/else, loops, nested blocks
  - String interpolation: "SELECT...{$id}" correctly tainted

Rule IDs (PHAST-*):
  PHAST-SQL-001   SQL injection (PDO::query/exec/prepare, mysqli, mysql_query)
  PHAST-CMD-001   Command injection (system, exec, shell_exec, passthru, popen)
  PHAST-PATH-001  Path traversal (file_get_contents, fopen, readfile, include/require)
  PHAST-XSS-001   Reflected XSS (echo, print with unsanitized user input)
  PHAST-SSRF-001  SSRF (curl_setopt CURLOPT_URL, file_get_contents with URL)
  PHAST-REDIR-001 Open redirect (header("Location: " . $url))
  PHAST-DESER-001 Insecure deserialization (unserialize with user input)
  PHAST-LDAP-001  LDAP injection (ldap_search filter arg is user-controlled)
  PHAST-LOG-001   Log injection (error_log with user input)
  PHAST-EVAL-001  Code injection (eval() with user input)
  PHAST-EVAL-002  Code injection (assert() with user input — PHP < 8.0 evaluates strings)
  PHAST-CMD-002   Command injection (backtick shell execution `$cmd`)
  PHAST-SSTI-001  SSTI (Twig createTemplate, Smarty fetch with tainted template)
  PHAST-UPLOAD-001 Unrestricted file upload (stored name/extension taken from the client)
"""
from __future__ import annotations

import re
import threading as _threading
from dataclasses import dataclass as _dataclass, field as _field

try:
    import tree_sitter_php as _tsp
    from tree_sitter import Language, Parser as _TSParser
    _PHP_LANGUAGE = Language(_tsp.language_php())
    _php_parser = _TSParser(_PHP_LANGUAGE)
    _TS_AVAILABLE = True
except Exception:
    _TS_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType


# ── Cross-file taint context ──────────────────────────────────────────────────

@_dataclass
class PhpCrossFileContext:
    """PHP function names (from any .php file) that return tainted data."""
    tainted_func_names: frozenset[str] = _field(default_factory=frozenset)
    # Eloquent models declared with `$guarded = []` (every attribute mass-assignable).
    unguarded_models: frozenset[str] = _field(default_factory=frozenset)


_php_cf_local = _threading.local()


def set_php_cross_file_context(ctx: "PhpCrossFileContext | None") -> None:
    _php_cf_local.ctx = ctx


def _get_php_cf_ctx() -> "PhpCrossFileContext | None":
    return getattr(_php_cf_local, "ctx", None)


_UNGUARDED_RE = re.compile(r"\$guarded\s*=\s*\[\s*\]\s*;")
_CLASS_NAME_RE = re.compile(r"\bclass\s+(\w+)")


def _unguarded_models_of(path: str, content: str) -> frozenset[str]:
    """Eloquent model declared `$guarded = []` in application code (not vendor / tests / fixtures).
    A temporary `Model::unguard()` in an importer or seeder is deliberately not counted."""
    from vulnscanner.analyzers.file_context import is_fixture_path, is_test_path, is_vendor_file
    if is_vendor_file(path) or is_test_path(path) or is_fixture_path(path):
        return frozenset()
    if _UNGUARDED_RE.search(content):
        m = _CLASS_NAME_RE.search(content)
        if m:
            return frozenset({m.group(1)})
    return frozenset()


def collect_php_file(path: str, content: str) -> "tuple[frozenset[str], frozenset[str]] | None":
    """Per-file part of the pre-pass: (tainted function names, unguarded Eloquent models)."""
    if not _TS_AVAILABLE or not path.endswith(".php"):
        return None
    try:
        tree = _php_parser.parse(content.encode("utf-8", errors="replace"))
        _, file_funcs, _ = _build_taint(tree.root_node)
        return frozenset(file_funcs), _unguarded_models_of(path, content)
    except Exception:
        return None


def merge_php_cross_file_parts(parts) -> PhpCrossFileContext:
    global_tainted: set[str] = set()
    unguarded: set[str] = set()
    for part in parts:
        if isinstance(part, tuple):
            global_tainted.update(part[0])
            unguarded.update(part[1])
        else:                       # a bare set of function names (older callers)
            global_tainted.update(part)
    return PhpCrossFileContext(tainted_func_names=frozenset(global_tainted),
                               unguarded_models=frozenset(unguarded))


def build_php_cross_file_context(all_contents: dict[str, str]) -> PhpCrossFileContext:
    """Pre-pass: collect all PHP function names that return tainted data."""
    parts = (collect_php_file(path, content) for path, content in all_contents.items())
    return merge_php_cross_file_parts(p for p in parts if p is not None)

# ── Source definitions ────────────────────────────────────────────────────────

_SOURCES: frozenset[str] = frozenset({
    '_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER',
})

# Laravel / Symfony-style request objects: a `Request $request` parameter (seeded as tainted by
# _seed_request_params), `request()` and the `Request::` facade carry client data. Methods that
# answer a yes/no question, cast the value, or return something other than client data do not.
_REQUEST_SAFE_METHODS: frozenset[str] = frozenset({
    'user', 'session', 'ip', 'ips', 'has', 'hasAny', 'filled', 'missing', 'isMethod', 'method',
    'boolean', 'integer', 'float', 'ajax', 'pjax', 'wantsJson', 'expectsJson', 'routeIs', 'hasFile',
    'hasHeader', 'hasCookie', 'is', 'secure', 'isJson', 'hasValidSignature', 'validate', 'validateWithBag',
    # UploadedFile attributes the server computes (the client-chosen name is getClientOriginalName)
    'getRealPath', 'getPathname', 'path', 'hashName', 'getSize', 'getMimeType', 'guessExtension',
    'extension', 'getError', 'isValid',
    # The client's extension cannot leave its directory (no separator survives it), so it is not
    # path-taint; PHAST-UPLOAD-001 reports the real problem (an extension the client picks).
    'getClientOriginalExtension',
})
# `$_FILES['f']['tmp_name']` is the server's own temporary path, `error` and `size` are numbers.
_FILES_SERVER_FIELD_RE = re.compile(r"""^\$_FILES\s*\[[^\]]*\]\s*\[\s*['"](?:tmp_name|error|size)['"]\s*\]$""")
# Path helpers that return a filesystem path built from their argument.
_PATH_HELPERS: frozenset[str] = frozenset({
    'storage_path', 'public_path', 'base_path', 'app_path', 'resource_path', 'config_path',
    'database_path', 'lang_path',
})
# String functions that change the shape of a value without making it safe: what the client sent
# is still in the result (`trim($_GET['id'])`, `str_replace("'", '', $x)`, `implode(',', $ids)`).
# Sanitizers (intval, htmlspecialchars, urlencode ...) are not here; they are in _ALL_SANITIZERS.
_PASSTHROUGH_FUNCS: frozenset[str] = frozenset({
    'trim', 'ltrim', 'rtrim', 'chop',
    'strtolower', 'strtoupper', 'ucfirst', 'lcfirst', 'ucwords',
    'mb_strtolower', 'mb_strtoupper', 'mb_convert_case', 'mb_substr', 'mb_convert_encoding',
    'substr', 'substr_replace', 'str_replace', 'str_ireplace', 'strtr', 'preg_replace',
    'str_pad', 'str_repeat', 'strrev', 'wordwrap', 'nl2br', 'strval',
    'sprintf', 'vsprintf', 'implode', 'join', 'explode', 'str_split', 'preg_split',
    'urldecode', 'rawurldecode', 'base64_decode', 'stripslashes', 'stripcslashes',
    'html_entity_decode', 'htmlspecialchars_decode', 'json_decode',
    'utf8_decode', 'utf8_encode', 'iconv',
})
_FORMAT_FUNCS: frozenset[str] = frozenset({'sprintf', 'vsprintf'})
_FORMAT_SPEC_RE = re.compile(r"%(?:\d+\$)?[-+ 0]*(?:'.)?\d*(?:\.\d+)?([a-zA-Z%])")
# Query-builder / DB-facade methods that take a raw SQL fragment as their first argument.
_SQL_RAW_METHODS: frozenset[str] = frozenset({
    'whereRaw', 'orWhereRaw', 'havingRaw', 'orHavingRaw', 'orderByRaw', 'selectRaw', 'groupByRaw',
    'fromRaw', 'joinRaw',
})
_DB_FACADE_SQL_METHODS: frozenset[str] = frozenset({
    'select', 'selectOne', 'statement', 'unprepared', 'raw', 'insert', 'update', 'delete',
    'scalar', 'affectingStatement', 'cursor',
})
_MASS_ASSIGN_METHODS: frozenset[str] = frozenset({
    'create', 'update', 'fill', 'forceFill', 'firstOrCreate', 'updateOrCreate', 'forceCreate',
})
# Illuminate\Filesystem\Filesystem / File:: operate on any path (unlike Storage disks, which are rooted).
_FILESYSTEM_METHODS: frozenset[str] = frozenset({
    'get', 'put', 'size', 'lastModified', 'exists', 'delete', 'isFile', 'isDirectory', 'move', 'copy',
    'files', 'allFiles', 'directories', 'hash', 'mimeType', 'append', 'prepend', 'sharedGet', 'getRequire',
    'requireOnce', 'lines', 'type', 'extension', 'basename', 'cleanDirectory', 'deleteDirectory',
})
_FILESYSTEM_RECEIVER_RE = re.compile(r'filesystem|^\$files$|^\$fs$', re.IGNORECASE)
_HTTP_FACADE_METHODS: frozenset[str] = frozenset({
    'get', 'post', 'put', 'patch', 'delete', 'head', 'send',
})

# ── Sanitizer definitions ─────────────────────────────────────────────────────

# Variables that conventionally accumulate output markup, and a markup tag inside the expression.
_OUTPUT_BUFFER_NAME_RE = re.compile(r'(?:html|output|out|content|body|response|msg|message)\Z', re.IGNORECASE)
_HTML_TAG_RE = re.compile(r'<[A-Za-z/!]')

# HTML output sanitizers (XSS)
_XSS_SANITIZERS: frozenset[str] = frozenset({
    'htmlspecialchars', 'htmlentities', 'strip_tags',
    'esc_html', 'esc_attr', 'esc_textarea', 'esc_url',
    'wp_kses', 'wp_kses_post', 'sanitize_text_field', 'wp_strip_all_tags',
})
# Numeric/type casters that sanitize SQL
_SQL_SANITIZERS: frozenset[str] = frozenset({
    'intval', 'floatval', 'abs', 'round', 'ceil', 'floor',
    'number_format', 'is_numeric',
})
# All sanitizers (clear taint on assignment)
_ALL_SANITIZERS: frozenset[str] = _XSS_SANITIZERS | _SQL_SANITIZERS | frozenset({
    'addslashes', 'mysqli_real_escape_string', 'pg_escape_string',
    'preg_quote', 'urlencode', 'rawurlencode', 'base64_encode',
    'filter_var', 'filter_input', 'ctype_digit', 'ctype_alpha',
})

# ── Sink definitions ──────────────────────────────────────────────────────────

# SQL sinks — function_call_expression
_SQL_FUNC_SINKS: frozenset[str] = frozenset({
    'mysql_query', 'mysql_db_query',
    'mysqli_query', 'mysqli_multi_query', 'mysqli_real_query',
    'pg_query', 'pg_send_query',
    'sqlite_query', 'sqlite_exec',
    'db_query', 'wpdb_get_results',
})
# SQL sinks where the SQL is arg[1] (first is the connection handle)
_SQL_FUNC_SINKS_ARG1: frozenset[str] = frozenset({
    'mysqli_query', 'mysqli_multi_query', 'mysqli_real_query',
    'pg_query', 'pg_send_query',
    'sqlite_query',
})
# SQL sinks — member_call_expression (PDO, mysqli object)
_DB_RECEIVER_RE = re.compile(r'db|conn|pdo|sql|mysqli|database|adapter|dbal|statement|stmt|query', re.I)

_SQL_METHOD_SINKS: frozenset[str] = frozenset({
    'query', 'exec', 'prepare', 'multi_query', 'real_query',
    'execute',
})

# Command injection — function_call_expression
_CMD_FUNC_SINKS: frozenset[str] = frozenset({
    'system', 'exec', 'passthru', 'shell_exec', 'popen',
    'proc_open', 'pcntl_exec',
})

# Path traversal — function_call_expression (arg 0 is path)
_PATH_FUNC_SINKS: frozenset[str] = frozenset({
    'file_get_contents', 'file_put_contents', 'file', 'readfile',
    'fopen', 'fwrite', 'fputs', 'unlink', 'rename', 'copy',
    'mkdir', 'rmdir', 'opendir', 'glob',
    'highlight_file', 'show_source', 'parse_ini_file',
    'include', 'require',
})

# Readers that fetch a remote URL when given one (allow_url_fopen): SSRF when the variable is a URL.
_URL_READ_FUNCS: frozenset[str] = frozenset({'file_get_contents', 'fopen', 'readfile', 'file', 'copy'})
# A URL-ish word at a name boundary ($url, $remote_url, {$link}) or a camelCase boundary ($imageUrl);
# a bare substring match fired on the 'uri' inside "security".
_URL_NAME_RE = re.compile(
    r'(?:^|[^A-Za-z])(?i:url|uri|link|endpoint|href|remote)|(?<=[a-z])(?:Url|Uri|Link|Endpoint|Href|Remote)')

# SSRF — curl_setopt with CURLOPT_URL
_CURL_URL_CONSTS: frozenset[str] = frozenset({'CURLOPT_URL', 'CURLOPT_PROXY'})

# ── AST helpers ───────────────────────────────────────────────────────────────

def _var_name(node) -> str | None:
    """Return bare name (no $) from a variable_name node, or None."""
    if node.type != 'variable_name':
        return None
    for child in node.children:
        if child.type == 'name':
            return child.text.decode('utf-8', errors='replace')
    return None


def _walk(node):
    """Yield node and all descendants in pre-order."""
    yield node
    for child in node.children:
        yield from _walk(child)


# A variable belongs to one method or named function (or to the file's top level): a name that is
# tainted in one method says nothing about the same name in another.  Closures and arrow functions
# share the scope of the code around them.
_SCOPE_TYPES = ('method_declaration', 'function_definition')


def _walk_scope(node):
    """`_walk`, but nested methods / named functions are scopes of their own and are skipped."""
    yield node
    for child in node.children:
        if child.type in _SCOPE_TYPES:
            continue
        yield from _walk_scope(child)


# HTML-escaping helpers shipped by common frameworks, called as functions (Laravel e(),
# CakePHP h(), WordPress esc_*) or as static / instance methods (Yii Html::encode,
# Zend/Laminas ->escapeHtml, Twig Escaper->escape, HTMLPurifier->purify).
_HTML_ESCAPE_FUNC_RE = re.compile(r'^(?:e|h|esc_\w+|escape\w*)$', re.IGNORECASE)
_HTML_ESCAPE_METHOD_RE = re.compile(
    r'^(?:html|e|h|escape\w*|esc\w*|encode|purify|sanitize\w*)$', re.IGNORECASE
)
_ESCAPER_CLASS_RE = re.compile(r'sanitiz|purif|escap|^html$|^h$', re.IGNORECASE)


def _is_sanitizer_call(node) -> bool:
    """True if node is a sanitizer function call."""
    if node.type == 'function_call_expression' and node.children:
        fname_node = node.children[0]
        if fname_node.type != 'name':
            return False
        fname = fname_node.text.decode('utf-8', errors='replace')
        return fname.lower() in _ALL_SANITIZERS or bool(_HTML_ESCAPE_FUNC_RE.match(fname))
    if node.type == 'scoped_call_expression' and len(node.children) >= 3:
        cls, meth = node.children[0], node.children[2]
        if cls.type in ('name', 'qualified_name') and meth.type == 'name':
            return bool(
                _ESCAPER_CLASS_RE.search(cls.text.decode('utf-8', errors='replace'))
                and _HTML_ESCAPE_METHOD_RE.match(meth.text.decode('utf-8', errors='replace'))
            )
    if node.type == 'member_call_expression':
        return bool(re.match(r'^(?:escape\w*|esc\w*|purify|sanitize\w*)$', _method_name(node), re.IGNORECASE))
    return False


def _is_existence_check(node) -> bool:
    """isset($x) / empty($x) test a value; they never write it to the output."""
    if node.type in ('isset_expression', 'empty_intrinsic'):
        return True
    if node.type == 'function_call_expression' and node.children:
        f = node.children[0]
        return f.type == 'name' and f.text.lower() in (b'isset', b'empty')
    return False


def _walk_output_refs(node):
    """Pre-order walk that does not descend into sanitizer calls or isset()/empty()."""
    if _is_sanitizer_call(node) or _is_existence_check(node):
        return
    yield node
    for child in node.children:
        yield from _walk_output_refs(child)


def _member_prop_name(node) -> str | None:
    """Return property name from a $obj->prop member access expression, or None."""
    if node.type != 'member_access_expression':
        return None
    for child in reversed(node.children):
        if child.type == 'name':
            return child.text.decode('utf-8', errors='replace')
    return None


def _member_obj_is_this(node) -> bool:
    """True if the member access expression object is $this."""
    if node.type != 'member_access_expression':
        return False
    obj = node.children[0] if node.children else None
    return obj is not None and obj.type == 'variable_name' and _var_name(obj) == 'this'


def _call_name(node) -> str:
    """Return the function name from a function_call_expression, or ''."""
    if node.type == 'function_call_expression' and node.children:
        first = node.children[0]
        if first.type == 'name':
            return first.text.decode('utf-8', errors='replace')
        # qualified name: PDO::query etc.
        if first.type in ('qualified_name', 'static_method_call_expression'):
            return first.text.decode('utf-8', errors='replace')
    return ''


def _call_args(node) -> list:
    """Return argument value nodes from a call's arguments."""
    args_nodes = [c for c in node.children if c.type == 'arguments']
    if not args_nodes:
        return []
    result = []
    for arg_node in args_nodes[0].children:
        if arg_node.type == 'argument':
            result.append(arg_node.children[0] if arg_node.children else arg_node)
        elif arg_node.type not in ('(', ')', ','):
            pass
    return result


def _method_name(node) -> str:
    """Return method name from a member_call_expression, or ''."""
    if node.type != 'member_call_expression':
        return ''
    for child in node.children:
        if child.type == 'name' and child.parent == node:
            return child.text.decode('utf-8', errors='replace')
    # fallback: find 'name' after '->'
    found_arrow = False
    for child in node.children:
        if child.type == '->':
            found_arrow = True
        elif found_arrow and child.type == 'name':
            return child.text.decode('utf-8', errors='replace')
    return ''


def _member_args(node) -> list:
    """Return argument value nodes from a member_call_expression's arguments."""
    args_nodes = [c for c in node.children if c.type == 'arguments']
    if not args_nodes:
        return []
    result = []
    for arg_node in args_nodes[0].children:
        if arg_node.type == 'argument':
            result.append(arg_node.children[0] if arg_node.children else arg_node)
    return result


# ── Taint propagation ─────────────────────────────────────────────────────────

def _is_tainted_node(node, tainted: dict, tainted_funcs: set,
                      tainted_props: "frozenset | set" = frozenset()) -> bool:
    """Return True if this AST node carries user-controlled data."""
    if node is None:
        return False

    t = node.type

    # Direct superglobal bare variable: $_{GET,POST,...}
    if t == 'variable_name':
        name = _var_name(node)
        if name is None or not (name in _SOURCES or name in tainted):
            return False
        return not _is_guarded(tainted, name, node)

    # Subscript: $_GET["key"] or $tainted["key"]
    if t == 'subscript_expression':
        if _FILES_SERVER_FIELD_RE.match(node.text.decode('utf-8', errors='replace')):
            return False
        if getattr(tainted, 'guards', None) and _is_guarded(tainted, _guard_key(node), node):
            return False
        obj = node.children[0] if node.children else None
        if obj and obj.type == 'variable_name':
            name = _var_name(obj)
            if name and (name in _SOURCES or name in tainted):
                return True
        elif obj is not None and obj.type in ('function_call_expression', 'member_call_expression',
                                               'scoped_call_expression', 'member_access_expression',
                                               'parenthesized_expression', 'subscript_expression'):
            # `json_decode($_POST['d'], true)['k']`, `explode(',', $_GET['x'])[0]`, `$request->all()['k']`
            return _is_tainted_node(obj, tainted, tainted_funcs, tainted_props)
        return False

    # String concatenation / null-coalescing
    if t == 'binary_expression':
        return any(
            _is_tainted_node(c, tainted, tainted_funcs, tainted_props)
            for c in node.children
            if c.type not in ('.', '??', '+', '-', '*', '/', '%', 'and', 'or',
                              'xor', '&&', '||', '==', '!=', '<', '>', '<=', '>=')
        )

    # Double-quoted string with interpolation: "Hello $name" or "SELECT...{$id}"
    if t == 'encapsed_string':
        for child in node.children:
            if child.type in ('variable_name', 'subscript_expression',
                               'member_access_expression', 'variable'):
                if _is_tainted_node(child, tainted, tainted_funcs, tainted_props):
                    return True
        return False

    # Parenthesized
    if t == 'parenthesized_expression':
        for child in node.named_children:
            if _is_tainted_node(child, tainted, tainted_funcs, tainted_props):
                return True
        return False

    # Function call returning tainted data
    if t == 'function_call_expression' and not _is_sanitizer_call(node):
        fname = _call_name(node)
        if fname in tainted_funcs:
            return True

    # Request object API: $request->input('k'), request('k'), Request::get('k')
    if t == 'member_call_expression':
        if _is_sanitizer_call(node) or _method_name(node) in _REQUEST_SAFE_METHODS:
            return False
        obj = node.children[0] if node.children else None
        return obj is not None and _is_tainted_node(obj, tainted, tainted_funcs, tainted_props)
    if t == 'function_call_expression':
        fname = _call_name(node)
        if fname == 'request':
            return True
        if fname in _PATH_HELPERS:
            return any(_is_tainted_node(a, tainted, tainted_funcs, tainted_props) for a in _call_args(node))
        plain = fname.lstrip('\\').lower()
        if plain in _PASSTHROUGH_FUNCS and not _is_sanitizer_call(node):
            args = _call_args(node)
            if plain in _FORMAT_FUNCS and _format_is_numeric_only(args):
                return False        # sprintf('%d', $x) is how a number is forced
            return any(_is_tainted_node(a, tainted, tainted_funcs, tainted_props) for a in args)
    if t == 'scoped_call_expression' and len(node.children) >= 3:
        cls, meth = node.children[0], node.children[2]
        return (cls.text.decode('utf-8', errors='replace').lstrip('\\').split('\\')[-1] == 'Request'
                and meth.text.decode('utf-8', errors='replace') not in _REQUEST_SAFE_METHODS)

    # Cast expression: (int)$x is clean; (string)$x propagates
    if t == 'cast_expression':
        for child in node.children:
            if child.type in ('integer_cast', 'float_cast', 'boolean_cast'):
                return False
            if child.type == 'cast_type' and child.text.decode('utf-8', errors='replace').lower() in (
                    'int', 'integer', 'float', 'double', 'real', 'bool', 'boolean'):
                return False
        for child in node.children:
            if _is_tainted_node(child, tainted, tainted_funcs, tainted_props):
                return True

    # $this->property taint: $this->userId flows from $_GET['id']
    if t == 'member_access_expression':
        if _member_obj_is_this(node):
            prop = _member_prop_name(node)
            return prop is not None and prop in tainted_props
        obj = node.children[0] if node.children else None
        return obj is not None and _is_tainted_node(obj, tainted, tainted_funcs, tainted_props)

    return False


def _format_is_numeric_only(args: list) -> bool:
    """`sprintf('%d', ...)`: the format is a literal and every conversion in it is numeric."""
    if not args or args[0].type not in ('string', 'encapsed_string'):
        return False
    specs = [s for s in _FORMAT_SPEC_RE.findall(args[0].text.decode('utf-8', errors='replace')) if s != '%']
    return bool(specs) and all(s in 'dDiuUfFeEgG' for s in specs)


# ── Validation guards ─────────────────────────────────────────────────────────
# `if (in_array($sort, ['id', 'name'], true)) { ...$sort... }` and
# `if (!is_numeric($id)) { abort(404); }  ...$id...` leave the variable holding a value the client
# could not choose freely.  A guard is a byte range in which a variable (or `$_GET['id']`) counts as
# clean.  The taint map itself stays flow-insensitive; ranges are consulted when a variable is read.

class _ScopeTaint(dict):
    """The taint map of one scope, with the byte ranges where guarded variables are clean."""

    guards: dict
    guard_signature: tuple | None

    def __init__(self) -> None:
        super().__init__()
        self.guards = {}
        self.guard_signature = None


_NUMERIC_GUARDS = frozenset({
    'is_numeric', 'ctype_digit', 'ctype_alnum', 'ctype_alpha', 'ctype_xdigit',
    'is_int', 'is_integer', 'is_float', 'is_bool',
})
_ABORT_IF = {'abort_if': False, 'throw_if': False, 'abort_unless': True, 'throw_unless': True}
_TERMINATOR_CALLS = frozenset({'die', 'exit', 'abort'})
# Inside [...]: escapes, same-kind ranges and single characters; a bare `-` only as the first or last
# character (anywhere else it would join two characters into a range such as 0-z).
_REGEX_CLASS_TOKEN = r"(?:\\[dw]|\\-|[a-z]-[a-z]|[A-Z]-[A-Z]|[0-9]-[0-9]|[A-Za-z0-9_])"
_REGEX_ITEM_RE = re.compile(
    r"(?:\\[dw]|\[-?" + _REGEX_CLASS_TOKEN + r"+-?\]|[A-Za-z0-9_])(?:[+*?]|\{\d+(?:,\d*)?\})?")


def _regex_pins_safe_chars(pattern: str) -> bool:
    """`/^[a-z0-9_-]+$/i`: the whole string is made of letters, digits, `_` and `-` (no quote,
    backslash, space, dot, or anything else an injection needs)."""
    if len(pattern) < 4:
        return False
    closing = {'(': ')', '{': '}', '[': ']', '<': '>'}.get(pattern[0], pattern[0])
    end = pattern.rfind(closing)
    if end <= 0:
        return False
    body, flags = pattern[1:end], pattern[end + 1:]
    if any(f in flags for f in 'mxe'):      # `m` lets ^ and $ match at any line; x / e change meaning
        return False
    if body.startswith('^'):
        core = body[1:]
    elif body.startswith('\\A'):
        core = body[2:]
    else:
        return False
    for tail in ('$', '\\z', '\\Z'):
        if core.endswith(tail):
            core = core[:-len(tail)]
            break
    else:
        return False
    pos = 0
    while pos < len(core):
        m = _REGEX_ITEM_RE.match(core, pos)
        if not m:
            return False
        pos = m.end()
    return pos > 0


def _guard_key(node) -> str | None:
    """Name a guarded subject: `$id` -> 'id', `$_GET['id']` -> "_GET['id']"; None for anything else."""
    if node is None:
        return None
    if node.type == 'variable_name':
        name = _var_name(node)
        return name if name and name != 'this' else None
    if node.type == 'subscript_expression' and len(node.children) >= 3:
        obj = node.children[0]
        index = next((c for c in node.children[1:] if c.type in ('string', 'integer', 'encapsed_string')), None)
        base = _var_name(obj) if obj.type == 'variable_name' else None
        if base and index is not None and index.type != 'encapsed_string':
            return f"{base}[{index.text.decode('utf-8', errors='replace')}]"
    return None


def _is_guarded(tainted, key: str | None, node) -> bool:
    guards = getattr(tainted, 'guards', None)
    if not guards or key is None or key not in guards:
        return False
    pos = node.start_byte
    return any(start <= pos < end for start, end in guards[key])


def _unwrap(node):
    while node is not None and node.type in ('parenthesized_expression', 'argument') and node.named_children:
        node = node.named_children[0]
    return node


def _server_side_value(node, tainted, funcs, props) -> bool:
    """The other side of `$v == <this>`: a literal, a constant, or something read off an object
    or call that is not client data.  A bare variable is not accepted: where it came from is unknown."""
    node = _unwrap(node)
    if node is None or node.type == 'variable_name':
        return False
    return not _is_tainted_node(node, tainted, funcs, props)


def _array_is_server_side(node, tainted, funcs, props, strict: bool) -> bool:
    node = _unwrap(node)
    if node is None or _is_tainted_node(node, tainted, funcs, props):
        return False
    if node.type == 'array_creation_expression' and not strict:
        # PHP's loose comparison makes "1abc" == 1: only string members are safe without `true`
        for el in _walk(node):
            if el.type in ('integer', 'float'):
                return False
    return True


def _guard_sets(expr, tainted, funcs, props) -> tuple[frozenset, frozenset]:
    """(subjects that are safe when `expr` is true, subjects that are safe when it is false)."""
    expr = _unwrap(expr)
    none: frozenset = frozenset()
    if expr is None:
        return none, none
    t = expr.type
    if t == 'unary_op_expression' and expr.children and expr.children[0].type == '!':
        inner_true, inner_false = _guard_sets(expr.children[-1], tainted, funcs, props)
        return inner_false, inner_true
    if t == 'binary_expression' and len(expr.children) == 3:
        left, op, right = expr.children
        op_t = op.type
        if op_t in ('&&', 'and', '||', 'or'):
            lt, lf = _guard_sets(left, tainted, funcs, props)
            rt, rf = _guard_sets(right, tainted, funcs, props)
            if op_t in ('&&', 'and'):
                return lt | rt, lf & rf
            return lt & rt, lf | rf
        if op_t in ('==', '===', '!=', '!=='):
            for subject, other in ((left, right), (right, left)):
                key = _guard_key(_unwrap(subject))
                if key and _server_side_value(other, tainted, funcs, props):
                    s = frozenset({key})
                    return (s, none) if op_t in ('==', '===') else (none, s)
        return none, none
    if t == 'function_call_expression':
        name = _call_name(expr).lstrip('\\').lower()
        args = [_unwrap(a) for a in _call_args(expr)]
        if name in _NUMERIC_GUARDS and args:
            key = _guard_key(args[0])
            return (frozenset({key}), none) if key else (none, none)
        if name == 'in_array' and len(args) >= 2:
            strict = len(args) >= 3 and args[2] is not None and args[2].text.decode('utf-8').lower() == 'true'
            key = _guard_key(args[0])
            if key and _array_is_server_side(args[1], tainted, funcs, props, strict):
                return frozenset({key}), none
        if name == 'array_key_exists' and len(args) >= 2:
            key = _guard_key(args[0])
            if key and _array_is_server_side(args[1], tainted, funcs, props, True):
                return frozenset({key}), none
        if name == 'preg_match' and len(args) >= 2 and args[0] is not None and args[0].type == 'string':
            key = _guard_key(args[1])
            # the raw text, not the string_content pieces: an escape such as \' splits the literal
            # and would otherwise vanish from the pattern we judge
            pattern = args[0].text.decode('utf-8', errors='replace')[1:-1]
            if key and _regex_pins_safe_chars(pattern):
                return frozenset({key}), none
    return none, none


def _block_terminates(block) -> bool:
    """The branch ends in return / throw / exit / die / abort / continue / break."""
    if block is None:
        return False
    stmts = block.named_children if block.type in ('compound_statement', 'colon_block') else [block]
    stmts = [s for s in stmts if s.type != 'comment']
    if not stmts:
        return False
    last = stmts[-1]
    if last.type in ('return_statement', 'exit_statement', 'continue_statement', 'break_statement'):
        return True
    if last.type == 'expression_statement' and last.named_children:
        inner = last.named_children[0]
        if inner.type == 'throw_expression':
            return True
        if inner.type == 'function_call_expression' and _call_name(inner).lstrip('\\').lower() in _TERMINATOR_CALLS:
            return True
    return False


def _enclosing_block_end(node) -> int:
    n = node.parent
    while n is not None and n.type not in ('compound_statement', 'colon_block', 'case_statement',
                                           'default_statement', 'declaration_list', 'program'):
        n = n.parent
    return n.end_byte if n is not None else node.end_byte


def _guard_candidates(scope_node) -> list:
    """The `if` statements and `abort_if()`-style calls of one scope: where a guard can start.
    Collected once; most scopes have none and then cost nothing afterwards."""
    found = []
    for node in _walk_scope(scope_node):
        if node.type == 'if_statement':
            found.append(node)
        elif node.type == 'expression_statement' and node.named_children:
            call = node.named_children[0]
            if (call.type == 'function_call_expression'
                    and _call_name(call).lstrip('\\').lower() in _ABORT_IF):
                found.append(node)
    return found


def _compute_guards(scope_node, candidates, tainted, funcs, props) -> dict:
    """{subject: [(start_byte, end_byte)]} where the subject is checked by the surrounding code."""
    ranges: dict[str, list[tuple[int, int]]] = {}

    def add(keys, start, end):
        for k in keys:
            ranges.setdefault(k, []).append((start, end))

    for node in candidates:
        if node.type == 'expression_statement' and node.named_children:
            call = node.named_children[0]
            if call.type == 'function_call_expression':
                name = _call_name(call).lstrip('\\').lower()
                args = _call_args(call)
                if name in _ABORT_IF and args:
                    when_true, when_false = _guard_sets(args[0], tainted, funcs, props)
                    # abort_if(C): the code after it runs when C is false; abort_unless(C): when C is true
                    add(when_true if _ABORT_IF[name] else when_false, node.end_byte, _enclosing_block_end(node))
            continue
        if node.type != 'if_statement':
            continue
        cond = next((c for c in node.named_children if c.type == 'parenthesized_expression'), None)
        if cond is None:
            continue
        clauses = [c for c in node.named_children if c.type in ('else_if_clause', 'else_clause')]
        then_body = next((c for c in node.named_children
                          if c is not cond and c.type not in ('else_if_clause', 'else_clause', 'comment')), None)
        when_true, when_false = _guard_sets(cond, tainted, funcs, props)
        if then_body is not None:
            add(when_true, then_body.start_byte, then_body.end_byte)
        not_taken = set(when_false)            # known once every earlier condition was false
        for clause in clauses:
            if clause.type == 'else_if_clause':
                c_cond = next((c for c in clause.named_children if c.type == 'parenthesized_expression'), None)
                c_body = next((c for c in clause.named_children
                               if c is not c_cond and c.type != 'comment'), None)
                if c_cond is not None and c_body is not None:
                    c_true, c_false = _guard_sets(c_cond, tainted, funcs, props)
                    add(set(c_true) | not_taken, c_body.start_byte, c_body.end_byte)
                    not_taken |= set(c_false)
            else:
                body = next((c for c in clause.named_children if c.type != 'comment'), None)
                if body is not None:
                    add(not_taken, body.start_byte, body.end_byte)
        if not clauses and _block_terminates(then_body):
            add(when_false, node.end_byte, _enclosing_block_end(node))
    if not ranges:
        return {}
    # a guard says nothing about a value that is overwritten inside its range
    assigned: dict[str, list[int]] = {}
    for node in _walk_scope(scope_node):
        if node.type == 'assignment_expression' and node.children:
            key = _guard_key(node.children[0])
            if key in ranges:
                assigned.setdefault(key, []).append(node.start_byte)
    for key, spans in list(ranges.items()):
        later = assigned.get(key, ())
        ranges[key] = [(s, e) for s, e in spans if not any(s <= p < e for p in later)]
    return {k: v for k, v in ranges.items() if v}


def _taint_source_desc(node) -> str:
    """Return a short human-readable description of where taint originates."""
    text = node.text.decode('utf-8', errors='replace')[:60]
    return text


_SCALAR_TYPES = frozenset({'int', 'float', 'bool'})


def _typed_scalar_props(root) -> frozenset:
    """Properties declared `int` / `float` / `bool` (also promoted constructor parameters): PHP coerces
    or rejects whatever is assigned, so a request value stored there cannot carry SQL or markup."""
    names: set[str] = set()
    for n in _walk(root):
        if n.type not in ('property_declaration', 'property_promotion_parameter'):
            continue
        if not any(c.type == 'primitive_type' and c.text.decode() in _SCALAR_TYPES
                   or c.type == 'optional_type' and any(g.type == 'primitive_type' and g.text.decode() in _SCALAR_TYPES
                                                        for g in c.children)
                   for c in n.children):
            continue
        for c in n.children:
            if c.type == 'property_element':
                v = _var_name(c.children[0]) if c.children else None
                if v:
                    names.add(v)
            elif c.type == 'variable_name':
                v = _var_name(c)
                if v:
                    names.add(v)
    return frozenset(names)


def _enclosing_function_text(node) -> str:
    """Text of the outermost method / function around *node* (a closure's output belongs to its method)."""
    found = None
    n = node.parent
    while n is not None:
        if n.type in ('method_declaration', 'function_definition', 'anonymous_function', 'arrow_function'):
            found = n
        n = n.parent
    return found.text.decode('utf-8', errors='replace') if found is not None else ''


_NON_HTML_RESPONSE_RE = re.compile(
    r"application/pdf|application/octet-stream|text/csv|text/plain|application/json|streamDownload|image/(?:png|jpe?g|gif|webp)",
    re.IGNORECASE)


def _is_uploaded_file_var(arg, node) -> bool:
    """`$file = $request->file('x'); file_get_contents($file)`: the UploadedFile object stands for the
    server-side temporary file, not for a path the client chose."""
    if arg is None or arg.type != 'variable_name':
        return False
    name = _var_name(arg)
    if not name:
        return False
    rx = re.compile(r"[$]" + re.escape(name) + r"\s*=\s*[$]\w+->file\(")
    return bool(rx.search(_enclosing_function_text(node)))


def _collect_pass(root, tainted: dict, tainted_funcs: set, tainted_props: set,
                  clean_props: frozenset = frozenset(), walker=_walk) -> bool:
    """Walk all assignments and function defs; update taint. Returns True if changed."""
    changed = False
    for node in walker(root):
        # ── Simple assignment: $var = expr ────────────────────────────────────
        if node.type in ('assignment_expression', 'augmented_assignment_expression'):
            children = node.children
            # find the assignment operator (= or .= or compound)
            eq_idx = next(
                (i for i, c in enumerate(children)
                 if c.type in ('=', '.=')), None
            )
            if eq_idx is None or eq_idx == 0 or eq_idx + 1 >= len(children):
                continue
            lhs = children[eq_idx - 1]
            rhs = children[eq_idx + 1]
            compound = children[eq_idx].type == '.='

            # $this->prop = tainted — class property taint
            if lhs.type == 'member_access_expression' and _member_obj_is_this(lhs):
                prop = _member_prop_name(lhs)
                if prop and prop not in tainted_props and prop not in clean_props:
                    if _is_tainted_node(rhs, tainted, tainted_funcs, tainted_props):
                        tainted_props.add(prop)
                        changed = True
                continue

            if lhs.type != 'variable_name':
                continue
            var = _var_name(lhs)
            if not var or var in _SOURCES:
                continue
            line = lhs.start_point[0] + 1

            if _is_sanitizer_call(rhs) and not compound:
                # sanitizer clears taint (only for simple =)
                if var in tainted:
                    tainted.pop(var)
                    changed = True
            elif _is_tainted_node(rhs, tainted, tainted_funcs, tainted_props):
                # compound .= preserves existing taint; simple = replaces
                if var not in tainted:
                    tainted[var] = (line, _taint_source_desc(rhs))
                    changed = True
            elif not compound:
                # clean assignment clears taint
                if var in tainted:
                    tainted.pop(var)
                    changed = True

        # ── Function definition: check if body returns tainted value ──────────
        elif node.type == 'function_definition':
            name_nodes = [c for c in node.children if c.type == 'name']
            if not name_nodes:
                continue
            fname = name_nodes[0].text.decode('utf-8', errors='replace')
            if fname in tainted_funcs:
                continue
            body_nodes = [c for c in node.children if c.type == 'compound_statement']
            if not body_nodes:
                continue
            for sub in _walk(body_nodes[0]):
                if sub.type == 'return_statement':
                    for child in sub.children:
                        if child.type not in ('return', ';') and _is_tainted_node(
                                child, tainted, tainted_funcs, tainted_props):
                            tainted_funcs.add(fname)
                            changed = True
                            break

    return changed


def _build_php_func_param_map(root) -> dict[str, list[str]]:
    """Build {func_name: [param_var_names (no $)]} for all function defs."""
    result: dict[str, list[str]] = {}
    for node in _walk(root):
        if node.type != 'function_definition':
            continue
        name_nodes = [c for c in node.children if c.type == 'name']
        if not name_nodes:
            continue
        fname = name_nodes[0].text.decode('utf-8', errors='replace')
        formal = next((c for c in node.children if c.type == 'formal_parameters'), None)
        params: list[str] = []
        if formal:
            for child in formal.named_children:
                # simple_parameter, variadic_parameter, property_promotion_parameter
                var_node = next(
                    (c for c in child.children if c.type == 'variable_name'), None
                )
                if var_node:
                    vname = _var_name(var_node)
                    if vname:
                        params.append(vname)
        result[fname] = params
    return result


def _collect_php_call_site_taint(
    root,
    tainted: dict,
    tainted_funcs: set,
    tainted_props: set,
    func_param_map: dict[str, list[str]],
) -> bool:
    """Seed callee param vars when a call site passes a tainted argument.

    When `vulnerable_func($tainted_var)` is found and `vulnerable_func` is
    defined locally, add the corresponding parameter variable to `tainted`.
    """
    changed = False
    for node in _walk(root):
        if node.type != 'function_call_expression':
            continue
        fname = _call_name(node)
        if not fname or fname not in func_param_map:
            continue
        param_names = func_param_map[fname]
        if not param_names:
            continue
        args_node = next(
            (c for c in node.children if c.type == 'arguments'), None
        )
        if args_node is None:
            continue
        # Each child may be an `argument` wrapper or a direct expression
        raw_args = [c for c in args_node.named_children
                    if c.type not in ('(', ')', ',')]
        args = []
        for c in raw_args:
            if c.type == 'argument':
                # unwrap: first named child is the actual expression
                expr = c.named_children[0] if c.named_children else c
                args.append(expr)
            else:
                args.append(c)
        for i, arg in enumerate(args):
            if i >= len(param_names):
                break
            if _is_tainted_node(arg, tainted, tainted_funcs, tainted_props):
                pname = param_names[i]
                if pname not in tainted:
                    line = arg.start_point[0] + 1
                    tainted[pname] = (line, f"arg #{i} of {fname}()")
                    changed = True
    return changed


def _seed_request_params(root, tainted: dict, walker=_walk) -> None:
    """`Request $request` / `FormRequest $r` parameters hold the client's request."""
    for n in walker(root):
        if n.type != 'simple_parameter':
            continue
        type_node = n.child_by_field_name('type')
        if type_node is None:
            continue
        type_name = type_node.text.decode('utf-8', errors='replace').lstrip('?\\').split('\\')[-1]
        if not type_name.endswith('Request'):
            continue
        name_node = n.child_by_field_name('name')
        var = _var_name(name_node) if name_node is not None else None
        if var:
            tainted.setdefault(var, (n.start_point[0] + 1, 'request object parameter'))


def _build_taint(
    root,
    seed_funcs: "frozenset[str] | None" = None,
) -> tuple[dict, set, set]:
    """Fixed-point taint propagation, max 8 passes.

    seed_funcs: pre-known tainted function names from cross-file analysis.
    Includes interprocedural caller→callee param seeding.
    """
    scopes, tainted_funcs, tainted_props = _build_taint_scoped(root, seed_funcs)
    tainted: dict[str, tuple[int, str]] = {}
    for _node, scope_taint in scopes:      # flat view for callers that only need the function names
        for var, entry in scope_taint.items():
            tainted.setdefault(var, entry)
    return tainted, tainted_funcs, tainted_props


def _php_params(node) -> list[str]:
    """Parameter variable names (no $) of a method or function, in order."""
    formal = next((c for c in node.children if c.type == 'formal_parameters'), None)
    names: list[str] = []
    if formal is not None:
        for child in formal.named_children:
            var_node = next((c for c in child.children if c.type == 'variable_name'), None)
            names.append((_var_name(var_node) if var_node is not None else None) or '')
    return names


def _php_scope_name(node) -> str:
    name = next((c for c in node.children if c.type == 'name'), None)
    return name.text.decode('utf-8', errors='replace') if name is not None else ''


def _php_global_names(node) -> set[str]:
    """`global $a, $b;` inside a function: those names are the file's top-level variables."""
    names: set[str] = set()
    for n in _walk_scope(node):
        if n.type == 'global_declaration':
            names.update(v for v in (_var_name(c) for c in n.children if c.type == 'variable_name') if v)
    return names


def _callee_key(node) -> tuple[str, str] | None:
    """('f', name) for `name(...)`, ('m', name) for `$this->name(...)` / `self::name(...)` /
    `static::name(...)`; None for calls on objects whose class is unknown."""
    if node.type == 'function_call_expression':
        name = _call_name(node)
        return ('f', name) if name else None
    if node.type == 'member_call_expression':
        obj = node.children[0] if node.children else None
        if obj is not None and obj.type == 'variable_name' and _var_name(obj) == 'this':
            name = _method_name(node)
            return ('m', name) if name else None
        return None
    if node.type == 'scoped_call_expression' and len(node.children) >= 3:
        cls, meth = node.children[0], node.children[2]
        if (cls.type == 'relative_scope' and cls.text.decode('utf-8', errors='replace') in ('self', 'static')
                and meth.type == 'name'):
            return ('m', meth.text.decode('utf-8', errors='replace'))
    return None


def _seed_callee_params(scopes, callees, tainted_funcs, tainted_props) -> bool:
    """A call that passes a tainted argument taints the matching parameter of the callee's own scope
    (functions by name, methods through `$this` / `self` / `static`)."""
    changed = False
    for node_s, taint in scopes:
        for node in _walk_scope(node_s):
            key = _callee_key(node)
            if key is None or key not in callees:
                continue
            args = _call_args(node)
            for i, arg in enumerate(args):
                if not _is_tainted_node(arg, taint, tainted_funcs, tainted_props):
                    continue
                for params, callee_taint in callees[key]:
                    if i < len(params) and params[i] and params[i] not in callee_taint:
                        callee_taint[params[i]] = (arg.start_point[0] + 1, f"arg #{i} of {key[1]}()")
                        changed = True
    return changed


def _build_taint_scoped(root, seed_funcs: "frozenset[str] | None" = None) -> tuple[list, set, set]:
    """Fixed-point taint propagation with one taint map per method / named function.

    Returns ([(scope_node, {var: (line, source)})], tainted_funcs, tainted_props).  The first scope is
    the file's top level.  Function names that return tainted data and `$this->prop` taint are
    shared by the whole file; variables are not.
    """
    nodes = [root] + [n for n in _walk(root) if n.type in _SCOPE_TYPES]
    scopes: list[tuple] = []
    callees: dict[tuple[str, str], list] = {}
    for n in nodes:
        taint = _ScopeTaint()
        _seed_request_params(n, taint, _walk_scope)
        scopes.append((n, taint))
        if n.type in _SCOPE_TYPES:
            kind = 'f' if n.type == 'function_definition' else 'm'
            name = _php_scope_name(n)
            if name:
                callees.setdefault((kind, name), []).append((_php_params(n), taint))
    tainted_funcs: set[str] = set(seed_funcs or ())
    tainted_props: set[str] = set()
    clean_props = _typed_scalar_props(root)
    module_taint = scopes[0][1]
    globals_of = [_php_global_names(n) if n.type in _SCOPE_TYPES else set() for n, _ in scopes]
    candidates = [_guard_candidates(n) for n, _ in scopes]

    def refresh_guards(i: int) -> None:
        """Guards depend on the map (is the other side of `==` client data?): redo them only when it moved."""
        n, taint = scopes[i]
        signature = (len(taint), len(tainted_funcs), len(tainted_props))
        if candidates[i] and taint.guard_signature != signature:
            taint.guards = _compute_guards(n, candidates[i], taint, tainted_funcs, tainted_props)
            taint.guard_signature = signature

    for _ in range(8):
        changed = False
        for i, ((n, taint), declared) in enumerate(zip(scopes, globals_of)):
            for var in declared:
                if var in module_taint and var not in taint:
                    taint[var] = module_taint[var]
                    changed = True
            refresh_guards(i)
            if _collect_pass(n, taint, tainted_funcs, tainted_props, clean_props, _walk_scope):
                changed = True
        if _seed_callee_params(scopes, callees, tainted_funcs, tainted_props):
            changed = True
        if not changed:
            break
    for i in range(len(scopes)):                # the sinks are judged against the final map
        refresh_guards(i)
    return scopes, tainted_funcs, tainted_props


# ── Emit helper ───────────────────────────────────────────────────────────────

def _emit(
    findings: list,
    seen: set,
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
    content = lines[line - 1].strip() if 0 < line <= len(lines) else ''
    findings.append(Finding(
        vuln_type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_number=line,
        line_content=content,
        description=desc,
        rule_id=rule_id,
        repo_url=repo_url,
        snippet='\n'.join(lines[max(0, line - 3): min(len(lines), line + 2)]),
    ))


def _scoped_parts(node) -> tuple[str, str]:
    """(class, method) of `Cls::method(...)`, class without namespace."""
    cls = node.children[0].text.decode('utf-8', errors='replace').lstrip('\\').split('\\')[-1]
    return cls, node.children[2].text.decode('utf-8', errors='replace')


def _is_call_to(node, name: str) -> bool:
    """`name(...)` as a plain function call, e.g. the receiver in `redirect()->to(...)`."""
    return node is not None and node.type == 'function_call_expression' and _call_name(node) == name


_INTERNAL_URL_BUILDERS: frozenset[str] = frozenset({'route', 'action', 'to_route'})


def _is_internal_redirect_target(node) -> bool:
    """`route('x') . $suffix`, `"/path/{$id}"`: the host part is fixed by the application."""
    while node is not None and node.type == 'parenthesized_expression' and node.named_children:
        node = node.named_children[0]
    if node is None:
        return False
    if node.type == 'binary_expression' and node.children:
        return _is_internal_redirect_target(node.children[0])
    if node.type == 'function_call_expression':
        return _call_name(node) in _INTERNAL_URL_BUILDERS
    if node.type in ('encapsed_string', 'string'):
        text = node.text.decode('utf-8', errors='replace')
        if re.match(r'''["']https?://[^/$"'{]+[/?]''', text):
            return True     # literal scheme://host/ prefix: only the path/query is variable
        return len(text) > 2 and text[1] == '/' and text[2:3] not in ('/', '\\')
    return False


def _url_host_is_fixed(node, url) -> bool:
    """The URL starts with a literal `https://host/` (directly, or in every assignment of the
    variable inside the enclosing function): request data can only fill the path / query, so this
    is not SSRF."""
    if _is_internal_redirect_target(url):
        return True
    if url.type != 'variable_name':
        return False
    name = url.text.decode('utf-8', errors='replace')
    # A `case` / `default` arm is its own flow: assignments in sibling arms do not reach this call.
    fn = node.parent
    while fn is not None and fn.type not in ('case_statement', 'default_statement', 'method_declaration',
                                              'function_definition', 'anonymous_function', 'arrow_function'):
        fn = fn.parent
    if fn is None:
        return False
    rhs: list = []
    stack = [fn]
    while stack:
        cur = stack.pop()
        if cur.type == 'assignment_expression' and cur.children and \
                cur.children[0].text.decode('utf-8', errors='replace') == name:
            rhs.append(cur.children[-1])
        stack.extend(cur.children)
    return bool(rhs) and all(_is_internal_redirect_target(r) for r in rhs)


def _has_origin_check(node) -> bool:
    """The enclosing function compares the target's host (parse_url(...)['host']) before redirecting."""
    fn = node.parent
    while fn is not None and fn.type not in ('method_declaration', 'function_definition',
                                              'anonymous_function', 'arrow_function'):
        fn = fn.parent
    if fn is None:
        return False
    text = fn.text.decode('utf-8', errors='replace')
    return 'parse_url(' in text and ("'host'" in text or '"host"' in text or 'PHP_URL_HOST' in text)


def _redirect_is_safe(node, target) -> bool:
    return _is_internal_redirect_target(target) or _has_origin_check(node)


def _emit_mass_assignment(findings, seen, file_path, line, lines, repo_url, call, cls) -> None:
    """Mass assignment needs a model that accepts every attribute (`$guarded = []`): Eloquent drops
    attributes outside `$fillable`, so a whole-request create()/fill() on a guarded model is fine."""
    ctx = _get_php_cf_ctx()
    unguarded = ctx.unguarded_models if ctx else frozenset()
    if not unguarded:
        return
    if cls is not None and cls in unguarded:
        sev, note = Severity.MEDIUM, f"{cls} declares $guarded = []"
    else:
        sev = Severity.LOW
        note = "model type not resolved; unguarded models here: " + ", ".join(sorted(unguarded)[:4])
    _emit(findings, seen, file_path, line, lines, repo_url,
          VulnType.TRUST_BOUNDARY_VIOLATION, sev, 'PHAST-MASS-001',
          f"[needs_review] whole request body passed to {call} — mass assignment ({note}); "
          "use validated()/only()")


def _is_whole_request(node, taint) -> bool:
    """`$request->all()` / `->input()` without a key or whitelist: every field the client sent."""
    return (node is not None and node.type == 'member_call_expression'
            and _method_name(node) in ('all', 'input', 'post', 'query', 'json', 'toArray')
            and not _member_args(node) and taint(node.children[0]))


# ── Sink checker ─────────────────────────────────────────────────────────────

def _output_buffer_name(lhs) -> str | None:
    """`$html` / `$page['body']` when the target conventionally accumulates output markup."""
    if lhs.type == 'variable_name':
        name = _var_name(lhs) or ''
        return name if _OUTPUT_BUFFER_NAME_RE.match(name) else None
    if lhs.type == 'subscript_expression' and lhs.children and lhs.children[0].type == 'variable_name':
        key = next((c for c in lhs.children if c.type == 'encapsed_string' or c.type == 'string'), None)
        text = key.text.decode('utf-8', errors='replace').strip("'\"") if key is not None else ''
        if _OUTPUT_BUFFER_NAME_RE.match(text):
            return f"{_var_name(lhs.children[0])}['{text}']"
    return None


def _check_sinks(root, tainted, tainted_funcs, tainted_props, file_path, lines, repo_url,
                 walker=_walk) -> list:
    findings: list[Finding] = []
    seen: set = set()
    buffer_assigns: list = []

    def raw_taint(n):
        return _is_tainted_node(n, tainted, tainted_funcs, tainted_props)

    def taint(n):
        # The request object itself (`foo($request)`) is not client data; its accessors are.
        if n is not None and n.type == 'variable_name':
            entry = tainted.get(_var_name(n) or '')
            if entry is not None and entry[1] == 'request object parameter':
                return False
        return _is_tainted_node(n, tainted, tainted_funcs, tainted_props)

    for node in walker(root):
        # ── Function call sinks ───────────────────────────────────────────────
        if node.type == 'function_call_expression':
            fname = _call_name(node)
            if not fname:
                continue
            args = _call_args(node)
            line = node.start_point[0] + 1

            # SQL injection
            if fname in _SQL_FUNC_SINKS_ARG1 and len(args) >= 2 and taint(args[1]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH, 'PHAST-SQL-001',
                      f"User-controlled data flows into {fname}() — SQL injection risk")

            elif fname in _SQL_FUNC_SINKS and fname not in _SQL_FUNC_SINKS_ARG1 \
                    and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH, 'PHAST-SQL-001',
                      f"User-controlled data flows into {fname}() — SQL injection risk")

            # Command injection
            elif fname in _CMD_FUNC_SINKS and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.COMMAND_INJECTION, Severity.CRITICAL, 'PHAST-CMD-001',
                      f"User-controlled data flows into {fname}() — OS command injection risk")

            # Path traversal (also catches SSRF for URL schemeable paths)
            elif fname in _PATH_FUNC_SINKS and args and taint(args[0]) and not _is_uploaded_file_var(args[0], node):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH, 'PHAST-PATH-001',
                      f"User-controlled path flows into {fname}() — path traversal risk")
                if (fname in _URL_READ_FUNCS
                        and _URL_NAME_RE.search(args[0].text.decode('utf-8', errors='replace'))
                        and not _url_host_is_fixed(node, args[0])):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.SSRF, Severity.HIGH, 'PHAST-SSRF-001',
                          f"User-controlled URL flows into {fname}() — SSRF risk")

            # SSRF: curl_setopt($ch, CURLOPT_URL, $url)
            elif fname == 'curl_setopt' and len(args) >= 3:
                const_node = args[1]
                const_text = const_node.text.decode('utf-8', errors='replace') \
                    if const_node else ''
                if (const_text in _CURL_URL_CONSTS and taint(args[2])
                        and not _url_host_is_fixed(node, args[2])):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.SSRF, Severity.HIGH, 'PHAST-SSRF-001',
                          "User-controlled URL in curl_setopt(CURLOPT_URL) — SSRF risk")

            # Open redirect: header("Location: " . $url)
            elif fname == 'header' and args:
                arg0 = args[0]
                arg_text = arg0.text.decode('utf-8', errors='replace').lower()
                if 'location:' in arg_text and taint(arg0):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.OPEN_REDIRECT, Severity.MEDIUM, 'PHAST-REDIR-001',
                          "User-controlled value in Location header — open redirect risk")

            # Deserialization: unserialize(tainted) — CRITICAL gadget chain risk
            elif fname == 'unserialize' and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL, 'PHAST-DESER-001',
                      "User-controlled data flows into unserialize() — object injection / RCE risk")

            # LDAP injection: ldap_search($conn, $base, $filter) — arg[2] is the filter
            elif fname == 'ldap_search' and len(args) >= 3 and taint(args[2]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.LDAP_INJECTION, Severity.HIGH, 'PHAST-LDAP-001',
                      "User-controlled data flows into ldap_search() filter — LDAP injection risk")

            # Log injection: error_log(tainted) — newlines in log can forge entries
            elif fname == 'error_log' and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.LOG_INJECTION, Severity.LOW, 'PHAST-LOG-001',
                      "User-controlled data flows into error_log() — log injection risk")

            # Code injection: eval(tainted) — arbitrary PHP execution
            elif fname == 'eval' and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSTI, Severity.CRITICAL, 'PHAST-EVAL-001',
                      "User-controlled data flows into eval() — arbitrary PHP code execution")

            # Code injection: assert(tainted) — PHP < 8.0 evaluates string args as code
            elif fname == 'assert' and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSTI, Severity.CRITICAL, 'PHAST-EVAL-002',
                      "User-controlled data flows into assert() — arbitrary PHP code execution (PHP < 8.0)")

            # SSTI: Smarty->fetch(tainted), Smarty->display(tainted)
            elif fname in ('smarty_fetch', 'fetch', 'display') and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSTI, Severity.HIGH, 'PHAST-SSTI-001',
                      f"User-controlled data flows into {fname}() — template injection risk")

            # ReDoS: user-controlled regex pattern in preg_* functions
            elif fname in ('preg_match', 'preg_match_all', 'preg_replace',
                           'preg_split', 'preg_replace_callback') \
                    and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.REDOS, Severity.HIGH, 'PHAST-REDOS-001',
                      f"User-controlled regex pattern in {fname}() — ReDoS / regex injection risk")

            # XXE: simplexml_load_string / simplexml_load_file with tainted XML
            elif fname in ('simplexml_load_string', 'simplexml_load_file') \
                    and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.XXE, Severity.HIGH, 'PHAST-XXE-001',
                      f"User-controlled XML input to {fname}() — XXE if external entities not disabled")

            # Laravel: redirect($request->input('next')) — open redirect
            elif fname == 'redirect' and args and taint(args[0]) and not _redirect_is_safe(node, args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.OPEN_REDIRECT, Severity.MEDIUM, 'PHAST-REDIR-001',
                      "User-controlled value flows into redirect() — open redirect risk")

            # Laravel: response($html) with client data — reflected XSS when served as text/html
            elif fname == 'response' and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.XSS, Severity.MEDIUM, 'PHAST-XSS-001',
                      "User-controlled data flows into response() body — reflected XSS if served as HTML")

            # XSS: print_r($var, false) — only if output goes to browser
            # Covered by echo_statement below; skip here to avoid FPs

        # ── Method call sinks: $pdo->query($sql) ─────────────────────────────
        elif node.type == 'member_call_expression':
            mname = _method_name(node)
            if not mname:
                continue
            args = _member_args(node)
            line = node.start_point[0] + 1

            if mname in _SQL_METHOD_SINKS:
                # `$stmt->execute($params)` binds values and `$cache->execute($action)` is an
                # application method: only a database-looking receiver makes execute() a SQL sink.
                if mname == 'execute' and not _DB_RECEIVER_RE.search(
                        node.children[0].text.decode('utf-8', errors='replace')):
                    continue
                if args and taint(args[0]):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.SQL_INJECTION, Severity.HIGH, 'PHAST-SQL-001',
                          f"User-controlled data flows into ->{mname}() — SQL injection risk")

            # SSTI: $twig->createTemplate($userInput) — Twig evaluates template string
            elif (mname == 'createTemplate' and args and taint(args[0])
                  and re.search(r'twig|environment|(?<![a-z])env(?![a-z])',
                                node.children[0].text.decode('utf-8', errors='replace'), re.I)):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSTI, Severity.CRITICAL, 'PHAST-SSTI-001',
                      "User-controlled data flows into ->createTemplate() — Twig SSTI risk")

            # Smarty method: $smarty->fetch($tainted), $smarty->display($tainted)
            elif mname in ('fetch', 'display') and args and taint(args[0]) \
                    and re.search(r'smarty|tpl|templ', node.children[0].text.decode('utf-8', errors='replace'), re.I):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSTI, Severity.HIGH, 'PHAST-SSTI-001',
                      f"User-controlled data flows into ->{mname}() — Smarty template injection risk")

            # XXE: $dom->loadXML($tainted) / $dom->load($tainted)
            elif (mname in ('loadXML', 'load', 'loadHTML') and args and taint(args[0])
                  and (mname == 'loadXML'
                       or re.search(r'dom|xml|doc|reader|html',
                                    node.children[0].text.decode('utf-8', errors='replace'), re.I))):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.XXE, Severity.HIGH, 'PHAST-XXE-001',
                      f"User-controlled XML in ->{mname}() — XXE risk if external entities not disabled")

            # Laravel query builder: ->whereRaw("... " . $request->input('q'))
            elif mname in _SQL_RAW_METHODS and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH, 'PHAST-SQL-001',
                      f"User-controlled data flows into ->{mname}() — SQL injection risk; bind it with ? placeholders")

            # Laravel mass assignment: $model->update($request->all())
            elif mname in _MASS_ASSIGN_METHODS and args and _is_whole_request(args[0], raw_taint):
                _emit_mass_assignment(findings, seen, file_path, line, lines, repo_url,
                                      f"->{mname}()", None)

            # Laravel: response()->download($request->input('f')) — arbitrary file read
            elif mname in ('download', 'file') and _is_call_to(node.children[0], 'response')                     and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH, 'PHAST-PATH-001',
                      f"User-controlled path flows into response()->{mname}() — path traversal risk")

            # Laravel: redirect()->to($url) / ->away($url)
            elif mname in ('to', 'away') and _is_call_to(node.children[0], 'redirect')                     and args and taint(args[0]) and not _redirect_is_safe(node, args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.OPEN_REDIRECT, Severity.MEDIUM, 'PHAST-REDIR-001',
                      f"User-controlled value flows into redirect()->{mname}() — open redirect risk")

            # Laravel Filesystem: $this->filesystem->size($request->get('fileName')) — arbitrary path
            elif (mname in _FILESYSTEM_METHODS and args and taint(args[0])
                  and _FILESYSTEM_RECEIVER_RE.search(node.children[0].text.decode('utf-8', errors='replace').split('->')[-1])):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH, 'PHAST-PATH-001',
                      f"User-controlled path flows into Filesystem->{mname}() — path traversal / phar:// "
                      "object injection risk")

        # ── Static / facade calls: DB::select($sql), Http::get($url) ─────────
        elif node.type == 'scoped_call_expression' and len(node.children) >= 3:
            cls, mname = _scoped_parts(node)
            args = _member_args(node)
            line = node.start_point[0] + 1
            if not args:
                continue
            if cls == 'DB' and mname in _DB_FACADE_SQL_METHODS and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH, 'PHAST-SQL-001',
                      f"User-controlled data flows into DB::{mname}() — SQL injection risk; bind it with ? placeholders")
            elif mname in _SQL_RAW_METHODS and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH, 'PHAST-SQL-001',
                      f"User-controlled data flows into {cls}::{mname}() — SQL injection risk; bind it with ? placeholders")
            elif mname in _MASS_ASSIGN_METHODS and _is_whole_request(args[0], raw_taint):
                _emit_mass_assignment(findings, seen, file_path, line, lines, repo_url,
                                      f"{cls}::{mname}()", cls)
            elif (cls == 'Http' and mname in _HTTP_FACADE_METHODS and taint(args[0])
                  and not _url_host_is_fixed(node, args[0])):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSRF, Severity.HIGH, 'PHAST-SSRF-001',
                      f"User-controlled URL flows into Http::{mname}() — SSRF risk")
            elif cls == 'Redirect' and mname in ('to', 'away') and taint(args[0]) \
                    and not _redirect_is_safe(node, args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.OPEN_REDIRECT, Severity.MEDIUM, 'PHAST-REDIR-001',
                      f"User-controlled value flows into Redirect::{mname}() — open redirect risk")
            elif cls == 'File' and mname in _FILESYSTEM_METHODS and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH, 'PHAST-PATH-001',
                      f"User-controlled path flows into File::{mname}() — path traversal / phar:// "
                      "object injection risk")
            elif cls == 'Response' and mname in ('download', 'file') and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH, 'PHAST-PATH-001',
                      f"User-controlled path flows into Response::{mname}() — path traversal risk")

        # ── Echo / print sinks ────────────────────────────────────────────────
        elif node.type in ('echo_statement', 'print_intrinsic'):
            line = node.start_point[0] + 1
            if _NON_HTML_RESPONSE_RE.search(_enclosing_function_text(node)):
                continue  # the output is a PDF / CSV / image / JSON body, not an HTML page
            for child in node.children:
                if child.type in ('echo', 'print', ';', ','):
                    continue
                # Walk the argument to find tainted references not inside sanitizers
                for sub in _walk_output_refs(child):
                    if sub.type == 'variable_name':
                        vname = _var_name(sub)
                        if vname and vname in tainted:
                            _emit(findings, seen, file_path, line, lines, repo_url,
                                  VulnType.XSS, Severity.HIGH, 'PHAST-XSS-001',
                                  f"${vname} carries user-controlled input and is echoed "
                                  f"without HTML encoding — use htmlspecialchars()")
                            break
                    elif sub.type == 'subscript_expression':
                        obj = sub.children[0] if sub.children else None
                        if obj and obj.type == 'variable_name':
                            oname = _var_name(obj)
                            if oname and oname in _SOURCES:
                                _emit(findings, seen, file_path, line, lines, repo_url,
                                      VulnType.XSS, Severity.HIGH, 'PHAST-XSS-001',
                                      "Superglobal echoed without HTML encoding — "
                                      "use htmlspecialchars()")
                                break

        # ── HTML output buffer: $html .= '<p>' . $_GET['x'] . '</p>' (echoed elsewhere) ──
        elif node.type in ('assignment_expression', 'augmented_assignment_expression'):
            ch = node.children
            buf = _output_buffer_name(ch[0]) if len(ch) >= 3 and ch[1].type in ('=', '.=') else None
            if (buf and len(ch) >= 3
                    and _HTML_TAG_RE.search(ch[2].text.decode('utf-8', errors='replace'))
                    and not _is_sanitizer_call(ch[2]) and taint(ch[2])):
                buffer_assigns.append((buf, node.start_point[0] + 1))

        # ── include / require sinks ───────────────────────────────────────────
        elif node.type in ('include_expression', 'include_once_expression',
                            'require_expression', 'require_once_expression'):
            line = node.start_point[0] + 1
            for child in node.children:
                if child.type in ('include', 'include_once', 'require', 'require_once'):
                    continue
                if taint(child):
                    kw = node.children[0].text.decode() if node.children else 'include'
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.PATH_TRAVERSAL, Severity.CRITICAL, 'PHAST-PATH-001',
                          f"User-controlled path in {kw}() — remote/local file inclusion risk")

        # ── Backtick shell execution: `ls $cmd` ───────────────────────────────
        elif node.type == 'shell_command_expression':
            line = node.start_point[0] + 1
            for child in node.children:
                if taint(child):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.COMMAND_INJECTION, Severity.CRITICAL, 'PHAST-CMD-002',
                          "User-controlled data in backtick shell execution — OS command injection risk")
                    break

    # A buffer that this file already echoes is reported by the echo sink (HIGH); the rest are
    # built here and output elsewhere (view file reached through include/require): MEDIUM.
    for vname, line in buffer_assigns:
        if any(f.rule_id == 'PHAST-XSS-001' and f.description.startswith(f'${vname} ') for f in findings):
            continue
        _emit(findings, seen, file_path, line, lines, repo_url,
              VulnType.XSS, Severity.MEDIUM, 'PHAST-XSS-002',
              f"${vname} is built as HTML from user-controlled input without encoding; it is output "
              "elsewhere (include/return) — use htmlspecialchars()")

    return findings


# ── Analyzer class ────────────────────────────────────────────────────────────

# ── Unrestricted file upload (PHAST-UPLOAD-001, CWE-434) ──────────────────────
#
# An uploaded file is saved under a name whose extension the client chose.  Content
# checks (Laravel ``image`` / ``mimes``) look at the bytes, not at that extension, so
# they do not stop a script-type extension from being stored.  Names built from
# guessExtension()/extension()/hashName() or a fixed suffix never match, and an
# allow-list check on the extension anywhere in the same function suppresses it.

_UPLOAD_CLIENT_NAME_RE = re.compile(
    r"getClientOriginalExtension\s*\(|getClientOriginalName\s*\(|getClientFilename\s*\("
    r"|\$_FILES\b[^;]*?\[\s*['\"]name['\"]\s*\]"
)
_UPLOAD_PUBLIC_RE = re.compile(
    r"public_path|DOCUMENT_ROOT|webroot|web_root|wwwroot|htdocs|\bpublic\b", re.IGNORECASE
)
_UPLOAD_EXT_RULE_RE = re.compile(r"['\"|]extensions:|->extensions\s*\(")
# method / function -> (index of the stored-name argument, index of the directory argument)
_UPLOAD_METHOD_SINKS = {'move': (1, 0), 'storeAs': (1, 0), 'storePubliclyAs': (1, 0),
                        'putFileAs': (2, 0)}
_UPLOAD_FUNC_SINKS = {'move_uploaded_file': (1, 1)}
_UPLOAD_SCOPE_TYPES = ('method_declaration', 'function_definition', 'anonymous_function',
                       'anonymous_function_creation_expression')
_PHP_VAR_RE = re.compile(r"\$\w+")
# Calls that test the client name/extension against an allow-list (suffix match included).
_UPLOAD_CHECK_FUNCS = frozenset({
    'in_array', 'array_search', 'preg_match', 'preg_match_all',
    'substr_compare', 'str_ends_with', 'endsWith', 'ends_with',
})
# A client *name* that only passes through these loses its extension (slug turns the dot
# into a dash, hashes are hex, pathinfo(.., PATHINFO_FILENAME) drops it).  The extension
# itself (getClientOriginalExtension) is never neutralised by them.
_UPLOAD_BAL = r"(?:[^()]|\((?:[^()]|\([^()]*\))*\))*"
_UPLOAD_NAME_WRAP_RE = re.compile(
    r"(?:\bpathinfo|Str::slug|\bslug|\bmd5|\bsha1|\bcrc32|\bhash|\bbin2hex)\s*\(" + _UPLOAD_BAL + r"\)"
)


def _drop_extensionless_names(text: str) -> str:
    def repl(m):
        inner = m.group(0)
        if 'OriginalExtension' in inner:
            return inner
        if inner.lstrip().startswith('pathinfo') and 'PATHINFO_FILENAME' not in inner:
            return inner
        return ' '
    return _UPLOAD_NAME_WRAP_RE.sub(repl, text)


def _node_text(node) -> str:
    return node.text.decode('utf-8', errors='replace')


def _upload_scope(node):
    cur = node.parent
    while cur is not None and cur.type not in _UPLOAD_SCOPE_TYPES:
        cur = cur.parent
    return cur


def _upload_scope_assignments(scope) -> dict[str, list[str]]:
    """{'$var': [rhs text, ...]} for every plain assignment inside *scope*."""
    found: dict[str, list[str]] = {}
    for n in _walk(scope):
        if n.type in ('assignment_expression', 'augmented_assignment_expression'):
            left = n.child_by_field_name('left')
            right = n.child_by_field_name('right')
            if left is not None and right is not None and left.type == 'variable_name':
                found.setdefault(_node_text(left), []).append(_node_text(right))
    return found


def _expand_upload_expr(text: str, assigns: dict[str, list[str]], depth: int = 4,
                        seen: frozenset = frozenset()) -> str:
    """*text* plus the right-hand sides of every variable it mentions (transitively)."""
    out = [text]
    if depth <= 0:
        return text
    for var in set(_PHP_VAR_RE.findall(text)):
        if var in seen:
            continue
        for rhs in assigns.get(var, ()):
            out.append(_expand_upload_expr(rhs, assigns, depth - 1, seen | {var}))
    return ' '.join(out)


def _upload_name_is_checked(scope, assigns: dict[str, list[str]]) -> bool:
    """True when the function checks the client extension against an allow-list."""
    if _UPLOAD_EXT_RULE_RE.search(_node_text(scope)):
        return True
    for n in _walk(scope):
        if n.type == 'function_call_expression':
            fname, args = _call_name(n), _call_args(n)
        elif n.type == 'member_call_expression':
            fname, args = _method_name(n), _member_args(n)
        elif n.type == 'scoped_call_expression':
            fname = next((_node_text(c) for c in reversed(n.children) if c.type == 'name'), '')
            args = _call_args(n)
        else:
            continue
        if fname not in _UPLOAD_CHECK_FUNCS:
            continue
        subject = args[1] if fname.startswith('preg_') and len(args) > 1 else (args[0] if args else None)
        if subject is not None and _UPLOAD_CLIENT_NAME_RE.search(
                _expand_upload_expr(_node_text(subject), assigns)):
            return True
    return False


def _check_uploads(root, file_path: str, lines: list[str], repo_url: str) -> list:
    findings: list[Finding] = []
    seen: set = set()
    cache: dict[int, tuple[dict, bool]] = {}
    for node in _walk(root):
        if node.type == 'member_call_expression':
            sink = _method_name(node)
            idx = _UPLOAD_METHOD_SINKS.get(sink)
            args = _member_args(node) if idx else []
        elif node.type == 'scoped_call_expression':
            sink = next((_node_text(c) for c in reversed(node.children) if c.type == 'name'), '')
            idx = _UPLOAD_METHOD_SINKS.get(sink)
            args = _call_args(node) if idx else []
        elif node.type == 'function_call_expression':
            sink = _call_name(node)
            idx = _UPLOAD_FUNC_SINKS.get(sink)
            args = _call_args(node) if idx else []
        else:
            continue
        if not idx or len(args) <= idx[0]:
            continue
        scope = _upload_scope(node) or root
        key = id(scope)
        if key not in cache:
            assigns = _upload_scope_assignments(scope)
            cache[key] = (assigns, _upload_name_is_checked(scope, assigns))
        assigns, checked = cache[key]
        name_text = _expand_upload_expr(_node_text(args[idx[0]]), assigns)
        if checked or not _UPLOAD_CLIENT_NAME_RE.search(_drop_extensionless_names(name_text)):
            continue
        dir_text = _expand_upload_expr(_node_text(args[idx[1]]), assigns) if len(args) > idx[1] else ''
        publicly = bool(_UPLOAD_PUBLIC_RE.search(dir_text)) or sink == 'storePubliclyAs' \
            or any(_node_text(a).strip('\'"') == 'public' for a in args[2:])
        _emit(findings, seen, file_path, node.start_point[0] + 1, lines, repo_url,
              VulnType.FILE_UPLOAD, Severity.HIGH if publicly else Severity.MEDIUM,
              'PHAST-UPLOAD-001',
              f"Uploaded file saved via {sink}() under a name whose extension comes from the "
              f"client{' into a web-served directory' if publicly else ''} - a script-type "
              "extension would be stored; use a server-chosen name and an extension allow-list")
    return findings


class PhpASTAnalyzer(BaseAnalyzer):
    """PHP AST multi-vuln taint analyzer (tree-sitter-php).

    Covers .php files — Laravel, WordPress, Symfony, and vanilla PHP patterns.
    Detects SQL injection, command injection, path traversal/LFI, XSS,
    SSRF (curl), and open redirect via fixed-point multi-hop taint tracking.
    """
    supported_extensions = ('.php',)

    def analyze(self, file_path: str, content: str, repo_url: str = '') -> list[Finding]:
        if not _TS_AVAILABLE:
            return []
        if not file_path.endswith('.php'):
            return []
        try:
            tree = _php_parser.parse(content.encode('utf-8', errors='replace'))
        except Exception:
            return []

        lines = content.splitlines()
        cf_ctx = _get_php_cf_ctx()
        seed = cf_ctx.tainted_func_names if cf_ctx else None
        scopes, tainted_funcs, tainted_props = _build_taint_scoped(tree.root_node, seed)

        findings = []
        for scope_node, tainted in scopes:
            findings.extend(_check_sinks(
                scope_node, tainted, tainted_funcs, tainted_props, file_path, lines, repo_url,
                walker=_walk_scope,
            ))
        findings.extend(_check_uploads(tree.root_node, file_path, lines, repo_url))
        return findings
