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
"""
from __future__ import annotations

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

# ── Source definitions ────────────────────────────────────────────────────────

_SOURCES: frozenset[str] = frozenset({
    '_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER',
})

# ── Sanitizer definitions ─────────────────────────────────────────────────────

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


def _is_sanitizer_call(node) -> bool:
    """True if node is a sanitizer function call."""
    if node.type != 'function_call_expression' or not node.children:
        return False
    fname_node = node.children[0]
    if fname_node.type != 'name':
        return False
    return fname_node.text.decode('utf-8', errors='replace').lower() in _ALL_SANITIZERS


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

def _is_tainted_node(node, tainted: dict, tainted_funcs: set) -> bool:
    """Return True if this AST node carries user-controlled data."""
    if node is None:
        return False

    t = node.type

    # Direct superglobal bare variable: $_{GET,POST,...}
    if t == 'variable_name':
        name = _var_name(node)
        return name is not None and (name in _SOURCES or name in tainted)

    # Subscript: $_GET["key"] or $tainted["key"]
    if t == 'subscript_expression':
        obj = node.children[0] if node.children else None
        if obj and obj.type == 'variable_name':
            name = _var_name(obj)
            if name and (name in _SOURCES or name in tainted):
                return True
        return False

    # String concatenation / null-coalescing
    if t == 'binary_expression':
        return any(
            _is_tainted_node(c, tainted, tainted_funcs)
            for c in node.children
            if c.type not in ('.', '??', '+', '-', '*', '/', '%', 'and', 'or',
                              'xor', '&&', '||', '==', '!=', '<', '>', '<=', '>=')
        )

    # Double-quoted string with interpolation: "Hello $name" or "SELECT...{$id}"
    if t == 'encapsed_string':
        for child in node.children:
            if child.type in ('variable_name', 'subscript_expression',
                               'member_access_expression', 'variable'):
                if _is_tainted_node(child, tainted, tainted_funcs):
                    return True
        return False

    # Parenthesized
    if t == 'parenthesized_expression':
        for child in node.named_children:
            if _is_tainted_node(child, tainted, tainted_funcs):
                return True
        return False

    # Function call returning tainted data
    if t == 'function_call_expression' and not _is_sanitizer_call(node):
        fname = _call_name(node)
        if fname in tainted_funcs:
            return True

    # Cast expression: (int)$x is clean; (string)$x propagates
    if t == 'cast_expression':
        for child in node.children:
            if child.type in ('integer_cast', 'float_cast', 'boolean_cast'):
                return False
        for child in node.children:
            if _is_tainted_node(child, tainted, tainted_funcs):
                return True

    return False


def _taint_source_desc(node) -> str:
    """Return a short human-readable description of where taint originates."""
    text = node.text.decode('utf-8', errors='replace')[:60]
    return text


def _collect_pass(root, tainted: dict, tainted_funcs: set) -> bool:
    """Walk all assignments and function defs; update taint. Returns True if changed."""
    changed = False
    for node in _walk(root):
        # ── Simple assignment: $var = expr ────────────────────────────────────
        if node.type == 'assignment_expression':
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
            elif _is_tainted_node(rhs, tainted, tainted_funcs):
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
                                child, tainted, tainted_funcs):
                            tainted_funcs.add(fname)
                            changed = True
                            break

    return changed


def _build_taint(root) -> tuple[dict, set]:
    """Fixed-point taint propagation, max 8 passes."""
    tainted: dict[str, tuple[int, str]] = {}
    tainted_funcs: set[str] = set()
    for _ in range(8):
        if not _collect_pass(root, tainted, tainted_funcs):
            break
    return tainted, tainted_funcs


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


# ── Sink checker ─────────────────────────────────────────────────────────────

def _check_sinks(root, tainted, tainted_funcs, file_path, lines, repo_url) -> list:
    findings: list[Finding] = []
    seen: set = set()

    def taint(n):
        return _is_tainted_node(n, tainted, tainted_funcs)

    for node in _walk(root):
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
            elif fname in _PATH_FUNC_SINKS and args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH, 'PHAST-PATH-001',
                      f"User-controlled path flows into {fname}() — path traversal risk")

            # SSRF: curl_setopt($ch, CURLOPT_URL, $url)
            elif fname == 'curl_setopt' and len(args) >= 3:
                const_node = args[1]
                const_text = const_node.text.decode('utf-8', errors='replace') \
                    if const_node else ''
                if const_text in _CURL_URL_CONSTS and taint(args[2]):
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

            # XSS: print_r($var, false) — only if output goes to browser
            # Covered by echo_statement below; skip here to avoid FPs

        # ── Method call sinks: $pdo->query($sql) ─────────────────────────────
        elif node.type == 'member_call_expression':
            mname = _method_name(node)
            if not mname or mname not in _SQL_METHOD_SINKS:
                continue
            args = _member_args(node)
            line = node.start_point[0] + 1
            if args and taint(args[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH, 'PHAST-SQL-001',
                      f"User-controlled data flows into ->{mname}() — SQL injection risk")

        # ── Echo / print sinks ────────────────────────────────────────────────
        elif node.type in ('echo_statement', 'print_intrinsic'):
            line = node.start_point[0] + 1
            for child in node.children:
                if child.type in ('echo', 'print', ';', ','):
                    continue
                # Walk the argument to find tainted references not inside sanitizers
                for sub in _walk(child):
                    if _is_sanitizer_call(sub):
                        break
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

    return findings


# ── Analyzer class ────────────────────────────────────────────────────────────

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
        tainted, tainted_funcs = _build_taint(tree.root_node)

        return _check_sinks(
            tree.root_node, tainted, tainted_funcs, file_path, lines, repo_url
        )
