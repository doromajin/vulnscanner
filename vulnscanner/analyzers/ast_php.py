"""
PHP AST analyzer (tree-sitter-php) — multi-hop XSS taint tracking.

Detects patterns that regex-based analysis (XSS-008) misses:
  PHP-XSS-010  2-hop variable reassignment  ($a=src; $b=$a; echo $b)
  PHP-XSS-011  null-coalescing propagation  ($b=$a??'x'; echo $b when $a tainted)
  PHP-XSS-012  function return taint        (function f(){return $_GET[..];} echo f())

Intentionally does NOT re-detect what XSS-005 / XSS-008 already cover:
  - Direct superglobal echo: echo $_GET[...] (XSS-005)
  - 1-hop var taint:         $a=$_GET[..]; echo $a (XSS-008)
"""
from __future__ import annotations

try:
    import tree_sitter_php as _tsp
    from tree_sitter import Language, Parser as _TSParser
    _PHP_LANGUAGE = Language(_tsp.language_php())
    _parser = _TSParser(_PHP_LANGUAGE)
    _TS_AVAILABLE = True
except Exception:
    _TS_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# PHP superglobal names (without leading $) that carry user-controlled data
_SOURCES: frozenset[str] = frozenset({
    '_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES',
})

# Functions that make a value safe for HTML output
_XSS_SANITIZERS: frozenset[str] = frozenset({
    'htmlspecialchars', 'htmlentities', 'strip_tags',
    'esc_html', 'esc_attr', 'esc_textarea', 'esc_url',
    'wp_kses', 'wp_kses_post', 'sanitize_text_field', 'wp_strip_all_tags',
    'intval', 'floatval', 'abs', 'number_format', 'round', 'ceil', 'floor',
})


# ── AST helpers ───────────────────────────────────────────────────────────────

def _var_name(node) -> str | None:
    """Return bare name (no $) from a variable_name node, or None."""
    if node.type != 'variable_name':
        return None
    for child in node.children:
        if child.type == 'name':
            return child.text.decode('utf-8')
    return None


def _is_source(node) -> bool:
    """True when node is a superglobal access like $_GET[...]."""
    if node.type == 'variable_name':
        name = _var_name(node)
        return name is not None and name in _SOURCES
    return False


def _walk(node):
    """Yield node and all descendants in pre-order."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _contains_source(node) -> bool:
    """True if node or any descendant is a superglobal variable."""
    return any(_is_source(n) for n in _walk(node))


def _is_sanitizer_call(node) -> bool:
    """True if node is a call to an HTML-sanitizing function."""
    if node.type != 'function_call_expression':
        return False
    children = node.children
    if not children:
        return False
    fname_node = children[0]
    if fname_node.type != 'name':
        return False
    return fname_node.text.decode('utf-8').lower() in _XSS_SANITIZERS


def _collect_unsafe_tainted_refs(
    node, transitive_tainted: dict[str, tuple[int, str, str]]
) -> list[tuple[str, str, str]]:
    """
    Walk *node* and return [(varname, rule_id, src_desc)] for each variable
    that is in *transitive_tainted* and is NOT wrapped in a sanitizing call.
    Stops recursion when it enters a sanitizer call subtree.
    """
    if _is_sanitizer_call(node):
        return []

    if node.type == 'variable_name':
        name = _var_name(node)
        if name and name in transitive_tainted:
            _line, src_desc, rule_id = transitive_tainted[name]
            return [(name, rule_id, src_desc)]
        return []

    results: list[tuple[str, str, str]] = []
    for child in node.children:
        results.extend(_collect_unsafe_tainted_refs(child, transitive_tainted))
    return results


# ── Taint state ───────────────────────────────────────────────────────────────

class _TaintState:
    """
    Accumulates taint for a single PHP file.

    direct_tainted    – vars whose RHS directly contained a superglobal.
                        XSS-008 handles these at sinks; AST skips them.
    transitive_tainted – vars tainted through ≥1 hop of variable propagation,
                        null-coalescing, or a function returning a source.
                        Stored as {varname: (line, src_desc, rule_id)}.
    tainted_funcs     – {funcname: def_line} for functions whose bodies
                        return a superglobal directly.
    """

    def __init__(self) -> None:
        self.direct_tainted: dict[str, int] = {}
        self.transitive_tainted: dict[str, tuple[int, str, str]] = {}
        self.tainted_funcs: dict[str, int] = {}

    # ── Assignment ────────────────────────────────────────────────────────────

    def process_assignment(self, lhs_node, rhs_node) -> None:
        var = _var_name(lhs_node)
        if var is None or var in _SOURCES:
            return
        line = lhs_node.start_point[0] + 1

        # Sanitizer on RHS → clear any taint on this var
        if _is_sanitizer_call(rhs_node):
            self.direct_tainted.pop(var, None)
            self.transitive_tainted.pop(var, None)
            return

        # Superglobal in RHS → directly tainted (XSS-008 territory)
        if _contains_source(rhs_node):
            self.direct_tainted[var] = line
            self.transitive_tainted.pop(var, None)
            return

        # Check for transitive taint
        taint = self._resolve_transitive(rhs_node, line)
        if taint:
            self.transitive_tainted[var] = taint
            self.direct_tainted.pop(var, None)
        else:
            # Clean RHS — clear previous taint on this variable
            self.direct_tainted.pop(var, None)
            self.transitive_tainted.pop(var, None)

    def _resolve_transitive(
        self, rhs_node, line: int
    ) -> tuple[int, str, str] | None:
        """
        Return (line, src_desc, rule_id) if rhs carries transitive taint, else None.
        Priority: null-coalescing > variable refs > function call.
        """
        # ── Null-coalescing: $b = $tainted ?? 'fallback' → PHP-XSS-011 ─────
        if rhs_node.type == 'binary_expression':
            children = rhs_node.children
            has_nullcoalesce = any(c.type == '??' for c in children)
            if has_nullcoalesce and children:
                left = children[0]
                left_var = _var_name(left)
                if left_var and (
                    left_var in self.direct_tainted
                    or left_var in self.transitive_tainted
                ):
                    return (line, f'${left_var} (null-coalescing ??)', 'PHP-XSS-011')

        # ── Variable references: $b = $tainted → PHP-XSS-010 ────────────────
        for n in _walk(rhs_node):
            if n.type == 'variable_name':
                rv = _var_name(n)
                if rv is None:
                    continue
                if rv in self.transitive_tainted or rv in self.direct_tainted:
                    return (line, f'${rv}', 'PHP-XSS-010')

        # ── Function call: $b = tainted_func() → PHP-XSS-012 ────────────────
        if rhs_node.type == 'function_call_expression' and rhs_node.children:
            fname_node = rhs_node.children[0]
            if fname_node.type == 'name':
                fname = fname_node.text.decode('utf-8')
                if fname in self.tainted_funcs:
                    return (line, f'{fname}()', 'PHP-XSS-012')

        return None

    # ── Function definition analysis ──────────────────────────────────────────

    def analyze_function(self, func_node) -> None:
        """Mark function as tainted if its body returns a superglobal directly."""
        name_nodes = [c for c in func_node.children if c.type == 'name']
        if not name_nodes:
            return
        func_name = name_nodes[0].text.decode('utf-8')
        def_line = func_node.start_point[0] + 1

        body_nodes = [c for c in func_node.children if c.type == 'compound_statement']
        if not body_nodes:
            return

        for n in _walk(body_nodes[0]):
            if n.type == 'return_statement' and _contains_source(n):
                self.tainted_funcs[func_name] = def_line
                return

    # ── Echo / print sink ─────────────────────────────────────────────────────

    def check_echo_sink(self, echo_node) -> tuple[str, str, int] | None:
        """
        Return (rule_id, description, line) if the echo outputs a transitively-
        tainted value without sanitization, else None.
        Direct-taint vars (XSS-008 territory) are intentionally skipped.
        """
        line = echo_node.start_point[0] + 1
        for child in echo_node.children:
            if child.type in ('echo', 'print', ';'):
                continue
            refs = _collect_unsafe_tainted_refs(child, self.transitive_tainted)
            if refs:
                varname, rule_id, src_desc = refs[0]
                desc = (
                    f'${varname} carries user-controlled input from {src_desc} '
                    f'and is echoed without HTML encoding — use htmlspecialchars()'
                )
                return rule_id, desc, line
        return None


# ── Analyzer class ────────────────────────────────────────────────────────────

class PhpASTAnalyzer(BaseAnalyzer):
    supported_extensions = ('.php',)

    def analyze(self, file_path: str, content: str, repo_url: str = '') -> list[Finding]:
        if not _TS_AVAILABLE:
            return []

        try:
            tree = _parser.parse(content.encode('utf-8', errors='replace'))
        except Exception:
            return []

        root = tree.root_node
        state = _TaintState()
        lines = content.splitlines()

        # Pass 1: collect function definitions (PHP hoists them)
        for node in _walk(root):
            if node.type == 'function_definition':
                state.analyze_function(node)

        # Pass 2: process top-level statements in source order
        findings: list[Finding] = []
        for node in root.children:
            if node.type == 'expression_statement':
                _process_expression_statement(node, state)
            elif node.type in ('echo_statement', 'print_intrinsic'):
                result = state.check_echo_sink(node)
                if result:
                    rule_id, desc, lineno = result
                    findings.append(Finding(
                        vuln_type=VulnType.XSS,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=lines[lineno - 1].strip() if lineno <= len(lines) else '',
                        description=desc,
                        rule_id=rule_id,
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))

        return findings


def _process_expression_statement(stmt_node, state: _TaintState) -> None:
    """Extract assignment_expression children and update taint state."""
    for child in stmt_node.children:
        if child.type == 'assignment_expression':
            _process_assignment_expr(child, state)


def _process_assignment_expr(node, state: _TaintState) -> None:
    """
    Parse an assignment_expression node and call state.process_assignment.
    Handles simple $var = expr (skips compound assignments like .=, +=).
    """
    children = node.children
    eq_idx = next((i for i, c in enumerate(children) if c.type == '='), None)
    if eq_idx is None or eq_idx == 0 or eq_idx >= len(children) - 1:
        return
    lhs = children[eq_idx - 1]
    rhs = children[eq_idx + 1]
    if lhs.type == 'variable_name':
        state.process_assignment(lhs, rhs)
