"""Java vulnerability analyzer using javalang AST.

Provides taint-aware detection with variable-flow tracking:
  source (request.getParameter) -> local var -> sink (executeQuery)

Falls back gracefully to empty list if javalang is not installed or
the file uses unsupported Java syntax.
"""
from __future__ import annotations

import json
from pathlib import Path

try:
    import javalang
    import javalang.tree as jt
    _HAS_JAVALANG = True
except ImportError:
    _HAS_JAVALANG = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType


def _load_custom_taint_sources() -> frozenset:
    """Load user-defined any-qualifier taint methods from custom_taint_sources.json.

    Searches for the config file next to this file's package root (i.e. the project
    root two levels up from analyzers/). Silently returns an empty set if the file is
    absent or malformed so the analyzer remains usable without configuration.
    """
    config_path = Path(__file__).parent.parent.parent / "custom_taint_sources.json"
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        entries = data.get("any_qualifier_taint_methods", [])
        return frozenset(e["method"] for e in entries if isinstance(e, dict) and "method" in e)
    except (FileNotFoundError, json.JSONDecodeError, TypeError, KeyError):
        return frozenset()

# ── request source methods ─────────────────────────────────────────────────────

_REQUEST_METHODS = frozenset({
    "getParameter", "getParameterValues", "getParameterMap", "getParameterNames",
    "getHeader", "getHeaders", "getHeaderNames",
    "getInputStream", "getReader",
    "getQueryString", "getPathInfo", "getRequestURI", "getRequestURL",
    "getCookies", "getRemoteAddr", "getAttribute", "getSession",
})

_REQUEST_OBJECTS = frozenset({
    "request", "req", "httpRequest", "servletRequest",
    "httpServletRequest", "hreq",
})

# Methods that return user-controlled data regardless of what object they're called on.
# Populated from custom_taint_sources.json — no hardcoded values here.
_ANY_QUALIFIER_TAINT_METHODS = _load_custom_taint_sources()

# ── sink sets ──────────────────────────────────────────────────────────────────

_SQL_EXEC_METHODS = frozenset({
    "execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
    "executeBatch", "addBatch", "prepareCall", "prepareStatement",
    # Spring JdbcTemplate
    "queryForLong", "queryForInt", "queryForObject", "queryForList",
    "queryForMap", "queryForRowSet", "queryForStream",
    "query", "batchUpdate",
})

_JPA_METHODS = frozenset({
    "createQuery", "createNativeQuery", "createNamedQuery",
})

_FILE_CLASSES = frozenset({
    "File", "FileInputStream", "FileOutputStream",
    "FileReader", "FileWriter", "RandomAccessFile",
})

_XXE_FACTORIES = frozenset({
    "DocumentBuilderFactory", "SAXParserFactory",
    "XMLInputFactory", "TransformerFactory",
})

_DESER_CLASSES = frozenset({"ObjectInputStream"})

_SPEL_METHODS = frozenset({"parseExpression"})

# ── XSS writer sinks and sanitizers ───────────────────────────────────────────

_RESPONSE_OBJECTS = frozenset({
    "response", "resp", "httpResponse", "servletResponse", "res",
})

_XSS_SINK_METHODS = frozenset({
    "print", "println", "format", "printf", "write", "append",
})

# These methods sanitize for HTML output — taint should NOT propagate through them
_XSS_SANITIZER_METHODS = frozenset({
    "htmlEscape", "escapeHtml", "escapeHtml4", "escapeHtml3",
    "encodeForHTML", "encodeForHTMLAttribute",
    "htmlEncode", "escapeXml", "escapeXml10", "escapeXml11",
    "encode",  # ESAPI encoder().encode()
})

# ── Weak cryptography ──────────────────────────────────────────────────────────

# Algorithms to flag for MessageDigest.getInstance(algo)
_WEAK_HASH_ALGOS = frozenset({"MD5", "SHA-1", "SHA1", "MD2", "MD4"})

# Prefixes/exact names to flag for Cipher.getInstance(algo)
_WEAK_CIPHER_PREFIXES = ("DES", "RC2", "RC4", "ARCFOUR", "BLOWFISH")

# ── LDAP ──────────────────────────────────────────────────────────────────────

_LDAP_HINTS = frozenset({
    "DirContext", "InitialDirContext", "LdapContext",
    "javax.naming", "NamingEnumeration",
})

_LDAP_SEARCH_METHODS = frozenset({"search", "lookup", "bind", "getAttributes"})


# Spring MVC: method parameters carrying these annotations receive user-supplied data.
# Equivalent in taint terms to request.getParameter() on the same value.
_SPRING_PARAM_ANNOTATIONS = frozenset({
    "RequestParam", "PathVariable", "RequestBody",
    "RequestHeader", "CookieValue", "MatrixVariable",
    "ModelAttribute",
})

# ── taint helpers ──────────────────────────────────────────────────────────────

def _type_name(ref_type) -> str:
    """Return the leaf class name from a javalang ReferenceType (handles java.util.Random etc.)."""
    while getattr(ref_type, "sub_type", None) is not None:
        ref_type = ref_type.sub_type
    return getattr(ref_type, "name", "") or ""


def _node_line(node) -> int:
    pos = getattr(node, "position", None)
    if pos and hasattr(pos, "line"):
        return pos.line
    return 0


def _is_request_source(node) -> bool:
    """True if node is a direct call to a servlet/framework request getter."""
    if not isinstance(node, jt.MethodInvocation):
        return False
    if node.member in _ANY_QUALIFIER_TAINT_METHODS:
        return True  # tainted regardless of what object it is called on
    if node.member not in _REQUEST_METHODS:
        return False
    q = node.qualifier or ""
    return (not q) or str(q) in _REQUEST_OBJECTS


# ── Constant expression evaluator (for dead-code elimination) ──────────────────

def _eval_const_expr(node, const_ints: dict, const_strings: dict) -> "int | None":
    """Evaluate an arithmetic/comparison expression as a constant integer.

    Returns an integer (0 = false, non-zero = true for boolean ops) or None if
    the expression depends on non-constant values.
    """
    if node is None:
        return None
    if isinstance(node, jt.Literal):
        v = str(node.value or "")
        try:
            return int(v)
        except ValueError:
            pass
        if v == "true":
            return 1
        if v == "false":
            return 0
        # char literal: 'A' → 65
        if len(v) >= 3 and v[0] == "'" and v[-1] == "'":
            inner = v[1:-1]
            if len(inner) == 1:
                return ord(inner)
        # hex integer: 0xFF
        if v.startswith(("0x", "0X")):
            try:
                return int(v, 16)
            except Exception:
                pass
        # long literal: 86L
        if v.endswith(("l", "L")):
            try:
                return int(v[:-1])
            except Exception:
                pass
        return None
    if isinstance(node, jt.MemberReference):
        return const_ints.get(node.member)
    if isinstance(node, jt.BinaryOperation):
        lv = _eval_const_expr(node.operandl, const_ints, const_strings)
        rv = _eval_const_expr(node.operandr, const_ints, const_strings)
        if lv is None or rv is None:
            return None
        op = node.operator
        try:
            if op == "+":   return lv + rv
            if op == "-":   return lv - rv
            if op == "*":   return lv * rv
            if op == "/":   return lv // rv if rv else None
            if op == "%":   return lv % rv if rv else None
            if op == ">":   return int(lv > rv)
            if op == "<":   return int(lv < rv)
            if op == ">=":  return int(lv >= rv)
            if op == "<=":  return int(lv <= rv)
            if op == "==":  return int(lv == rv)
            if op == "!=":  return int(lv != rv)
            if op == "&&":  return int(bool(lv) and bool(rv))
            if op == "||":  return int(bool(lv) or bool(rv))
        except Exception:
            pass
        return None
    if isinstance(node, jt.MethodInvocation) and node.member == "charAt":
        args = node.arguments or []
        if args:
            n = _eval_const_expr(args[0], const_ints, const_strings)
            if n is not None:
                q = str(node.qualifier or "")
                # "literal".charAt(N)
                if len(q) >= 2 and q[0] == '"' and q[-1] == '"':
                    s = q[1:-1]
                    if 0 <= n < len(s):
                        return ord(s[n])
                # variable.charAt(N) where variable = "literal"
                if q in const_strings:
                    s = const_strings[q]
                    if 0 <= n < len(s):
                        return ord(s[n])
    return None


def _collect_const_context(tree):
    """Collect constant integer/char/string variable values from the tree.

    Returns (const_ints, const_strings) where const_ints maps variable name → int
    and const_strings maps variable name → str value (without surrounding quotes).
    """
    const_ints: dict = {}
    const_strings: dict = {}
    try:
        for _, node in tree.filter(jt.LocalVariableDeclaration):
            for decl in node.declarators:
                init = decl.initializer
                if init is None:
                    continue
                if isinstance(init, jt.Literal):
                    v = str(init.value or "")
                    # Integer or boolean literal
                    try:
                        const_ints[decl.name] = int(v)
                        continue
                    except ValueError:
                        pass
                    if v == "true":
                        const_ints[decl.name] = 1
                        continue
                    if v == "false":
                        const_ints[decl.name] = 0
                        continue
                    # char literal: 'B' → 66
                    if len(v) >= 3 and v[0] == "'" and v[-1] == "'":
                        inner = v[1:-1]
                        if len(inner) == 1:
                            const_ints[decl.name] = ord(inner)
                            continue
                    # String literal: "ABC" → const_strings entry
                    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                        const_strings[decl.name] = v[1:-1]
                        continue
                # charAt() call producing a constant char: char c = guess.charAt(1)
                if isinstance(init, jt.MethodInvocation) and init.member == "charAt":
                    val = _eval_const_expr(init, const_ints, const_strings)
                    if val is not None:
                        const_ints[decl.name] = val
    except Exception:
        pass
    return const_ints, const_strings


def _collect_dead_lines(tree, const_ints: dict, const_strings: dict) -> "set[int]":
    """Return line numbers of statement-level assignments/declarations in provably dead branches.

    Handles two patterns from OWASP Benchmark:
    1. IfStatement with a constant-evaluable condition
    2. SwitchStatement with a constant-evaluable switch expression

    IMPORTANT: in javalang, statement-level assignments ``bar = param;`` are wrapped in
    StatementExpression (which carries the line number), not in Assignment directly.
    So we collect StatementExpression lines, not Assignment lines.
    """
    dead: set = set()

    def _pos_line(node) -> int:
        pos = getattr(node, "position", None)
        return pos.line if pos else -1

    def _mark_subtree(block) -> None:
        if block is None:
            return
        # Handle single-statement else/then without braces: the block IS a StatementExpression
        if isinstance(block, jt.StatementExpression):
            if isinstance(getattr(block, "expression", None), jt.Assignment):
                ln = _pos_line(block)
                if ln > 0:
                    dead.add(ln)
        elif isinstance(block, jt.LocalVariableDeclaration):
            ln = _pos_line(block)
            if ln > 0:
                dead.add(ln)
        # Recurse: find all nested StatementExpression(Assignment) nodes
        try:
            for _, se in block.filter(jt.StatementExpression):
                if isinstance(getattr(se, "expression", None), jt.Assignment):
                    ln = _pos_line(se)
                    if ln > 0:
                        dead.add(ln)
        except Exception:
            pass
        try:
            for _, d in block.filter(jt.LocalVariableDeclaration):
                ln = _pos_line(d)
                if ln > 0:
                    dead.add(ln)
        except Exception:
            pass

    try:
        for _, if_node in tree.filter(jt.IfStatement):
            val = _eval_const_expr(if_node.condition, const_ints, const_strings)
            if val is None:
                continue
            # condition always True → else branch is dead; always False → then branch
            dead_block = if_node.else_statement if val != 0 else if_node.then_statement
            _mark_subtree(dead_block)
    except Exception:
        pass

    try:
        for _, sw in tree.filter(jt.SwitchStatement):
            sw_val = _eval_const_expr(sw.expression, const_ints, const_strings)
            if sw_val is None:
                continue
            # Track whether a prior live case fell through (no break/return).
            # Fall-through makes the next case live even if its label doesn't match.
            live_and_falling = False
            for case in (sw.cases or []):
                # In javalang, case.case is a list of Literals (empty = default)
                case_literals = case.case if isinstance(case.case, list) else (
                    [case.case] if case.case is not None else []
                )
                if not case_literals:
                    # default: live only if a prior case fell through, else dead
                    if not live_and_falling:
                        _mark_subtree(case)
                    live_and_falling = False
                    continue
                # This case directly matches the constant switch value
                case_direct = any(
                    _eval_const_expr(lit, const_ints, const_strings) == sw_val
                    for lit in case_literals
                )
                is_live = case_direct or live_and_falling
                if not is_live:
                    _mark_subtree(case)
                # A live case falls through if it has no break/return in its body
                stmts = getattr(case, "statements", None) or []
                has_terminator = any(
                    isinstance(s, (jt.BreakStatement, jt.ReturnStatement))
                    for s in stmts
                )
                live_and_falling = is_live and not has_terminator
    except Exception:
        pass

    return dead


# ── taint propagation ──────────────────────────────────────────────────────────

def _is_tainted(node, tainted: "set[str]", const_ints: "dict | None" = None) -> bool:
    """Recursively check whether a javalang expression node carries taint."""
    if node is None:
        return False
    if isinstance(node, jt.MethodInvocation):
        if _is_request_source(node):
            return True
        # Known XSS sanitizers: taint is neutralized, do not propagate
        if node.member in _XSS_SANITIZER_METHODS:
            return False
        q = str(node.qualifier or "")
        # Propagate through qualifier chain: taintedVar.getValue(), nextElement(), etc.
        if q and q in tainted:
            return True
        if any(_is_tainted(a, tainted, const_ints) for a in (node.arguments or [])):
            return True
        return False
    if isinstance(node, jt.MemberReference):
        return node.member in tainted
    if isinstance(node, jt.BinaryOperation):
        return _is_tainted(node.operandl, tainted, const_ints) or _is_tainted(node.operandr, tainted, const_ints)
    if isinstance(node, jt.Literal):
        return False
    if isinstance(node, jt.ClassCreator):
        return any(_is_tainted(a, tainted, const_ints) for a in (node.arguments or []))
    if isinstance(node, jt.ArrayInitializer):
        return any(_is_tainted(x, tainted, const_ints) for x in (node.initializers or []))
    if isinstance(node, jt.ArrayCreator):
        inner = getattr(node, "initializer", None)
        if inner is not None:
            return any(_is_tainted(x, tainted, const_ints) for x in (getattr(inner, "initializers", None) or []))
        return False
    if isinstance(node, jt.Cast):
        return _is_tainted(node.expression, tainted, const_ints)
    if isinstance(node, jt.TernaryExpression):
        if const_ints is not None:
            cond_val = _eval_const_expr(node.condition, const_ints, {})
            if cond_val is not None:
                branch = node.if_true if cond_val != 0 else node.if_false
                return _is_tainted(branch, tainted, const_ints)
        return _is_tainted(node.if_true, tainted, const_ints) or _is_tainted(node.if_false, tainted, const_ints)
    if hasattr(node, "expression"):
        return _is_tainted(node.expression, tainted, const_ints)
    return False


def _analyze_local_method(
    tree,
    method_name: str,
    call_args: list,
    caller_tainted: "set[str]",
    caller_ci: dict,
) -> "bool | None":
    """Analyze a local (no-qualifier) static method's return taint.

    Returns True  → method returns tainted data given the caller's arg taint
            False → method provably returns safe data
            None  → method not found or analysis inconclusive (fall back to arg propagation)
    """
    try:
        for _, method in tree.filter(jt.MethodDeclaration):
            if method.name != method_name or not method.body:
                continue

            # Map caller args' taint to method formal params
            params = method.parameters or []
            m_tainted: set = set()
            for i, param in enumerate(params):
                pname = getattr(param, "name", "") or ""
                if not pname:
                    continue
                if i < len(call_args) and _is_tainted(call_args[i], caller_tainted, caller_ci):
                    m_tainted.add(pname)

            # Constant context scoped to this method's body
            m_ci: dict = {}
            m_cs: dict = {}
            try:
                for _, lvd in method.filter(jt.LocalVariableDeclaration):
                    for decl in lvd.declarators:
                        if decl.initializer is None:
                            continue
                        init = decl.initializer
                        if isinstance(init, jt.Literal):
                            v = str(init.value or "")
                            try:
                                m_ci[decl.name] = int(v)
                                continue
                            except ValueError:
                                pass
                            if len(v) >= 3 and v[0] == "'" and v[-1] == "'":
                                inner = v[1:-1]
                                if len(inner) == 1:
                                    m_ci[decl.name] = ord(inner)
                                    continue
                            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                                m_cs[decl.name] = v[1:-1]
                        elif isinstance(init, jt.MethodInvocation) and init.member == "charAt":
                            val = _eval_const_expr(init, m_ci, m_cs)
                            if val is not None:
                                m_ci[decl.name] = val
            except Exception:
                pass

            # Dead lines within method (handles if/switch dead branches)
            m_dead = _collect_dead_lines(method, m_ci, m_cs)

            def _m_line(n) -> int:
                pos = getattr(n, "position", None)
                return pos.line if pos else -1

            # Fixed-point taint propagation within this method's scope
            for _ in range(4):
                chg = False
                try:
                    for _, lvd in method.filter(jt.LocalVariableDeclaration):
                        if _m_line(lvd) in m_dead:
                            continue
                        for decl in lvd.declarators:
                            if decl.name not in m_tainted and decl.initializer:
                                if _is_tainted(decl.initializer, m_tainted, m_ci):
                                    m_tainted.add(decl.name)
                                    chg = True
                except Exception:
                    pass
                try:
                    for _, se in method.filter(jt.StatementExpression):
                        if not isinstance(getattr(se, "expression", None), jt.Assignment):
                            continue
                        if _m_line(se) in m_dead:
                            continue
                        assign = se.expression
                        lhs = assign.expressionl
                        if isinstance(lhs, jt.MemberReference) and lhs.member not in m_tainted:
                            if _is_tainted(assign.value, m_tainted, m_ci):
                                m_tainted.add(lhs.member)
                                chg = True
                except Exception:
                    pass
                if not chg:
                    break

            # Check every return statement for taint
            try:
                for _, ret in method.filter(jt.ReturnStatement):
                    if ret.expression is not None and _is_tainted(ret.expression, m_tainted, m_ci):
                        return True
            except Exception:
                pass
            return False  # All returns are safe
    except Exception:
        pass
    return None  # Method not found → fall back to arg-based propagation


def _collect_tainted(tree) -> "tuple[set[str], set[str]]":
    """Multi-pass fixed-point taint collector with dead-branch elimination.

    Handles:
    - LocalVariableDeclaration  (String param = request.getParameter(...))
    - Assignment                (param = request.getHeader(...), re-assignments)
    - ForStatement w/ EnhancedForControl  (for (Cookie c : taintedCookies))
    - Dead-code branches from constant if/switch conditions are skipped
    """
    tainted: set = set()

    # Constant context enables dead-branch skipping and constant-condition ternary
    const_ints, const_strings = _collect_const_context(tree)
    dead_lines = _collect_dead_lines(tree, const_ints, const_strings)

    # Key-matched HashMap taint tracking: {map_var_name → set_of_tainted_key_literals}
    # When map.put("key", tainted_val) is seen, "key" is added.
    # When map.get("key") is read with a matching tainted key, the result is tainted.
    map_tainted_keys: dict = {}

    # Ordered list state tracking: {list_var → [is_tainted_at_index_0, ...]}
    # Populated by list.add/remove/set SE calls; read by list.get checks.
    list_contents: dict = {}

    def _line_of(node) -> int:
        pos = getattr(node, "position", None)
        return pos.line if pos else -1

    def _map_get_tainted(node, map_keys: dict) -> bool:
        """Return True if node is map.get(key_literal) where key is in map_keys[map]."""
        inner = node.expression if isinstance(node, jt.Cast) else node
        if not isinstance(inner, jt.MethodInvocation) or inner.member != "get":
            return False
        q = str(inner.qualifier or "")
        if not q or q not in map_keys:
            return False
        args = inner.arguments or []
        if not args:
            return False
        key = _literal_str(args[0])
        return key is not None and key in map_keys[q]

    # Spring MVC: collect @RequestParam / @PathVariable / @RequestBody annotated
    # method parameters as taint sources before the fixed-point propagation loop.
    try:
        for _, method in tree.filter(jt.MethodDeclaration):
            for param in (method.parameters or []):
                for ann in (getattr(param, "annotations", None) or []):
                    if getattr(ann, "name", "") in _SPRING_PARAM_ANNOTATIONS:
                        pname = getattr(param, "name", "")
                        if pname:
                            tainted.add(pname)
                        break
    except Exception:
        pass

    for _ in range(6):
        changed = False

        try:
            for _, node in tree.filter(jt.LocalVariableDeclaration):
                if _line_of(node) in dead_lines:
                    continue
                for decl in node.declarators:
                    init = decl.initializer
                    # Reset list state each round when a new ArrayList/LinkedList/Vector is seen
                    if isinstance(init, jt.ClassCreator):
                        _lct = _type_name(init.type)
                        if _lct in ("ArrayList", "LinkedList", "Vector"):
                            list_contents.setdefault(decl.name, [])
                    if decl.name not in tainted and init:
                        # For bare (no-qualifier) static calls, try intra-file return analysis
                        # before falling back to argument propagation.
                        # qualifier=''  → bare call doSomething(...)   → intercept
                        # qualifier=None → chained new X().doSomething() → skip (fall back)
                        # qualifier='x'  → instance call x.doSomething() → skip
                        if (isinstance(init, jt.MethodInvocation)
                                and init.qualifier == ""
                                and not _is_request_source(init)):
                            result = _analyze_local_method(
                                tree, init.member, init.arguments or [],
                                tainted, const_ints,
                            )
                            if result is not None:
                                if result:
                                    tainted.add(decl.name)
                                    changed = True
                                continue  # analysis decided; skip arg-based fallback
                        # Ordered list.get(idx) taint propagation — always continue so the
                        # general _is_tainted fallback cannot over-taint via qualifier-in-tainted.
                        _li_inner = init.expression if isinstance(init, jt.Cast) else init
                        if (isinstance(_li_inner, jt.MethodInvocation)
                                and _li_inner.member == "get"
                                and str(_li_inner.qualifier or "") in list_contents):
                            _liq = str(_li_inner.qualifier)
                            _lia = _li_inner.arguments or []
                            if _lia:
                                _lii = _eval_const_expr(_lia[0], const_ints, const_strings)
                                if (_lii is not None
                                        and 0 <= _lii < len(list_contents[_liq])
                                        and list_contents[_liq][_lii]):
                                    tainted.add(decl.name); changed = True
                                continue  # skip general propagation for tracked list.get
                        # Key-matched HashMap.get: (Type) map.get("key") where key is tainted
                        if _map_get_tainted(init, map_tainted_keys):
                            tainted.add(decl.name)
                            changed = True
                            continue
                        if _is_tainted(init, tainted, const_ints):
                            tainted.add(decl.name)
                            changed = True
        except Exception:
            pass

        # Re-assignments like "bar = param;" are StatementExpression(Assignment(...)).
        # The position lives on the StatementExpression, not the inner Assignment, so we
        # iterate StatementExpression nodes to correctly apply the dead-line filter.
        try:
            for _, se in tree.filter(jt.StatementExpression):
                if not isinstance(getattr(se, "expression", None), jt.Assignment):
                    continue
                if _line_of(se) in dead_lines:
                    continue
                node = se.expression
                lhs = node.expressionl
                if not isinstance(lhs, jt.MemberReference):
                    continue
                _vname = lhs.member
                rhs = node.value

                # Key-matched HashMap.get: run regardless of current taint state so that
                # a safe-key reassignment (bar = map.get("safeKey")) can override a prior
                # tainted-key assignment (bar = map.get("taintedKey")).
                _rhs_m = rhs.expression if isinstance(rhs, jt.Cast) else rhs
                if (isinstance(_rhs_m, jt.MethodInvocation)
                        and _rhs_m.member == "get"
                        and _rhs_m.qualifier
                        and str(_rhs_m.qualifier) in map_tainted_keys):
                    _mq = str(_rhs_m.qualifier)
                    _margs = _rhs_m.arguments or []
                    if _margs:
                        _mkey = _literal_str(_margs[0])
                        if _mkey is not None:
                            if _mkey in map_tainted_keys[_mq]:
                                if _vname not in tainted:
                                    tainted.add(_vname); changed = True
                            elif _vname in tainted:
                                # Safe-key override: last map.get used a non-tainted key
                                tainted.discard(_vname); changed = True
                            continue

                # General propagation: only add taint (never remove).
                if _vname not in tainted:
                    # Ordered list.get(idx) taint propagation — always continue so the
                    # general _is_tainted fallback cannot over-taint via qualifier-in-tainted.
                    _li_rhs = rhs.expression if isinstance(rhs, jt.Cast) else rhs
                    if (isinstance(_li_rhs, jt.MethodInvocation)
                            and _li_rhs.member == "get"
                            and str(_li_rhs.qualifier or "") in list_contents):
                        _liq2 = str(_li_rhs.qualifier)
                        _lia2 = _li_rhs.arguments or []
                        if _lia2:
                            _lii2 = _eval_const_expr(_lia2[0], const_ints, const_strings)
                            if (_lii2 is not None
                                    and 0 <= _lii2 < len(list_contents[_liq2])
                                    and list_contents[_liq2][_lii2]):
                                tainted.add(_vname); changed = True
                            continue  # skip general propagation for tracked list.get
                    # For bare (no-qualifier) static calls, try intra-file return analysis.
                    # qualifier='' → bare call; qualifier=None → new X().m() chain → skip.
                    if (isinstance(rhs, jt.MethodInvocation)
                            and rhs.qualifier == ""
                            and not _is_request_source(rhs)):
                        result = _analyze_local_method(
                            tree, rhs.member, rhs.arguments or [],
                            tainted, const_ints,
                        )
                        if result is not None:
                            if result:
                                tainted.add(_vname)
                                changed = True
                            continue  # analysis decided; skip arg-based fallback
                    if _is_tainted(rhs, tainted, const_ints):
                        tainted.add(_vname)
                        changed = True
        except Exception:
            pass

        # Track map.put("key", tainted_val) → record tainted key in map_tainted_keys
        try:
            for _, se in tree.filter(jt.StatementExpression):
                if _line_of(se) in dead_lines:
                    continue
                expr = getattr(se, "expression", None)
                if not isinstance(expr, jt.MethodInvocation):
                    continue
                if expr.member not in ("put", "putIfAbsent"):
                    continue
                q = str(expr.qualifier or "")
                if not q:
                    continue
                args = expr.arguments or []
                if len(args) < 2:
                    continue
                key_lit = _literal_str(args[0])
                if key_lit is None:
                    continue
                if _is_tainted(args[1], tainted, const_ints):
                    if q not in map_tainted_keys:
                        map_tainted_keys[q] = set()
                    if key_lit not in map_tainted_keys[q]:
                        map_tainted_keys[q].add(key_lit)
                        changed = True
        except Exception:
            pass

        # Rebuild list_contents from scratch so indices stay correct across rounds.
        # Reset each tracked list, then replay all add/remove/set calls in document order.
        try:
            _old_lists = {k: list(v) for k, v in list_contents.items()}
            for k in list_contents:
                list_contents[k] = []
            for _, se in tree.filter(jt.StatementExpression):
                if _line_of(se) in dead_lines:
                    continue
                expr = getattr(se, "expression", None)
                if not isinstance(expr, jt.MethodInvocation):
                    continue
                q = str(expr.qualifier or "")
                if q not in list_contents:
                    continue
                lst = list_contents[q]
                args = expr.arguments or []
                if expr.member == "add":
                    if len(args) == 1:
                        if len(lst) <= 32:  # guard against unbounded growth
                            lst.append(_is_tainted(args[0], tainted, const_ints))
                    elif len(args) == 2:
                        idx = _eval_const_expr(args[0], const_ints, const_strings)
                        if idx is not None and 0 <= idx <= len(lst) <= 32:
                            lst.insert(idx, _is_tainted(args[1], tainted, const_ints))
                elif expr.member == "remove":
                    if len(args) == 1:
                        idx = _eval_const_expr(args[0], const_ints, const_strings)
                        if idx is not None and 0 <= idx < len(lst):
                            lst.pop(idx)
                elif expr.member == "set":
                    if len(args) == 2:
                        idx = _eval_const_expr(args[0], const_ints, const_strings)
                        if idx is not None and 0 <= idx < len(lst):
                            lst[idx] = _is_tainted(args[1], tainted, const_ints)
            if list_contents != _old_lists:
                changed = True
        except Exception:
            pass

        try:
            for _, node in tree.filter(jt.ForStatement):
                ctrl = node.control
                if hasattr(ctrl, "var") and hasattr(ctrl, "iterable"):
                    # EnhancedForControl: for (Type var : iterable)
                    if _is_tainted(ctrl.iterable, tainted, const_ints):
                        var_decl = ctrl.var
                        declarators = getattr(var_decl, "declarators", None)
                        if declarators:
                            for d in declarators:
                                if d.name not in tainted:
                                    tainted.add(d.name)
                                    changed = True
                        elif hasattr(var_decl, "name") and var_decl.name not in tainted:
                            tainted.add(var_decl.name)
                            changed = True
        except Exception:
            pass

        if not changed:
            break
    list_tainted_vars: set = {k for k, v in list_contents.items() if any(v)}
    return tainted, list_tainted_vars


def _collect_writers(tree) -> set[str]:
    """Find PrintWriter variable names from response.getWriter() declarations."""
    writers: set[str] = set()
    try:
        for _, node in tree.filter(jt.LocalVariableDeclaration):
            for decl in node.declarators:
                init = decl.initializer
                if isinstance(init, jt.MethodInvocation):
                    if init.member == "getWriter" and str(init.qualifier or "") in _RESPONSE_OBJECTS:
                        writers.add(decl.name)
    except Exception:
        pass
    return writers


def _literal_str(node) -> str | None:
    """Return the string value of a string Literal node (without surrounding quotes)."""
    if not isinstance(node, jt.Literal):
        return None
    v = node.value
    if v and v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    return None


# ── analyzer ───────────────────────────────────────────────────────────────────

class JavaASTAnalyzer(BaseAnalyzer):
    """AST-level analyzer for .java files using javalang."""

    supported_extensions = (".java",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _HAS_JAVALANG:
            return []
        try:
            tree = javalang.parse.parse(content)
        except Exception:
            return []

        lines = content.splitlines()
        tainted, list_tainted_vars = _collect_tainted(tree)
        writers = _collect_writers(tree)
        findings: list[Finding] = []

        def _add(node, vuln_type, severity, rule_id, desc, *, line_override: int = 0):
            ln = line_override or _node_line(node)
            findings.append(Finding(
                vuln_type=vuln_type,
                severity=severity,
                file_path=file_path,
                line_number=ln,
                line_content=lines[ln - 1].strip() if 0 < ln <= len(lines) else "",
                description=desc,
                rule_id=rule_id,
                repo_url=repo_url,
                snippet=self._extract_snippet(lines, ln),
            ))

        # ── SQL injection ──────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member in _SQL_EXEC_METHODS:
                    q = str(node.qualifier or "")
                    # Case 1: arg is tainted  (executeQuery(sql), prepareStatement(sql))
                    flagged = any(_is_tainted(a, tainted) for a in (node.arguments or []))
                    # Case 2: qualifier (statement object) is tainted
                    # e.g. stmt = conn.prepareCall(taintedSql); stmt.executeQuery()
                    if not flagged and q in tainted:
                        flagged = True
                    if flagged:
                        _add(node, VulnType.SQL_INJECTION, Severity.HIGH, "JAST-SQL-001",
                             f"{node.member}() receives user-controlled value — "
                             "SQL injection; use PreparedStatement with parameterized queries")
                elif node.member in _JPA_METHODS:
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SQL_INJECTION, Severity.HIGH, "JAST-SQL-002",
                                 f"JPA {node.member}() with user-controlled string — "
                                 "SQL injection; use named parameters (:param)")
                            break
        except Exception:
            pass

        # ── XSS ───────────────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                # Pattern 1: response.getWriter().println(tainted)
                if node.member == "getWriter" and str(node.qualifier or "") in _RESPONSE_OBJECTS:
                    for sel in (node.selectors or []):
                        if isinstance(sel, jt.MethodInvocation) and sel.member in _XSS_SINK_METHODS:
                            for arg in (sel.arguments or []):
                                if _is_tainted(arg, tainted):
                                    outer_ln = _node_line(node)
                                    _add(node, VulnType.XSS, Severity.HIGH, "JAST-XSS-001",
                                         f"response.getWriter().{sel.member}() with user-controlled value — "
                                         "reflected XSS; encode output with ESAPI or escapeHtml",
                                         line_override=outer_ln)
                                    break

                # Pattern 2: out.println(tainted) where out = response.getWriter()
                if node.member in _XSS_SINK_METHODS and str(node.qualifier or "") in writers:
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.XSS, Severity.HIGH, "JAST-XSS-001",
                                 f"PrintWriter.{node.member}() with user-controlled value — "
                                 "reflected XSS; encode output with ESAPI or escapeHtml")
                            break
        except Exception:
            pass

        # ── Command injection ──────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member == "exec":
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "JAST-CMD-001",
                                 "Runtime.exec() with user-controlled argument — "
                                 "command injection; use allowlisted fixed commands")
                            break
            for _, node in tree.filter(jt.ClassCreator):
                if _type_name(node.type) == "ProcessBuilder":
                    for arg in (node.arguments or []):
                        _arg_name = arg.member if isinstance(arg, jt.MemberReference) else ""
                        if (_is_tainted(arg, tainted)
                                or (_arg_name and _arg_name in list_tainted_vars)):
                            _add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "JAST-CMD-002",
                                 "new ProcessBuilder() with user-controlled argument — "
                                 "command injection; validate and allowlist commands")
                            break
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member == "command":
                    for arg in (node.arguments or []):
                        _arg_name = arg.member if isinstance(arg, jt.MemberReference) else ""
                        if (_is_tainted(arg, tainted)
                                or (_arg_name and _arg_name in list_tainted_vars)):
                            _add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "JAST-CMD-003",
                                 "ProcessBuilder.command() with user-controlled argument — "
                                 "command injection; validate and allowlist commands")
                            break
        except Exception:
            pass

        # ── Path traversal ────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.ClassCreator):
                class_name = _type_name(node.type)
                if class_name in _FILE_CLASSES:
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "JAST-PATH-001",
                                 f"new {class_name}() with user-controlled path — "
                                 "path traversal; canonicalize and validate within allowed root")
                            break
            for _, node in tree.filter(jt.MethodInvocation):
                _pq = str(node.qualifier or "")
                if (node.member in ("get", "of")
                        and (_pq in ("Paths", "Path")
                             or _pq.endswith(".Paths") or _pq.endswith(".Path"))):
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "JAST-PATH-002",
                                 f"Paths.{node.member}() with user-controlled path — "
                                 "path traversal; validate path does not escape allowed directory")
                            break
        except Exception:
            pass

        # ── Weak cryptography — new Random() or Math.random() ────────────────
        try:
            for _, node in tree.filter(jt.ClassCreator):
                if _type_name(node.type) == "Random":
                    _add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "JAST-CRYPTO-001",
                         "new Random() is not cryptographically secure — "
                         "use java.security.SecureRandom for security-sensitive randomness")
        except Exception:
            pass
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member == "random":
                    q = str(node.qualifier or "")
                    # Math.random() or java.lang.Math.random()
                    if q == "Math" or q.endswith(".Math") or q == "java.lang.Math":
                        _add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "JAST-CRYPTO-001B",
                             "Math.random() is not cryptographically secure — "
                             "use java.security.SecureRandom for security-sensitive randomness")
        except Exception:
            pass

        # ── Weak cryptography — MessageDigest.getInstance weak hash ───────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member != "getInstance":
                    continue
                q = str(node.qualifier or "")
                if "MessageDigest" not in q and q != "MessageDigest":
                    continue
                args = node.arguments or []
                if not args:
                    continue
                algo = _literal_str(args[0])
                if algo and algo.upper() in _WEAK_HASH_ALGOS:
                    _add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "JAST-CRYPTO-002",
                         f"MessageDigest.getInstance(\"{algo}\") uses a broken hash algorithm — "
                         "use SHA-256 or stronger")
        except Exception:
            pass

        # ── Weak cryptography — Cipher.getInstance weak cipher ────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member != "getInstance":
                    continue
                q = str(node.qualifier or "")
                if "Cipher" not in q and q != "Cipher":
                    continue
                args = node.arguments or []
                if not args:
                    continue
                algo = _literal_str(args[0])
                if algo:
                    algo_up = algo.upper()
                    if any(algo_up.startswith(p) for p in _WEAK_CIPHER_PREFIXES):
                        _add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "JAST-CRYPTO-003",
                             f"Cipher.getInstance(\"{algo}\") uses a weak/broken cipher — "
                             "use AES/GCM/NoPadding")
        except Exception:
            pass

        # ── LDAP injection ────────────────────────────────────────────────────
        # Only check when the file actually uses javax.naming / DirContext APIs
        _is_ldap_file = any(hint in content for hint in _LDAP_HINTS)
        if _is_ldap_file:
            try:
                for _, node in tree.filter(jt.MethodInvocation):
                    if node.member not in _LDAP_SEARCH_METHODS:
                        continue
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.LDAP_INJECTION, Severity.HIGH, "JAST-LDAP-001",
                                 f".{node.member}() with user-controlled argument — "
                                 "LDAP injection; sanitize input with ESAPI or whitelist")
                            break
            except Exception:
                pass

        # ── SSRF ──────────────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.ClassCreator):
                if _type_name(node.type) == "URL":
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SSRF, Severity.HIGH, "JAST-SSRF-001",
                                 "new URL() with user-controlled string — "
                                 "SSRF; validate scheme/host against an allowlist")
                            break
        except Exception:
            pass

        # ── XXE (always flag — factory needs hardening) ───────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member == "newInstance" and str(node.qualifier or "") in _XXE_FACTORIES:
                    _add(node, VulnType.XXE, Severity.HIGH, "JAST-XXE-001",
                         f"{node.qualifier}.newInstance() without XXE hardening — "
                         "disable external entities with setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)")
        except Exception:
            pass

        # ── Insecure deserialization (always flag) ────────────────────────────
        try:
            for _, node in tree.filter(jt.ClassCreator):
                if _type_name(node.type) in _DESER_CLASSES:
                    _add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL, "JAST-DESER-001",
                         "new ObjectInputStream() — deserializes untrusted data; "
                         "use ObjectInputFilter (Java 9+) or a safe format like JSON")
        except Exception:
            pass

        # ── JNDI injection ────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member == "lookup":
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.JNDI_INJECTION, Severity.CRITICAL, "JAST-JNDI-001",
                                 "JNDI lookup() with user-controlled name — "
                                 "Log4Shell-style injection; never pass user input to JNDI lookup")
                            break
        except Exception:
            pass

        # ── SpEL injection ────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member in _SPEL_METHODS:
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SSTI, Severity.CRITICAL, "JAST-SPEL-001",
                                 "SpEL parseExpression() with user-controlled input — "
                                 "Spring Expression Language injection allows RCE; avoid dynamic SpEL on user data")
                            break
        except Exception:
            pass

        return findings
