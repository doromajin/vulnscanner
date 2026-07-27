"""Java vulnerability analyzer using javalang AST.

Provides taint-aware detection with variable-flow tracking:
  source (request.getParameter) -> local var -> sink (executeQuery)

Falls back gracefully to empty list if javalang is not installed or
the file uses unsupported Java syntax.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
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
    "httpServletRequest", "hreq", "mreq",
})

# Methods that return user-controlled data regardless of what object they're called on.
# Populated from custom_taint_sources.json — no hardcoded values here.
_ANY_QUALIFIER_TAINT_METHODS = _load_custom_taint_sources()

# ── cross-file taint context (thread-local) ────────────────────────────────────

@dataclass
class JavaCrossFileCtx:
    """Indexed method declarations from all Java files in the repo.

    Built once by build_java_cross_file_context() before parallel per-file
    analysis starts, then injected per-worker via set_java_cross_file_context().

    remote_methods maps method_name → [(parsed_tree, file_path)] so that
    _analyze_remote_method() can call _analyze_local_method() on remote trees.

    tainted_callee_params maps method_name → {arg_indices} for methods that
    are called from Spring controllers with @RequestParam/@PathVariable args.
    Used to pre-seed parameter taint in service classes that have no Spring
    annotations of their own.
    """
    remote_methods: dict[str, list[tuple]] = field(default_factory=dict)
    tainted_callee_params: dict[str, set[int]] = field(default_factory=dict)
    # (class_name, method_name) → {param_index → (rule_id, VulnType, Severity, description)}
    sink_registry: dict[str, dict[int, tuple]] = field(default_factory=dict)
    # method_name-only reverse index for variable-qualifier MI lookup (no type inference)
    sink_registry_by_method: dict[str, dict[int, tuple]] = field(default_factory=dict)


_java_cf_local = threading.local()


def build_java_cross_file_context(all_contents: dict[str, str]) -> JavaCrossFileCtx:
    """Pre-parse all .java files and index their MethodDeclarations by name.

    Called once before the thread pool starts so each worker can share the
    read-only context via set_java_cross_file_context().
    """
    if not _HAS_JAVALANG:
        return JavaCrossFileCtx()

    remote_methods: dict[str, list] = {}
    parsed_trees: list[tuple] = []  # (tree, fp) for second pass

    for fp, content in all_contents.items():
        if not fp.endswith(".java"):
            continue
        try:
            tree = javalang.parse.parse(content)
            for _, method in tree.filter(jt.MethodDeclaration):
                name = method.name
                if name not in remote_methods:
                    remote_methods[name] = []
                remote_methods[name].append((tree, fp))
            parsed_trees.append((tree, fp))
        except Exception:
            pass

    # Build a name → [MethodDeclaration, ...] map for fixed-point propagation below.
    method_nodes: dict[str, list] = {}
    for tree, _fp in parsed_trees:
        try:
            for _, method in tree.filter(jt.MethodDeclaration):
                method_nodes.setdefault(method.name, []).append(method)
        except Exception:
            pass

    # Second pass: find controller methods with Spring-annotated params,
    # then record which callee methods are invoked with those tainted params.
    tainted_callee_params: dict[str, set[int]] = {}

    def _propagate_from_method(method, tainted_pnames: set[str]) -> None:
        """Record callee param indices whenever a tainted param is passed as an arg."""
        try:
            for _, invoc in method.filter(jt.MethodInvocation):
                callee = invoc.member
                if not callee:
                    continue
                for idx, arg in enumerate(invoc.arguments or []):
                    arg_name: str | None = None
                    if isinstance(arg, jt.MemberReference) and not arg.qualifier:
                        arg_name = arg.member
                    if arg_name and arg_name in tainted_pnames:
                        if idx not in tainted_callee_params.get(callee, set()):
                            tainted_callee_params.setdefault(callee, set()).add(idx)
        except Exception:
            pass

    # Seed from Spring-annotated controller params (1-hop)
    for tree, _fp in parsed_trees:
        try:
            for _, method in tree.filter(jt.MethodDeclaration):
                spring_params: set[str] = set()
                for param in (method.parameters or []):
                    for ann in (getattr(param, "annotations", None) or []):
                        if getattr(ann, "name", "") in _SPRING_PARAM_ANNOTATIONS:
                            pname = getattr(param, "name", "")
                            if pname:
                                spring_params.add(pname)
                if spring_params:
                    _propagate_from_method(method, spring_params)
        except Exception:
            pass

    # Seed tainted_callee_params from methods that directly receive user input
    # via request.getParameter() etc. and pass it to callee methods.
    # This enables callee JAST rules when the caller is not a Spring controller.
    for tree, _fp in parsed_trees:
        try:
            for _, method in tree.filter(jt.MethodDeclaration):
                _tv: set[str] = set()
                try:
                    for _, lvd in method.filter(jt.LocalVariableDeclaration):
                        for decl in lvd.declarators:
                            init = decl.initializer
                            if init and _is_request_source(init):
                                _tv.add(decl.name)
                            elif (init and isinstance(init, jt.MethodInvocation)
                                  and init.member in _ANY_QUALIFIER_TAINT_METHODS):
                                _tv.add(decl.name)
                except Exception:
                    pass
                if _tv:
                    _propagate_from_method(method, _tv)
        except Exception:
            pass

    # Fixed-point transitive propagation (up to 8 hops)
    for _ in range(8):
        changed = False
        snapshot = {k: set(v) for k, v in tainted_callee_params.items()}
        for mname, tainted_indices in snapshot.items():
            for mnode in method_nodes.get(mname, []):
                params = mnode.parameters or []
                tainted_pnames: set[str] = set()
                for idx in tainted_indices:
                    if idx < len(params):
                        pname = getattr(params[idx], "name", "")
                        if pname:
                            tainted_pnames.add(pname)
                if not tainted_pnames:
                    continue
                before = sum(len(v) for v in tainted_callee_params.values())
                _propagate_from_method(mnode, tainted_pnames)
                after = sum(len(v) for v in tainted_callee_params.values())
                if after > before:
                    changed = True
        if not changed:
            break

    # ── Sink registry: discover methods whose params flow to SQL / path sinks ──
    # Phase 1 — direct: param → JDBC call in the same method body.
    sink_registry: dict[str, dict[int, tuple]] = {}

    def _build_method_sink_params(mnode) -> "dict[int, tuple]":
        """Return {param_idx → sink_info} for params that flow to SQL/path sinks."""
        params = mnode.parameters or []
        if not params or not mnode.body:
            return {}
        pbyn: dict[str, int] = {}
        for idx, p in enumerate(params):
            pn = getattr(p, "name", "")
            if pn:
                pbyn[pn] = idx
        if not pbyn:
            return {}
        # Seed all params as tainted, run 3-iteration mini propagation.
        tl: set[str] = set(pbyn)
        for _ in range(3):
            try:
                for _, lvd in mnode.filter(jt.LocalVariableDeclaration):
                    for decl in lvd.declarators:
                        if decl.name not in tl and decl.initializer:
                            if _is_tainted(decl.initializer, tl):
                                tl.add(decl.name)
            except Exception:
                pass
        result: dict[int, tuple] = {}
        # SQL sinks (JDBC execute methods with tainted args)
        try:
            for _, mi in mnode.filter(jt.MethodInvocation):
                if mi.member not in _JDBC_EXEC_METHODS:
                    continue
                if any(_is_tainted(a, tl) for a in (mi.arguments or [])):
                    for pn, pidx in pbyn.items():
                        if pn in tl:
                            result.setdefault(pidx, (
                                "JAST-SQL-001", VulnType.SQL_INJECTION, Severity.HIGH,
                                f"cross-file: tainted arg passed to {mnode.name}() which"
                                " executes raw SQL — SQL injection; use PreparedStatement",
                            ))
                    break
        except Exception:
            pass
        # Path traversal sinks (File/FileInputStream etc. with tainted arg)
        if not result:
            try:
                for _, cc in mnode.filter(jt.ClassCreator):
                    if _type_name(cc.type) not in _FILE_CLASSES:
                        continue
                    if any(_is_tainted(a, tl) for a in (cc.arguments or [])):
                        for pn, pidx in pbyn.items():
                            if pn in tl:
                                result.setdefault(pidx, (
                                    "JAST-PATH-001", VulnType.PATH_TRAVERSAL, Severity.HIGH,
                                    f"cross-file: tainted arg passed to {mnode.name}() which"
                                    " opens a file — path traversal; validate path",
                                ))
                        break
            except Exception:
                pass
        return result

    for tree, _fp in parsed_trees:
        try:
            for _, cls in tree.filter(jt.ClassDeclaration):
                for method in (cls.methods or []):
                    sr = _build_method_sink_params(method)
                    if sr:
                        sink_registry.setdefault((cls.name, method.name), {}).update(sr)
        except Exception:
            pass

    # Phase 2 — transitive: if M passes its params to a registry sink, M is also a sink.
    # Precompute each method's call sites ONCE to avoid repeated tree.filter() per hop.
    # _p2_data: (cls, method) → {pbyn, tl, cc_calls, mi_calls}
    # cc_calls: [(cc_type, sel_member, sel_args), ...]
    # mi_calls: [(qualifier, mi_member, mi_args), ...]
    _p2_data: dict[tuple, dict] = {}
    for tree, _fp in parsed_trees:
        try:
            for _, cls in tree.filter(jt.ClassDeclaration):
                for method in (cls.methods or []):
                    params = method.parameters or []
                    if not params or not method.body:
                        continue
                    pbyn2: dict[str, int] = {}
                    for idx2, p2 in enumerate(params):
                        pn2 = getattr(p2, "name", "")
                        if pn2:
                            pbyn2[pn2] = idx2
                    if not pbyn2:
                        continue
                    tl2: set[str] = set(pbyn2)
                    try:
                        for _, lvd in method.filter(jt.LocalVariableDeclaration):
                            for decl in lvd.declarators:
                                if decl.name not in tl2 and decl.initializer:
                                    if _is_tainted(decl.initializer, tl2):
                                        tl2.add(decl.name)
                    except Exception:
                        pass
                    cc_calls: list[tuple] = []
                    try:
                        for _, cc in method.filter(jt.ClassCreator):
                            for sel in (cc.selectors or []):
                                if isinstance(sel, jt.MethodInvocation):
                                    cc_calls.append((_type_name(cc.type), sel.member,
                                                     sel.arguments or []))
                    except Exception:
                        pass
                    mi_calls: list[tuple] = []
                    try:
                        for _, mi in method.filter(jt.MethodInvocation):
                            mi_calls.append((str(mi.qualifier or ""), mi.member,
                                             mi.arguments or []))
                    except Exception:
                        pass
                    _p2_data[(cls.name, method.name)] = {
                        "pbyn": pbyn2, "tl": tl2,
                        "cc": cc_calls, "mi": mi_calls,
                    }
        except Exception:
            pass

    # Build name-only reverse index once per hop (rebuilt after each registry update).
    for _hop in range(4):
        _changed_sr = False
        _sr_keys = set(sink_registry.keys())
        # Reverse index: method_name → merged sink params across all classes
        _sr_by_mn: dict[str, dict] = {}
        for (ck, mk), sv in sink_registry.items():
            _sr_by_mn.setdefault(mk, {}).update(sv)

        for (cls_name, method_name), data in _p2_data.items():
            if (cls_name, method_name) in _sr_keys:
                continue
            pbyn2 = data["pbyn"]
            tl2 = data["tl"]
            new_sr: dict[int, tuple] = {}
            # ClassCreator selectors: (new Foo()).knownSink(param) — class is known.
            for _cc_type, sel_member, sel_args in data["cc"]:
                if (_cc_type, sel_member) not in _sr_keys:
                    continue
                for cpidx, sinfo in sink_registry.get((_cc_type, sel_member), {}).items():
                    if cpidx < len(sel_args) and _is_tainted(sel_args[cpidx], tl2):
                        for pn2, pidx2 in pbyn2.items():
                            if pn2 in tl2:
                                new_sr.setdefault(pidx2, sinfo)
            # Plain MIs: uppercase qualifier → exact (class, method); else name-only index.
            for q, mi_member, mi_args in data["mi"]:
                if mi_member not in _sr_by_mn:
                    continue
                candidates = (sink_registry.get((q, mi_member), {})
                              if q and q[0].isupper()
                              else _sr_by_mn.get(mi_member, {}))
                for cpidx, sinfo in candidates.items():
                    if cpidx < len(mi_args) and _is_tainted(mi_args[cpidx], tl2):
                        for pn2, pidx2 in pbyn2.items():
                            if pn2 in tl2:
                                new_sr.setdefault(pidx2, sinfo)
            if new_sr:
                _bef = len(sink_registry.get((cls_name, method_name), {}))
                sink_registry.setdefault((cls_name, method_name), {}).update(new_sr)
                if len(sink_registry[(cls_name, method_name)]) > _bef:
                    _changed_sr = True
        if not _changed_sr:
            break

    # Build name-only reverse index for caller-side variable-qualifier lookups.
    sink_registry_by_method: dict[str, dict] = {}
    for (ck, mk), sv in sink_registry.items():
        sink_registry_by_method.setdefault(mk, {}).update(sv)

    return JavaCrossFileCtx(
        remote_methods=remote_methods,
        tainted_callee_params=tainted_callee_params,
        sink_registry=sink_registry,
        sink_registry_by_method=sink_registry_by_method,
    )


def set_java_cross_file_context(ctx: JavaCrossFileCtx | None) -> None:
    """Store Java cross-file context in thread-local for the current worker."""
    _java_cf_local.ctx = ctx


def _get_java_cf_ctx() -> JavaCrossFileCtx | None:
    return getattr(_java_cf_local, "ctx", None)


# ── sink sets ──────────────────────────────────────────────────────────────────

# Standard JDBC: any tainted argument (or tainted qualifier/statement object) is suspicious.
_JDBC_EXEC_METHODS = frozenset({
    "execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
    "executeBatch", "addBatch", "prepareCall", "prepareStatement",
})

# Spring JdbcTemplate / NamedParameterJdbcTemplate: the first argument is the SQL string;
# subsequent arguments are BOUND parameters (safe).  Only the first arg must be checked.
_SPRING_JDBC_METHODS = frozenset({
    "queryForLong", "queryForInt", "queryForObject", "queryForList",
    "queryForMap", "queryForRowSet", "queryForStream",
    "query", "batchUpdate", "update",
})

_SQL_EXEC_METHODS = _JDBC_EXEC_METHODS | _SPRING_JDBC_METHODS

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

# Spring RestTemplate / WebClient methods: first arg is the URL.
_SPRING_REST_URL_METHODS = frozenset({
    "getForObject", "getForEntity", "postForObject", "postForEntity",
    "postForLocation", "put", "delete", "patchForObject", "exchange",
    "execute",
})
_SPRING_REST_QUALIFIERS = frozenset({
    "restTemplate", "RestTemplate", "rt", "template", "webClient", "WebClient",
})

# HTTP client constructors that take a URL string directly.
_HTTP_CLIENT_URL_CTORS = frozenset({
    "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "HttpHead",
    "HttpOptions",
    "URI",
})

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

# ── Trust Boundary Violation (CWE-501) ────────────────────────────────────────
# session.setAttribute(key, tainted) stores untrusted request data in the HTTP session.
_SESSION_SET_METHODS = frozenset({"setAttribute", "putValue"})
_SESSION_QUALIFIERS = frozenset({
    "session", "httpSession", "sess", "userSession", "req_session",
    "request_session",
})

# ── LDAP ──────────────────────────────────────────────────────────────────────

_LDAP_HINTS = frozenset({
    "DirContext", "InitialDirContext", "LdapContext",
    "javax.naming", "NamingEnumeration",
})

_LDAP_SEARCH_METHODS = frozenset({"search", "lookup", "bind", "getAttributes"})

# ── XPath injection ────────────────────────────────────────────────────────────
# File-level markers that indicate XPath API usage — used to avoid FPs from
# other evaluate()/compile() calls (e.g. JavaScript engines, regex Pattern.compile).
_XPATH_FILE_HINTS = frozenset({
    "XPathFactory", "javax.xml.xpath", "XPathConstants", "XPathExpression",
})

# Sink methods on javax.xml.xpath.XPath and XPathExpression.
# evaluate(expression, context, ...) — first arg is the XPath query string.
# compile(expression) — the expression itself is the sink.
_XPATH_SINK_METHODS = frozenset({"evaluate", "compile"})

# ── Insecure cookie ────────────────────────────────────────────────────────────
# Only flag when the developer explicitly passes false — "missing call" heuristics
# produce too many FPs in real codebases (non-HTTPS dev contexts, non-sensitive
# cookies, etc.).  Explicit setSecure(false) / setHttpOnly(false) is unambiguous.
_COOKIE_FLAG_METHODS = frozenset({"setSecure", "setHttpOnly"})


# Spring MVC: method parameters carrying these annotations receive user-supplied data.
# Equivalent in taint terms to request.getParameter() on the same value.
_SPRING_PARAM_ANNOTATIONS = frozenset({
    "RequestParam", "PathVariable", "RequestBody",
    "RequestHeader", "CookieValue", "MatrixVariable",
    "ModelAttribute",
})

# String-format validation methods whose presence in an if-guard condition
# (followed by throw/return) marks the variable as format-validated (CLEAN).
# Null/empty checks are intentionally excluded: they prove non-null but do
# not sanitize content against injection.
_JAVA_GUARD_VALIDATION_METHODS = frozenset({
    "matches",          # String.matches(regex) — whitelist regex guard
    "isNumeric",        # Apache Commons StringUtils.isNumeric()
    "isAlpha",          # Apache Commons StringUtils.isAlpha()
    "isAlphanumeric",   # Apache Commons StringUtils.isAlphanumeric()
    "isDigitsOnly",     # Android TextUtils.isDigitsOnly()
    "isValid",          # Bean Validation / custom Validator.isValid()
    "validate",         # Custom validation utility
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


def _collect_const_context(tree, properties: "dict | None" = None):
    """Collect constant integer/char/string variable values from the tree.

    Also resolves Properties.getProperty("key", default) calls: if the key
    exists in *properties* (a pre-loaded .properties dict), the runtime value
    is used; otherwise the literal default argument is used as a fallback.

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
                # Properties.getProperty("key", "default") — resolve via loaded .properties
                if isinstance(init, jt.MethodInvocation) and init.member == "getProperty":
                    _gp_args = init.arguments or []
                    if _gp_args:
                        _key = _literal_str(_gp_args[0])
                        _resolved: "str | None" = None
                        if _key and properties:
                            _resolved = properties.get(_key)
                        if _resolved is None and len(_gp_args) >= 2:
                            _resolved = _literal_str(_gp_args[1])
                        if _resolved is not None:
                            const_strings[decl.name] = _resolved
    except Exception:
        pass
    # Track SE-level mutations: x++, x--, x = lit, x += lit, x -= lit, x *= lit.
    # Processed in AST order so increments accumulated after the initial declaration.
    try:
        for _, se in tree.filter(jt.StatementExpression):
            expr = getattr(se, "expression", None)
            if expr is None:
                continue
            if (isinstance(expr, jt.MemberReference)
                    and not (expr.qualifier or "")
                    and expr.member in const_ints):
                ops = (getattr(expr, "postfix_operators", None) or []) + \
                      (getattr(expr, "prefix_operators", None) or [])
                if "++" in ops:
                    const_ints[expr.member] += 1
                elif "--" in ops:
                    const_ints[expr.member] -= 1
            elif (isinstance(expr, jt.Assignment)
                  and isinstance(expr.expressionl, jt.MemberReference)
                  and not (expr.expressionl.qualifier or "")):
                vname = expr.expressionl.member
                rhs_val = _eval_const_expr(expr.value, const_ints, const_strings)
                if rhs_val is not None:
                    op = getattr(expr, "type", "=")
                    if op == "=":
                        const_ints[vname] = rhs_val
                    elif op == "+=" and vname in const_ints:
                        const_ints[vname] += rhs_val
                    elif op == "-=" and vname in const_ints:
                        const_ints[vname] -= rhs_val
                    elif op == "*=" and vname in const_ints:
                        const_ints[vname] *= rhs_val
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
            ln = _pos_line(block)
            if ln > 0:
                dead.add(ln)
        elif isinstance(block, jt.LocalVariableDeclaration):
            ln = _pos_line(block)
            if ln > 0:
                dead.add(ln)
        # Recurse: find all nested StatementExpression nodes (assignments AND method calls)
        try:
            for _, se in block.filter(jt.StatementExpression):
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

# Methods on Collection/Map objects whose return value is a boolean/integer meta-query
# and does NOT expose the underlying data.  Even when called on a tainted collection,
# these do not propagate taint to their result.
_TAINT_SAFE_QUERY_METHODS = frozenset({
    "size", "length", "isEmpty", "contains", "containsKey", "containsValue",
    "hashCode", "indexOf", "lastIndexOf", "equals", "compareTo",
})

# List-mutation methods that add elements (treated like "add" for taint tracking).
_LIST_ADD_METHODS = frozenset({
    "add", "addLast", "addFirst", "push", "offer",
    "offerLast", "offerFirst",
})


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
        # Boolean/numeric query methods never expose underlying collection data
        if node.member in _TAINT_SAFE_QUERY_METHODS:
            return False
        q = str(node.qualifier or "")
        # Propagate through qualifier chain: taintedVar.getValue(), nextElement(), etc.
        if q and q in tainted:
            return True
        if any(_is_tainted(a, tainted, const_ints) for a in (node.arguments or [])):
            return True
        return False
    if isinstance(node, jt.MemberReference):
        if node.member in tainted:
            return True
        q = str(node.qualifier or "")
        if q:
            # obj.field virtual variable: "obj::field" added by post-fixpoint field pass
            if "." not in q and f"{q}::{node.member}" in tainted:
                return True
            # Propagate through chained field access: taintedObj.field1.field2
            # Only triggers when qualifier has a dot (avoids simple obj.field over-tainting).
            if "." in q and q.split(".")[0] in tainted:
                return True
        return False
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


def _is_tainted_raw(node, tainted_raw: "set[str]", const_ints: "dict | None" = None) -> bool:
    """Like _is_tainted but does NOT treat XSS sanitizers as cleaners.
    Used for trust-boundary checks: HTML encoding doesn't fix session storage violation."""
    if node is None:
        return False
    if isinstance(node, jt.MethodInvocation):
        if _is_request_source(node):
            return True
        if node.member in _TAINT_SAFE_QUERY_METHODS:
            return False
        q = str(node.qualifier or "")
        if q and q in tainted_raw:
            return True
        if any(_is_tainted_raw(a, tainted_raw, const_ints) for a in (node.arguments or [])):
            return True
        return False
    if isinstance(node, jt.MemberReference):
        if node.member in tainted_raw:
            return True
        q = str(node.qualifier or "")
        if q and "." not in q and f"{q}::{node.member}" in tainted_raw:
            return True
        return False
    if isinstance(node, jt.BinaryOperation):
        return _is_tainted_raw(node.operandl, tainted_raw, const_ints) or _is_tainted_raw(node.operandr, tainted_raw, const_ints)
    if isinstance(node, jt.Literal):
        return False
    if isinstance(node, jt.ClassCreator):
        return any(_is_tainted_raw(a, tainted_raw, const_ints) for a in (node.arguments or []))
    if isinstance(node, jt.Cast):
        return _is_tainted_raw(node.expression, tainted_raw, const_ints)
    if isinstance(node, jt.TernaryExpression):
        if const_ints is not None:
            cond_val = _eval_const_expr(node.condition, const_ints, {})
            if cond_val is not None:
                branch = node.if_true if cond_val != 0 else node.if_false
                return _is_tainted_raw(branch, tainted_raw, const_ints)
        return _is_tainted_raw(node.if_true, tainted_raw, const_ints) or _is_tainted_raw(node.if_false, tainted_raw, const_ints)
    if hasattr(node, "expression"):
        return _is_tainted_raw(node.expression, tainted_raw, const_ints)
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

            # @sanitizer Javadoc tag marks the method as a sanitizer — always clean output.
            doc = getattr(method, "documentation", None) or ""
            if "@sanitizer" in doc:
                return False

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


def _analyze_remote_method(
    method_name: str,
    call_args: list,
    caller_tainted: "set[str]",
    caller_ci: dict,
) -> "bool | None":
    """Analyze a method defined in another file using the cross-file context.

    Returns True  → at least one remote candidate returns tainted data
            False → all found candidates return safe data
            None  → method not found in remote context (fall through to arg propagation)
    """
    ctx = _get_java_cf_ctx()
    if ctx is None:
        return None
    entries = ctx.remote_methods.get(method_name)
    if not entries:
        return None

    found_any = False
    for (tree, _fp) in entries:
        result = _analyze_local_method(tree, method_name, call_args, caller_tainted, caller_ci)
        if result is True:
            return True
        if result is False:
            found_any = True
        # result is None → this tree has no matching method (shouldn't happen since we
        # indexed by method name, but guard against parse/filter edge cases)
    return False if found_any else None


def _find_setter_field(tree, method_name: str) -> "str | None":
    """Return the instance field name assigned in a single-arg setter, or None.

    Matches the pattern: void methodName(Type p) { this.field = p; }
    In javalang, `this.field = p` has LHS as This{selectors=[MemberReference{field}]}.
    """
    try:
        for _, method in tree.filter(jt.MethodDeclaration):
            if method.name != method_name:
                continue
            params = method.parameters or []
            if len(params) != 1:
                continue
            param_name = getattr(params[0], "name", None)
            if not param_name:
                continue
            if not method.body:
                continue
            for _, stmt in method.filter(jt.StatementExpression):
                expr = getattr(stmt, "expression", None)
                if not isinstance(expr, jt.Assignment):
                    continue
                lhs = expr.expressionl
                rhs = expr.value
                # javalang represents `this.field = p` as This{selectors=[MemberRef{field}]}
                if isinstance(lhs, jt.This):
                    sels = getattr(lhs, "selectors", None) or []
                    if len(sels) == 1 and isinstance(sels[0], jt.MemberReference):
                        field_name = sels[0].member
                        if isinstance(rhs, jt.MemberReference) and rhs.member == param_name:
                            return field_name
    except Exception:
        pass
    return None


def _collect_tainted(tree) -> "tuple[set[str], set[str]]":
    """Multi-pass fixed-point taint collector with dead-branch elimination.

    Handles:
    - LocalVariableDeclaration  (String param = request.getParameter(...))
    - Assignment                (param = request.getHeader(...), re-assignments)
    - ForStatement w/ EnhancedForControl  (for (Cookie c : taintedCookies))
    - Dead-code branches from constant if/switch conditions are skipped
    """
    tainted: set = set()
    # Parallel set: propagates through XSS sanitizers (for trust-boundary checks where
    # HTML encoding doesn't neutralize the session-storage violation).
    tainted_raw: set = set()

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

    # Getter/setter object field taint: {obj_var → set_of_tainted_field_names}
    # When obj.setX(tainted) matches a setter pattern this.field = param, record field.
    # Objects with any tainted field are merged into tainted so obj.getX() propagates.
    obj_field_tainted: dict = {}

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
                            tainted_raw.add(pname)
                        break
    except Exception:
        pass

    # Cross-file callee-param seeding: if this file's methods are called from
    # Spring controllers with tainted args, pre-seed those params as tainted.
    # Enables detection of SQL/CMD sinks in service classes that have no Spring
    # annotations but receive user-controlled data from a controller.
    _cf_ctx = _get_java_cf_ctx()
    if _cf_ctx and _cf_ctx.tainted_callee_params:
        try:
            for _, method in tree.filter(jt.MethodDeclaration):
                tainted_indices = _cf_ctx.tainted_callee_params.get(method.name)
                if not tainted_indices:
                    continue
                params = method.parameters or []
                for idx in tainted_indices:
                    if idx < len(params):
                        pname = getattr(params[idx], "name", "")
                        if pname:
                            tainted.add(pname)
                            tainted_raw.add(pname)
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
                            if result is None:
                                result = _analyze_remote_method(
                                    init.member, init.arguments or [], tainted, const_ints)
                            if result is not None:
                                if result:
                                    tainted.add(decl.name)
                                    changed = True
                                continue  # analysis decided; skip arg-based fallback
                        # this.method(args): javalang represents as This(selectors=[MethodInvocation])
                        if (isinstance(init, jt.This)
                                and init.selectors
                                and isinstance(init.selectors[0], jt.MethodInvocation)):
                            _this_sel = init.selectors[0]
                            if not _is_request_source(_this_sel):
                                _this_result = _analyze_local_method(
                                    tree, _this_sel.member, _this_sel.arguments or [],
                                    tainted, const_ints,
                                )
                                if _this_result is None:
                                    _this_result = _analyze_remote_method(
                                        _this_sel.member, _this_sel.arguments or [],
                                        tainted, const_ints)
                                if _this_result is not None:
                                    if _this_result:
                                        tainted.add(decl.name)
                                        changed = True
                                    continue
                        # Ordered list.get(idx) taint propagation.  If the collection
                        # itself is in tainted (has any tainted element), fall through so
                        # qualifier-in-tainted can fire (over-approximation).
                        _li_inner = init.expression if isinstance(init, jt.Cast) else init
                        if (isinstance(_li_inner, jt.MethodInvocation)
                                and _li_inner.member == "get"
                                and str(_li_inner.qualifier or "") in list_contents):
                            _liq = str(_li_inner.qualifier)
                            _lia = _li_inner.arguments or []
                            _lii_resolved = False
                            if _lia:
                                _lii = _eval_const_expr(_lia[0], const_ints, const_strings)
                                if (_lii is not None
                                        and 0 <= _lii < len(list_contents[_liq])):
                                    _lii_resolved = True
                                    if list_contents[_liq][_lii]:
                                        tainted.add(decl.name); changed = True
                            # Index-resolved: definitive result, skip general propagation.
                            # Unresolved but clean list: also skip (no taint to propagate).
                            if _lii_resolved or _liq not in tainted:
                                continue
                        # Key-matched HashMap.get: (Type) map.get("key").
                        # For literal-key access on a tracked map, key-specific result is
                        # final — do not allow qualifier-in-tainted to override clean keys.
                        _init_mi2 = init.expression if isinstance(init, jt.Cast) else init
                        if (isinstance(_init_mi2, jt.MethodInvocation)
                                and _init_mi2.member in ("get", "getOrDefault")
                                and str(_init_mi2.qualifier or "") in map_tainted_keys):
                            _margs2 = _init_mi2.arguments or []
                            if _margs2 and _literal_str(_margs2[0]) is not None:
                                if _map_get_tainted(init, map_tainted_keys):
                                    tainted.add(decl.name); changed = True
                                continue  # literal-key result is definitive
                        if _map_get_tainted(init, map_tainted_keys):
                            tainted.add(decl.name)
                            changed = True
                            continue
                        # Bare (no-qualifier) local method call: try intra-file analysis first.
                        # This handles @sanitizer-annotated helpers and similar wrappers.
                        if (isinstance(init, jt.MethodInvocation)
                                and init.qualifier == ""
                                and not _is_request_source(init)):
                            _loc_r = _analyze_local_method(
                                tree, init.member, init.arguments or [], tainted, const_ints)
                            if _loc_r is None:
                                _loc_r = _analyze_remote_method(
                                    init.member, init.arguments or [], tainted, const_ints)
                            if _loc_r is not None:
                                if _loc_r:
                                    tainted.add(decl.name); changed = True
                                continue  # analysis was definitive
                        # Cross-file: qualified method call (obj.method() / Class.method())
                        # where the qualifier itself isn't tainted (caught by _is_tainted below).
                        if (isinstance(init, jt.MethodInvocation)
                                and init.qualifier not in (None, "")
                                and not _is_request_source(init)
                                and str(init.qualifier) not in tainted):
                            _rq = _analyze_remote_method(
                                init.member, init.arguments or [], tainted, const_ints)
                            if _rq is True:
                                tainted.add(decl.name)
                                changed = True
                                continue
                        # new Foo().method(args) — ClassCreator with chained MethodInvocation.
                        # _is_tainted(ClassCreator) only checks constructor args, not selectors.
                        # Analyze the chained method's return taint via intra-file analysis.
                        if (isinstance(init, jt.ClassCreator)
                                and init.selectors
                                and isinstance(init.selectors[-1], jt.MethodInvocation)):
                            _ccs = init.selectors[-1]
                            _cc_r = _analyze_local_method(
                                tree, _ccs.member, _ccs.arguments or [], tainted, const_ints)
                            if _cc_r is None:
                                _cc_r = _analyze_remote_method(
                                    _ccs.member, _ccs.arguments or [], tainted, const_ints)
                            if _cc_r is not None:
                                if _cc_r:
                                    tainted.add(decl.name)
                                    changed = True
                                continue
                        if _is_tainted(init, tainted, const_ints):
                            tainted.add(decl.name)
                            tainted_raw.add(decl.name)
                            changed = True
                        elif decl.name not in tainted_raw and _is_tainted_raw(init, tainted_raw, const_ints):
                            tainted_raw.add(decl.name)
                            changed = True
        except Exception:
            pass

        # ForControl uses VariableDeclaration (not LocalVariableDeclaration) for loop vars.
        # e.g.: for(Iterator iter = ll.iterator(); ...) { Object o = iter.next(); }
        # Once the collection is tainted, ll.iterator() is tainted so iter is tainted.
        # Skip LocalVariableDeclaration (subclass of VariableDeclaration) — handled above
        # with the bare-method-call fix; re-processing them here would bypass that fix.
        try:
            for _, node in tree.filter(jt.VariableDeclaration):
                if isinstance(node, jt.LocalVariableDeclaration):
                    continue
                if _line_of(node) in dead_lines:
                    continue
                for decl in (node.declarators or []):
                    if decl.name in tainted or decl.initializer is None:
                        continue
                    if _is_tainted(decl.initializer, tainted, const_ints):
                        tainted.add(decl.name)
                        tainted_raw.add(decl.name)
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
                if str(lhs.qualifier or ""):
                    continue  # skip field assignments (w.value = x); only track bare locals
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
                    # Ordered list.get(idx) taint propagation (see LVD section above).
                    _li_rhs = rhs.expression if isinstance(rhs, jt.Cast) else rhs
                    if (isinstance(_li_rhs, jt.MethodInvocation)
                            and _li_rhs.member == "get"
                            and str(_li_rhs.qualifier or "") in list_contents):
                        _liq2 = str(_li_rhs.qualifier)
                        _lia2 = _li_rhs.arguments or []
                        _lii2_resolved = False
                        if _lia2:
                            _lii2 = _eval_const_expr(_lia2[0], const_ints, const_strings)
                            if (_lii2 is not None
                                    and 0 <= _lii2 < len(list_contents[_liq2])):
                                _lii2_resolved = True
                                if list_contents[_liq2][_lii2]:
                                    tainted.add(_vname); changed = True
                        # Index-resolved: definitive result, skip general propagation.
                        # Unresolved but clean list: also skip.
                        if _lii2_resolved or _liq2 not in tainted:
                            continue
                    # For bare (no-qualifier) static calls, try intra-file return analysis.
                    # qualifier='' → bare call; qualifier=None → new X().m() chain → skip.
                    if (isinstance(rhs, jt.MethodInvocation)
                            and rhs.qualifier == ""
                            and not _is_request_source(rhs)):
                        result = _analyze_local_method(
                            tree, rhs.member, rhs.arguments or [],
                            tainted, const_ints,
                        )
                        if result is None:
                            result = _analyze_remote_method(
                                rhs.member, rhs.arguments or [], tainted, const_ints)
                        if result is not None:
                            if result:
                                tainted.add(_vname)
                                changed = True
                            continue  # analysis decided; skip arg-based fallback
                    # this.method(args) in assignment RHS
                    if (isinstance(rhs, jt.This)
                            and rhs.selectors
                            and isinstance(rhs.selectors[0], jt.MethodInvocation)):
                        _this_rhs = rhs.selectors[0]
                        if not _is_request_source(_this_rhs):
                            _this_r = _analyze_local_method(
                                tree, _this_rhs.member, _this_rhs.arguments or [],
                                tainted, const_ints,
                            )
                            if _this_r is None:
                                _this_r = _analyze_remote_method(
                                    _this_rhs.member, _this_rhs.arguments or [],
                                    tainted, const_ints)
                            if _this_r is not None:
                                if _this_r:
                                    tainted.add(_vname)
                                    changed = True
                                continue
                    # Cross-file: qualified method call (obj.method() / Class.method())
                    if (isinstance(rhs, jt.MethodInvocation)
                            and rhs.qualifier not in (None, "")
                            and not _is_request_source(rhs)
                            and str(rhs.qualifier) not in tainted):
                        _rq2 = _analyze_remote_method(
                            rhs.member, rhs.arguments or [], tainted, const_ints)
                        if _rq2 is True:
                            tainted.add(_vname)
                            changed = True
                            continue
                    # new Foo().method(args) — ClassCreator with chained MethodInvocation.
                    if (isinstance(rhs, jt.ClassCreator)
                            and rhs.selectors
                            and isinstance(rhs.selectors[-1], jt.MethodInvocation)):
                        _ccs2 = rhs.selectors[-1]
                        _cc_r2 = _analyze_local_method(
                            tree, _ccs2.member, _ccs2.arguments or [], tainted, const_ints)
                        if _cc_r2 is None:
                            _cc_r2 = _analyze_remote_method(
                                _ccs2.member, _ccs2.arguments or [], tainted, const_ints)
                        if _cc_r2 is not None:
                            if _cc_r2:
                                tainted.add(_vname)
                                changed = True
                            continue
                    if _is_tainted(rhs, tainted, const_ints):
                        tainted.add(_vname)
                        tainted_raw.add(_vname)
                        changed = True
                    elif _vname not in tainted_raw and _is_tainted_raw(rhs, tainted_raw, const_ints):
                        tainted_raw.add(_vname)
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

        # Track obj.setX(tainted_arg) → obj_field_tainted when setX is a setter pattern.
        try:
            for _, se in tree.filter(jt.StatementExpression):
                if _line_of(se) in dead_lines:
                    continue
                expr = getattr(se, "expression", None)
                if not isinstance(expr, jt.MethodInvocation):
                    continue
                q = str(expr.qualifier or "")
                if not q:
                    continue
                args = expr.arguments or []
                if len(args) != 1:
                    continue
                if not _is_tainted(args[0], tainted, const_ints):
                    continue
                field = _find_setter_field(tree, expr.member)
                if field is not None:
                    obj_fields = obj_field_tainted.setdefault(q, set())
                    if field not in obj_fields:
                        obj_fields.add(field)
                        changed = True
        except Exception:
            pass

        # Rebuild list_contents from scratch so indices stay correct across rounds.
        # Reset each tracked list, then replay all mutation calls in document order.
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
                if expr.member in _LIST_ADD_METHODS:
                    if len(args) == 1:
                        if len(lst) <= 32:
                            lst.append(_is_tainted(args[0], tainted, const_ints))
                    elif len(args) == 2 and expr.member == "add":
                        # add(index, element)
                        idx = _eval_const_expr(args[0], const_ints, const_strings)
                        if idx is not None and 0 <= idx <= len(lst) <= 32:
                            lst.insert(idx, _is_tainted(args[1], tainted, const_ints))
                elif expr.member == "addAll":
                    # addAll(otherColl): propagate if source collection is tainted
                    if args:
                        src_name = args[0].member if isinstance(args[0], jt.MemberReference) else ""
                        src_tainted = (
                            _is_tainted(args[0], tainted, const_ints)
                            or (src_name and any(list_contents.get(src_name, [])))
                        )
                        if src_tainted and len(lst) <= 32:
                            lst.append(True)
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

        # Merge collection vars that contain any tainted element into the main tainted set.
        # This enables _is_tainted to propagate through coll.getLast(), coll.iterator(),
        # coll.toArray(), etc. in subsequent iterations and inline sink argument checks.
        for k, v in list_contents.items():
            if any(v) and k not in tainted:
                tainted.add(k)
                changed = True

        # Merge objects with any tainted field into tainted so obj.getX() propagates.
        for obj_var, fields in obj_field_tainted.items():
            if fields and obj_var not in tainted:
                tainted.add(obj_var)
                changed = True

        # Merge maps with any tainted value into tainted so m.entrySet().iterator() propagates.
        for m_var, m_keys in map_tainted_keys.items():
            if m_keys and m_var not in tainted:
                tainted.add(m_var)
                changed = True

        if not changed:
            break

    list_tainted_vars: set = {k for k, v in list_contents.items() if any(v)}

    # Strong update cleanup: if a LOCAL variable's last recorded assignment is a clean
    # literal, it is no longer tainted.  Only applies to local variables — instance
    # fields may be concurrently written by other threads so we never clean them.
    #
    # Cross-method guard: only discard when the clean assignment and the taint
    # assignment are in the same method scope.  A clean `data = "foo"` in good()
    # must not cancel taint established by `data = request.getParameter()` in bad().
    try:
        _su_mstarts = sorted(
            pos.line
            for _, _m in tree.filter(jt.MethodDeclaration)
            if (pos := getattr(_m, "position", None)) is not None
        )
    except Exception:
        _su_mstarts = []

    def _su_method_idx(ln: int) -> int:
        """Return which method (0-based index) the given line falls in."""
        idx = -1
        for i, s in enumerate(_su_mstarts):
            if ln >= s:
                idx = i
            else:
                break
        return idx

    try:
        local_vars: set = set()
        last_taint_line: dict = {}
        last_clean_line: dict = {}
        for _, lvd in tree.filter(jt.LocalVariableDeclaration):
            ln = _line_of(lvd)
            for decl in lvd.declarators:
                vn = decl.name
                local_vars.add(vn)
                # Only count as a taint line when the LVD has a tainted initializer.
                # A bare `String data;` with no init is NOT a taint assignment; treating
                # it as one causes scope-insensitive contamination to poison last_taint_line
                # with the declaration line of the good()-method variable, which then
                # makes the strong update incorrectly discard taint from bad().
                if (vn in tainted and decl.initializer is not None
                        and _is_tainted(decl.initializer, tainted, const_ints)):
                    last_taint_line[vn] = ln

        # Collect SE lines inside IfStatement branches: conditional assignments must not
        # count as "last clean line" — they only execute on one path, so they cannot
        # guarantee the variable is clean after the if-statement.
        # This fixes two patterns from OWASP Benchmark:
        #   (1) if (param == null) param = "";   — null-guard after request.getParameter()
        #   (2) else bar = "literal";            — dead else branch of a constant condition
        _cond_se_lines: set = set()
        try:
            for _, _if in tree.filter(jt.IfStatement):
                for _blk in (_if.then_statement, _if.else_statement):
                    if _blk is None:
                        continue
                    if isinstance(_blk, jt.StatementExpression):
                        _bl = _line_of(_blk)
                        if _bl > 0:
                            _cond_se_lines.add(_bl)
                    else:
                        try:
                            for _, _se2 in _blk.filter(jt.StatementExpression):
                                _bl = _line_of(_se2)
                                if _bl > 0:
                                    _cond_se_lines.add(_bl)
                        except Exception:
                            pass
        except Exception:
            pass

        for _, se in tree.filter(jt.StatementExpression):
            if not isinstance(getattr(se, "expression", None), jt.Assignment):
                continue
            assign = se.expression
            lhs = assign.expressionl
            if not isinstance(lhs, jt.MemberReference):
                continue
            vn = lhs.member
            if vn not in local_vars:
                continue  # Only apply strong update to local variables
            ln = _line_of(se)
            # Skip dead branches and conditional branches for clean-assignment tracking.
            # Dead branches (dead_lines) were never executed; conditional branches only
            # execute on one path — neither can guarantee the variable ends up clean.
            is_conditional = ln in _cond_se_lines or ln in dead_lines
            if isinstance(assign.value, jt.Literal):
                if not is_conditional:
                    last_clean_line[vn] = max(last_clean_line.get(vn, 0), ln)
            elif not _is_tainted(assign.value, tainted, const_ints):
                # RHS is provably clean (e.g. iter = cleanColl.iterator())
                if not is_conditional:
                    last_clean_line[vn] = max(last_clean_line.get(vn, 0), ln)
            else:
                last_taint_line[vn] = max(last_taint_line.get(vn, 0), ln)
        for vn in list(tainted):
            if vn not in local_vars:
                continue
            c_line = last_clean_line.get(vn, -1)
            t_line = last_taint_line.get(vn, -1)
            # Apply strong update only when both assignments are in the same method scope.
            if c_line > t_line and _su_method_idx(c_line) == _su_method_idx(t_line):
                tainted.discard(vn)
    except Exception:
        pass

    return tainted, list_tainted_vars, dead_lines, tainted_raw


def _compute_method_local_clean(
    tree, tainted: set, const_ints: dict, dead_lines: set
) -> "tuple[dict[int, set[str]], list[int]]":
    """Compute per-method local clean status for globally tainted variables.

    Returns (method_local_clean, mstarts) where:
      method_local_clean[method_idx] = set of var names that are locally clean
        in that method — meaning all local assignments to them are clean literals
        (or provably non-tainted) with NO taint assignment anywhere in the method.

    A variable is locally clean in method M when:
    - It is in the global tainted set (due to scope contamination from another method)
    - But within M, every assignment is a literal or provably-clean value
    - AND M has no taint assignment (request source, readLine, etc.) for that variable

    This handles the Juliet goodG2B() pattern: `data = "foo"` after scope contamination
    from bad()'s `data = request.getParameter("name")`.  The per-method check suppresses
    the sink finding in goodG2B() while keeping the TP in bad().
    """
    try:
        mstarts: list = sorted(
            pos.line
            for _, m in tree.filter(jt.MethodDeclaration)
            if (pos := getattr(m, "position", None)) is not None
        )
    except Exception:
        return {}, []

    if not mstarts:
        return {}, []

    def _midx(ln: int) -> int:
        idx = -1
        for i, s in enumerate(mstarts):
            if ln >= s:
                idx = i
            else:
                break
        return idx

    _has_literal_pm: dict = {}   # (vn, midx) -> True if any literal assignment
    _has_taint_pm: dict = {}     # (vn, midx) -> True if any taint assignment
    _taint_inits: dict = {}      # (vn, midx) -> list[node] — init nodes that triggered taint

    try:
        for _, lvd in tree.filter(jt.LocalVariableDeclaration):
            ln = getattr(getattr(lvd, "position", None), "line", -1)
            if ln < 0 or ln in dead_lines:
                continue
            m = _midx(ln)
            if m < 0:
                continue
            for decl in lvd.declarators:
                vn = decl.name
                if vn not in tainted:
                    continue
                init = decl.initializer
                if init is None:
                    continue
                if isinstance(init, jt.Literal):
                    _has_literal_pm[(vn, m)] = True
                elif _is_tainted(init, tainted, const_ints):
                    _has_taint_pm[(vn, m)] = True
                    _taint_inits.setdefault((vn, m), []).append(init)
    except Exception:
        pass

    try:
        for _, se in tree.filter(jt.StatementExpression):
            if not isinstance(getattr(se, "expression", None), jt.Assignment):
                continue
            ln = getattr(getattr(se, "position", None), "line", -1)
            if ln < 0 or ln in dead_lines:
                continue
            m = _midx(ln)
            if m < 0:
                continue
            assign = se.expression
            lhs = assign.expressionl
            if not isinstance(lhs, jt.MemberReference) or str(lhs.qualifier or ""):
                continue
            vn = lhs.member
            if vn not in tainted:
                continue
            rhs = assign.value
            if isinstance(rhs, jt.Literal):
                _has_literal_pm[(vn, m)] = True
            elif _is_tainted(rhs, tainted, const_ints):
                _has_taint_pm[(vn, m)] = True
                _taint_inits.setdefault((vn, m), []).append(rhs)
    except Exception:
        pass

    # Spring @RequestParam / @PathVariable: treat the method's own annotation-seeded
    # params as having a taint source in that method.
    try:
        for _, method in tree.filter(jt.MethodDeclaration):
            m_ln = getattr(getattr(method, "position", None), "line", -1)
            if m_ln < 0:
                continue
            m = _midx(m_ln)
            if m < 0:
                continue
            for param in (method.parameters or []):
                for ann in (getattr(param, "annotations", None) or []):
                    if getattr(ann, "name", "") in _SPRING_PARAM_ANNOTATIONS:
                        pname = getattr(param, "name", "")
                        if pname and pname in tainted:
                            _has_taint_pm[(pname, m)] = True
                            # No _taint_inits entry → direct source, never re-classifiable
                        break
    except Exception:
        pass

    method_local_clean: dict = {}
    all_keys = set(_has_literal_pm) | set(_has_taint_pm)
    for (vn, m) in all_keys:
        if _has_taint_pm.get((vn, m)):
            continue  # taint present in this method → re-evaluated below
        if _has_literal_pm.get((vn, m)):
            method_local_clean.setdefault(m, set()).add(vn)

    # Transitive propagation: if a var's taint init nodes are only tainted via
    # other locally-clean vars in the same method, it is also locally clean.
    # Example: data="foo" (clean) → file=new File(root+data) should also be clean.
    # Only (vn,m) pairs in _taint_inits are candidates; Spring annotations are excluded
    # because they have no _taint_inits entry (direct source, always tainted).
    try:
        changed = True
        _max_iters = 20  # safety cap (fixpoint reached in O(chain-depth) iters)
        while changed and _max_iters > 0:
            changed = False
            _max_iters -= 1
            for (vn, m), nodes_list in _taint_inits.items():
                if vn in method_local_clean.get(m, set()):
                    continue  # already locally clean
                local_clean_m = method_local_clean.get(m, set())
                effective_tainted = tainted - local_clean_m
                if not any(_is_tainted(n, effective_tainted, const_ints)
                           for n in nodes_list):
                    method_local_clean.setdefault(m, set()).add(vn)
                    changed = True
    except Exception:
        pass

    # Pass 2 — Collection clean: a collection variable freshly initialized in a method
    # (new ArrayList<>() etc.) with no tainted add() in that method scope is locally clean.
    # Uses the per-method clean set from Pass 1 to correctly classify add() arguments.
    # Collection type names that qualify for the "fresh collection" clean check.
    _COLL_TYPE_NAMES = frozenset({
        "ArrayList", "LinkedList", "Vector", "HashSet", "LinkedHashSet", "TreeSet",
        "ArrayDeque", "PriorityQueue", "HashMap", "LinkedHashMap", "TreeMap",
        "Hashtable", "ConcurrentHashMap", "CopyOnWriteArrayList",
    })
    _fresh_coll: dict[tuple, bool] = {}
    try:
        for _, lvd in tree.filter(jt.LocalVariableDeclaration):
            ln = getattr(getattr(lvd, "position", None), "line", -1)
            if ln < 0 or ln in dead_lines:
                continue
            m = _midx(ln)
            if m < 0:
                continue
            for decl in lvd.declarators:
                vn = decl.name
                if vn not in tainted:
                    continue
                init = decl.initializer
                if (isinstance(init, jt.ClassCreator)
                        and _type_name(init.type) in _COLL_TYPE_NAMES
                        and not _is_tainted(init, tainted, const_ints)):
                    _fresh_coll[(vn, m)] = True
    except Exception:
        pass

    _tainted_adds: dict[tuple, bool] = {}
    try:
        for _, se in tree.filter(jt.StatementExpression):
            if not isinstance(getattr(se, "expression", None), jt.MethodInvocation):
                continue
            mi = se.expression
            if mi.member not in ("add", "addAll", "set", "put"):
                continue
            ln = getattr(getattr(se, "position", None), "line", -1)
            if ln < 0 or ln in dead_lines:
                continue
            m = _midx(ln)
            if m < 0:
                continue
            q = str(mi.qualifier or "")
            if not q or (q, m) not in _fresh_coll:
                continue
            args = mi.arguments or []
            chk_idx = 1 if mi.member == "add" and len(args) == 2 else 0
            if chk_idx >= len(args):
                continue
            eff_tainted_m = tainted - method_local_clean.get(m, set())
            if _is_tainted(args[chk_idx], eff_tainted_m, const_ints):
                _tainted_adds[(q, m)] = True
    except Exception:
        pass

    for (vn, m) in _fresh_coll:
        if not _tainted_adds.get((vn, m)) and not _has_taint_pm.get((vn, m)):
            method_local_clean.setdefault(m, set()).add(vn)

    return method_local_clean, mstarts


def _collect_writers(tree) -> set[str]:
    """Find PrintWriter variable names from response.getWriter() assignments."""
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
    # Also catch instance field assignments: writer = resp.getWriter();
    try:
        for _, se in tree.filter(jt.StatementExpression):
            expr = getattr(se, "expression", None)
            if not isinstance(expr, jt.Assignment):
                continue
            lhs = expr.expressionl
            rhs = expr.value
            if not isinstance(lhs, jt.MemberReference) or str(lhs.qualifier or ""):
                continue  # only simple bare names (no qualifier = not this.field explicitly)
            if isinstance(rhs, jt.MethodInvocation):
                if rhs.member == "getWriter" and str(rhs.qualifier or "") in _RESPONSE_OBJECTS:
                    writers.add(lhs.member)
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


def _algo_str(node, const_strings: dict) -> str | None:
    """Resolve an algorithm string from a literal node or a const-tracked variable."""
    lit = _literal_str(node)
    if lit is not None:
        return lit
    if isinstance(node, jt.MemberReference):
        return const_strings.get(node.member)
    return None


def _load_properties_files(file_path_str: str) -> dict:
    """Load key→value pairs from .properties files found near file_path.

    Walks up from file_path until a project root marker is found (pom.xml,
    build.gradle, or src/), then rglob-scans for *.properties files.
    Returns a merged dict; later files' keys override earlier ones.

    Returns an empty dict if file_path_str does not resolve to a real file
    (e.g. when the scanner passes a relative path stripped of the project root).
    """
    props: dict = {}
    try:
        resolved = Path(file_path_str).resolve()
        if not resolved.is_file():
            return props
        search_root = resolved.parent
        for _ in range(12):
            if any((search_root / m).exists() for m in ("pom.xml", "build.gradle", "src")):
                break
            parent = search_root.parent
            if parent == search_root:
                break
            search_root = parent
        for pf in search_root.rglob("*.properties"):
            try:
                for raw_line in pf.read_text(encoding="utf-8", errors="replace").splitlines():  # vulnscanner: ignore[AST-PATH-004]
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    props[k.strip()] = v.strip()
            except Exception:
                pass
    except Exception:
        pass
    return props


# ── analyzer ───────────────────────────────────────────────────────────────────

def _collect_java_guards(tree) -> "set[str]":
    """Return names of variables format-validated by early-exit IfStatement guards.

    Recognized patterns (body must throw or return; no else allowed):
      if (!var.matches("[a-zA-Z0-9]+"))  { throw ... }  — whitelist regex
      if (!StringUtils.isNumeric(var))   { throw ... }  — numeric utility
      if (var == null || !var.matches(r)) { return; }   — combined null+regex

    Only format-validation methods from _JAVA_GUARD_VALIDATION_METHODS suppress
    taint.  Null/empty-only checks do not count as sanitization.
    """
    if not _HAS_JAVALANG:
        return set()
    guarded: set = set()

    def _has_exit(then_stmt) -> bool:
        """True if then_stmt is or contains a throw or return."""
        if then_stmt is None:
            return False
        stmts = getattr(then_stmt, "statements", None)
        if stmts is not None:
            return any(isinstance(s, (jt.ThrowStatement, jt.ReturnStatement)) for s in stmts)
        return isinstance(then_stmt, (jt.ThrowStatement, jt.ReturnStatement))

    def _vars_from_cond(cond) -> "set[str]":
        """Recursively collect validated variable names from an IfStatement condition."""
        if cond is None:
            return set()
        result: set = set()
        if isinstance(cond, jt.MethodInvocation):
            q = str(cond.qualifier or "")
            if q and cond.member in _JAVA_GUARD_VALIDATION_METHODS:
                result.add(q)
            # Also check if the method itself is a static validator: isNumeric(var)
            for arg in (cond.arguments or []):
                if isinstance(arg, jt.MemberReference) and not arg.qualifier:
                    if cond.member in _JAVA_GUARD_VALIDATION_METHODS:
                        result.add(arg.member)
        elif isinstance(cond, jt.BinaryOperation) and cond.operator in ("||", "&&"):
            result.update(_vars_from_cond(cond.operandl))
            result.update(_vars_from_cond(cond.operandr))
        return result

    try:
        for _, if_node in tree.filter(jt.IfStatement):
            if if_node.else_statement:
                continue
            if not _has_exit(if_node.then_statement):
                continue
            guarded.update(_vars_from_cond(if_node.condition))
    except Exception:
        pass

    return guarded


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
        _props = _load_properties_files(file_path)
        tainted, list_tainted_vars, dead_lines, tainted_raw = _collect_tainted(tree)
        # Remove format-validated variables (guarded by early-exit if-throw/return).
        # These are provably safe after the guard; keeping them in tainted causes FP.
        tainted -= _collect_java_guards(tree)
        writers = _collect_writers(tree)
        _const_ints, _const_strings = _collect_const_context(tree, _props)

        # Per-method local clean set: suppress findings where a tainted variable has
        # only clean (literal) assignments in the sink's method and no taint source.
        # This handles scope-insensitive contamination across bad()/good() methods.
        _mlc, _mstarts_mlc = _compute_method_local_clean(
            tree, tainted, _const_ints, dead_lines
        )
        _eff_cache: dict = {}

        def _eff_tainted(node_or_line) -> set:
            """Return effective tainted set with locally clean vars removed.

            Accepts either a javalang node (line extracted via _node_line) or
            an integer line number directly (for ClassCreator which needs the
            pre-computed ancestor-walk line).
            """
            if not _mlc:
                return tainted
            ln = node_or_line if isinstance(node_or_line, int) else _node_line(node_or_line)
            if ln < 0:
                return tainted
            midx = -1
            for i, s in enumerate(_mstarts_mlc):
                if ln >= s:
                    midx = i
                else:
                    break
            if midx < 0 or midx not in _mlc:
                return tainted
            if midx not in _eff_cache:
                _eff_cache[midx] = tainted - _mlc[midx]
            return _eff_cache[midx]

        # ── Post-fixpoint: field-level taint with strong updates ──────────────
        # Process obj.field = expr in AST (source) order so that
        # "w.value = tainted; w.value = clean" nets out as clean.
        # Uses "obj::field" virtual names in tainted — matched by _is_tainted.
        try:
            for _, _se in tree.filter(jt.StatementExpression):
                if _node_line(_se) in dead_lines:
                    continue
                _fexpr = getattr(_se, "expression", None)
                if not isinstance(_fexpr, jt.Assignment):
                    continue
                _flhs = _fexpr.expressionl
                if not isinstance(_flhs, jt.MemberReference):
                    continue
                _fq = str(_flhs.qualifier or "")
                if not _fq or "." in _fq:
                    continue  # only simple one-level obj.field
                _vkey = f"{_fq}::{_flhs.member}"
                if _is_tainted(_fexpr.value, tainted, _const_ints):
                    tainted.add(_vkey)
                elif _vkey in tainted:
                    tainted.discard(_vkey)  # strong update: overwritten with clean value
        except Exception:
            pass

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
                if _node_line(node) in dead_lines:
                    continue
                q = str(node.qualifier or "")
                if node.member in _JDBC_EXEC_METHODS:
                    # Case 1: any tainted arg  (executeQuery(sql), prepareStatement(sql), addBatch(sql))
                    _et = _eff_tainted(node)
                    flagged = any(_is_tainted(a, _et) for a in (node.arguments or []))
                    # Case 2: tainted qualifier/statement object
                    # e.g. stmt = conn.prepareCall(taintedSql); stmt.executeQuery()
                    if not flagged and q in _et:
                        flagged = True
                    if flagged:
                        _add(node, VulnType.SQL_INJECTION, Severity.HIGH, "JAST-SQL-001",
                             f"{node.member}() receives user-controlled value — "
                             "SQL injection; use PreparedStatement with parameterized queries")
                    else:
                        # AST determined safe via per-method clean analysis; emit suppression
                        # sentinel so the generic SQL-001 regex finding is dropped at this line.
                        _would_fire = (any(_is_tainted(a, tainted) for a in (node.arguments or []))
                                       or q in tainted)
                        if _would_fire:
                            _add(node, VulnType.SQL_INJECTION, Severity.LOW, "JAST-SQL-SAFE",
                                 "safe — method-local clean analysis")
                elif node.member in _SPRING_JDBC_METHODS:
                    # Only the FIRST argument is the SQL string; subsequent args are bound
                    # parameters and are safe (e.g. queryForObject(sql, type, param...)).
                    first_arg = (node.arguments or [None])[0]
                    if first_arg is not None and _is_tainted(first_arg, _eff_tainted(node)):
                        _add(node, VulnType.SQL_INJECTION, Severity.HIGH, "JAST-SQL-001",
                             f"Spring JdbcTemplate.{node.member}() SQL argument is user-controlled — "
                             "SQL injection; use '?' placeholders with bound parameters")
                elif node.member in _JPA_METHODS:
                    _et = _eff_tainted(node)
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, _et):
                            _add(node, VulnType.SQL_INJECTION, Severity.HIGH, "JAST-SQL-002",
                                 f"JPA {node.member}() with user-controlled string — "
                                 "SQL injection; use named parameters (:param)")
                            break
        except Exception:
            pass

        # ── XSS ───────────────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
                # Pattern 1: response.getWriter().println(tainted)
                if node.member == "getWriter" and str(node.qualifier or "") in _RESPONSE_OBJECTS:
                    _et = _eff_tainted(node)
                    for sel in (node.selectors or []):
                        if isinstance(sel, jt.MethodInvocation) and sel.member in _XSS_SINK_METHODS:
                            for arg in (sel.arguments or []):
                                if _is_tainted(arg, _et):
                                    outer_ln = _node_line(node)
                                    _add(node, VulnType.XSS, Severity.HIGH, "JAST-XSS-001",
                                         f"response.getWriter().{sel.member}() with user-controlled value — "
                                         "reflected XSS; encode output with ESAPI or escapeHtml",
                                         line_override=outer_ln)
                                    break

                # Pattern 2: out.println(tainted) where out = response.getWriter()
                if node.member in _XSS_SINK_METHODS and str(node.qualifier or "") in writers:
                    _et = _eff_tainted(node)
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, _et):
                            _add(node, VulnType.XSS, Severity.HIGH, "JAST-XSS-001",
                                 f"PrintWriter.{node.member}() with user-controlled value — "
                                 "reflected XSS; encode output with ESAPI or escapeHtml")
                            break
        except Exception:
            pass

        # ── Open Redirect ─────────────────────────────────────────────────────
        # resp.sendRedirect(tainted) / resp.setHeader("Location", tainted)
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
                q = str(node.qualifier or "")
                if node.member == "sendRedirect" and q in _RESPONSE_OBJECTS:
                    args = node.arguments or []
                    if args and _is_tainted(args[0], tainted):
                        _add(node, VulnType.OPEN_REDIRECT, Severity.HIGH, "JAST-REDIRECT-001",
                             "response.sendRedirect() with user-controlled URL — open redirect; "
                             "validate against a whitelist of allowed destinations")
        except Exception:
            pass

        # ── Log injection ──────────────────────────────────────────────────────
        # Covers SLF4J (logger.info/warn/error/debug), java.util.logging (log.info),
        # Log4j, and common logger variable names.
        _LOG_SINK_METHODS = frozenset({"info", "warn", "warning", "error", "debug",
                                       "trace", "fatal", "log", "severe", "fine"})
        _LOG_QUALIFIER_HINTS = frozenset({"log", "logger", "LOG", "LOGGER",
                                          "logging", "log4j"})
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
                if node.member not in _LOG_SINK_METHODS:
                    continue
                q = str(node.qualifier or "")
                if not (q in _LOG_QUALIFIER_HINTS or q.lower().endswith("log")
                        or q.lower().endswith("logger")):
                    continue
                for arg in (node.arguments or []):
                    if _is_tainted(arg, tainted):
                        _add(node, VulnType.LOG_INJECTION, Severity.MEDIUM, "JAST-LOG-001",
                             f"{q}.{node.member}() logs user-controlled data — log forging "
                             "via newline injection; strip \\n/\\r or use structured logging")
                        break
        except Exception:
            pass

        # ── Trust Boundary Violation (CWE-501) ────────────────────────────────
        # session.setAttribute(key, tainted) — untrusted request data stored in session.
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
                if node.member not in _SESSION_SET_METHODS:
                    continue
                q = str(node.qualifier or "")
                # qualifier=="" means chained call: request.getSession().setAttribute(...)
                if not (not q
                        or q in _SESSION_QUALIFIERS
                        or "session" in q.lower()):
                    continue
                args = node.arguments or []
                # Use tainted_raw: HTML encoding doesn't fix session-storage violations.
                key_tainted = len(args) >= 1 and (
                    _is_tainted(args[0], tainted) or _is_tainted_raw(args[0], tainted_raw, _const_ints))
                val_tainted = len(args) >= 2 and (
                    _is_tainted(args[1], tainted) or _is_tainted_raw(args[1], tainted_raw, _const_ints))
                if key_tainted or val_tainted:
                    which = "key" if key_tainted else "value"
                    _add(node, VulnType.TRUST_BOUNDARY_VIOLATION, Severity.MEDIUM, "JAST-TBV-001",
                         f"session.{node.member}() with user-controlled {which} — "
                         "storing untrusted request data in session (CWE-501); validate before storing")
        except Exception:
            pass

        # ── Command injection ──────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
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
            for _cc_path, node in tree.filter(jt.ClassCreator):
                # javalang ClassCreator nodes often have position=None; fall back to
                # the nearest ancestor that carries a line number.
                _cc_line = _node_line(node)
                if not _cc_line:
                    for _anc in reversed(_cc_path):
                        _cc_line = _node_line(_anc)
                        if _cc_line:
                            break
                if _cc_line in dead_lines:
                    continue
                class_name = _type_name(node.type)
                if class_name in _FILE_CLASSES:
                    _et_cc = _eff_tainted(_cc_line)
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, _et_cc):
                            _add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "JAST-PATH-001",
                                 f"new {class_name}() with user-controlled path — "
                                 "path traversal; canonicalize and validate within allowed root",
                                 line_override=_cc_line)
                            break
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
                _pq = str(node.qualifier or "")
                if (node.member in ("get", "of")
                        and (_pq in ("Paths", "Path")
                             or _pq.endswith(".Paths") or _pq.endswith(".Path"))):
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, _eff_tainted(node)):
                            _add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "JAST-PATH-002",
                                 f"Paths.{node.member}() with user-controlled path — "
                                 "path traversal; validate path does not escape allowed directory")
                            break
        except Exception:
            pass

        # ── Cross-file interprocedural sink detection ─────────────────────────
        # Pattern A: (new Foo()).sink(data) — ClassCreator with selector.
        # Pattern B: Foo foo = new Foo(); foo.sink(data) — variable-qualified MI.
        # Both patterns use sink_registry keyed by (class_name, method_name).
        _cf_sr = _get_java_cf_ctx()
        if _cf_sr and _cf_sr.sink_registry:
            # Build (var_name, method_idx) → class_name for pattern B.
            # Method index is the same as _eff_tainted uses, giving per-method scope.
            _var_type_mid: dict = {}
            try:
                for _, _vtm_lvd in tree.filter(jt.LocalVariableDeclaration):
                    _vtm_ln = getattr(getattr(_vtm_lvd, "position", None), "line", -1)
                    if _vtm_ln < 0 or _vtm_ln in dead_lines:
                        continue
                    _vtm_midx = -1
                    for _vi, _vs in enumerate(_mstarts_mlc):
                        if _vtm_ln >= _vs:
                            _vtm_midx = _vi
                        else:
                            break
                    if _vtm_midx < 0:
                        continue
                    for _vtm_decl in _vtm_lvd.declarators:
                        _vtm_init = _vtm_decl.initializer
                        if isinstance(_vtm_init, jt.ClassCreator):
                            _var_type_mid[(_vtm_decl.name, _vtm_midx)] = _type_name(_vtm_init.type)
            except Exception:
                pass

            # Pattern A
            try:
                for _cfi_path, _cfi_node in tree.filter(jt.ClassCreator):
                    for _cfi_sel in (_cfi_node.selectors or []):
                        if not isinstance(_cfi_sel, jt.MethodInvocation):
                            continue
                        _callee_sinks = _cf_sr.sink_registry.get(
                            (_type_name(_cfi_node.type), _cfi_sel.member)
                        )
                        if not _callee_sinks:
                            continue
                        # ClassCreator nodes often have no position; walk ancestors.
                        _cfi_line = _node_line(_cfi_node)
                        if not _cfi_line:
                            for _cfi_anc in reversed(_cfi_path):
                                _cfi_line = _node_line(_cfi_anc)
                                if _cfi_line:
                                    break
                        if _cfi_line in dead_lines:
                            continue
                        _et_cfi = _eff_tainted(_cfi_line)
                        _cfi_args = _cfi_sel.arguments or []
                        for _cfi_pidx, (_cfi_rid, _cfi_vt, _cfi_sv, _cfi_desc) in _callee_sinks.items():
                            if _cfi_pidx < len(_cfi_args) and _is_tainted(_cfi_args[_cfi_pidx], _et_cfi):
                                _add(_cfi_node, _cfi_vt, _cfi_sv, _cfi_rid, _cfi_desc,
                                     line_override=_cfi_line)
                                break
            except Exception:
                pass

            # Pattern B: obj.method(data) where obj was declared as new Foo().
            if _var_type_mid:
                _sr_mn_b = _cf_sr.sink_registry_by_method  # pre-built name-only index
                try:
                    for _mi2_path, _mi2_node in tree.filter(jt.MethodInvocation):
                        if _mi2_node.member not in _sr_mn_b:  # O(1) dict lookup
                            continue
                        _q2 = str(_mi2_node.qualifier or "")
                        if not _q2 or _q2[0].isupper():
                            continue  # skip class-qualified; handled by Pattern A / Phase 1
                        _mi2_line = _node_line(_mi2_node)
                        if not _mi2_line:
                            for _mi2_anc in reversed(_mi2_path):
                                _mi2_line = _node_line(_mi2_anc)
                                if _mi2_line:
                                    break
                        if not _mi2_line or _mi2_line in dead_lines:
                            continue
                        _mi2_midx = -1
                        for _i2, _s2 in enumerate(_mstarts_mlc):
                            if _mi2_line >= _s2:
                                _mi2_midx = _i2
                            else:
                                break
                        _cls2 = _var_type_mid.get((_q2, _mi2_midx))
                        if not _cls2:
                            continue
                        _callee_sinks2 = _cf_sr.sink_registry.get((_cls2, _mi2_node.member))
                        if not _callee_sinks2:
                            continue
                        _et_mi2 = _eff_tainted(_mi2_line)
                        _mi2_args = _mi2_node.arguments or []
                        for _mi2_pidx, (_mi2_rid, _mi2_vt, _mi2_sv, _mi2_desc) in _callee_sinks2.items():
                            if _mi2_pidx < len(_mi2_args) and _is_tainted(_mi2_args[_mi2_pidx], _et_mi2):
                                _add(_mi2_node, _mi2_vt, _mi2_sv, _mi2_rid, _mi2_desc,
                                     line_override=_mi2_line)
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
                algo = _algo_str(args[0], _const_strings)
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
                algo = _algo_str(args[0], _const_strings)
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
                    if _node_line(node) in dead_lines:
                        continue
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
                if _node_line(node) in dead_lines:
                    continue
                ctype = _type_name(node.type)
                if ctype == "URL":
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SSRF, Severity.HIGH, "JAST-SSRF-001",
                                 "new URL() with user-controlled string — "
                                 "SSRF; validate scheme/host against an allowlist")
                            break
                elif ctype in _HTTP_CLIENT_URL_CTORS:
                    first = (node.arguments or [None])[0]
                    if first is not None and _is_tainted(first, tainted):
                        _add(node, VulnType.SSRF, Severity.HIGH, "JAST-SSRF-001",
                             f"new {ctype}() with user-controlled URL — "
                             "SSRF; validate scheme/host against an allowlist before making HTTP requests")
        except Exception:
            pass

        # Spring RestTemplate / WebClient: first arg is the URL.
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
                if node.member not in _SPRING_REST_URL_METHODS:
                    continue
                q = str(node.qualifier or "")
                if not (q in _SPRING_REST_QUALIFIERS
                        or q.lower().endswith("resttemplate")
                        or q.lower().endswith("webclient")):
                    continue
                first = (node.arguments or [None])[0]
                if first is not None and _is_tainted(first, tainted):
                    _add(node, VulnType.SSRF, Severity.HIGH, "JAST-SSRF-002",
                         f"Spring {q}.{node.member}() with user-controlled URL — "
                         "SSRF; validate scheme/host or use allowlist before making external requests")
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

        # ── SnakeYAML unsafe deserialization (CVE-2022-1471) ─────────────────
        # new Yaml() / new Yaml(new Constructor(...)) allows arbitrary class
        # instantiation.  Only new Yaml(new SafeConstructor(...)) is safe.
        try:
            for _, node in tree.filter(jt.ClassCreator):
                if _type_name(node.type) != "Yaml":
                    continue
                args = node.arguments or []
                has_safe = any(
                    isinstance(a, jt.ClassCreator)
                    and _type_name(a.type) == "SafeConstructor"
                    for a in args
                )
                if not has_safe:
                    arg_desc = (
                        ", ".join(
                            _type_name(a.type) if isinstance(a, jt.ClassCreator) else "?"
                            for a in args
                        )
                        or "no-arg"
                    )
                    _add(node, VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                         "JAST-DESER-002",
                         f"new Yaml({arg_desc}) without SafeConstructor: SnakeYAML can "
                         "instantiate arbitrary Java types; use "
                         "new Yaml(new SafeConstructor(new LoaderOptions())) (CVE-2022-1471)")
        except Exception:
            pass

        # ── JNDI injection ────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if _node_line(node) in dead_lines:
                    continue
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
                if _node_line(node) in dead_lines:
                    continue
                if node.member in _SPEL_METHODS:
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SSTI, Severity.CRITICAL, "JAST-SPEL-001",
                                 "SpEL parseExpression() with user-controlled input — "
                                 "Spring Expression Language injection allows RCE; avoid dynamic SpEL on user data")
                            break
        except Exception:
            pass

        # ── XPath injection ────────────────────────────────────────────────────
        # Only run when the file actually uses XPath APIs — avoids FPs from
        # other evaluate()/compile() calls (JavaScript, regex, etc.).
        try:
            if any(hint in content for hint in _XPATH_FILE_HINTS):
                for _, node in tree.filter(jt.MethodInvocation):
                    if _node_line(node) in dead_lines:
                        continue
                    if node.member not in _XPATH_SINK_METHODS:
                        continue
                    args = node.arguments or []
                    if args and _is_tainted(args[0], tainted):
                        _add(node, VulnType.XPATH_INJECTION, Severity.HIGH, "JAST-XPATH-001",
                             f"XPath {node.member}() with user-controlled expression — "
                             "allows attacker to manipulate XPath query and bypass authentication "
                             "or extract arbitrary XML data; use parameterized XPath or whitelist input")
        except Exception:
            pass

        # ── Insecure cookie ────────────────────────────────────────────────────
        # Flag explicit setSecure(false) / setHttpOnly(false) on Cookie objects.
        # CWE-614 (Secure attribute) and CWE-1004 (HttpOnly attribute).
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member not in _COOKIE_FLAG_METHODS:
                    continue
                args = node.arguments or []
                if not args:
                    continue
                arg = args[0]
                if isinstance(arg, jt.Literal) and str(arg.value) == "false":
                    cwe_label = "614" if node.member == "setSecure" else "1004"
                    flag_name = "Secure" if node.member == "setSecure" else "HttpOnly"
                    _add(node, VulnType.INSECURE_COOKIE, Severity.MEDIUM,
                         "JAST-COOKIE-001",
                         f"Cookie.{node.member}(false) — {flag_name} flag disabled; "
                         f"{'cookies sent over plain HTTP expose session tokens to network eavesdroppers' if node.member == 'setSecure' else 'missing HttpOnly allows client-side JS to steal the cookie via XSS'} "
                         f"(CWE-{cwe_label})")
        except Exception:
            pass

        # ── SSL/TLS hostname verification bypass ──────────────────────────────
        # setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER) or any all-trusting
        # verifier completely disables hostname checks, enabling MITM attacks.
        try:
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member not in ("setHostnameVerifier", "setDefaultHostnameVerifier"):
                    continue
                args = node.arguments or []
                if not args:
                    continue
                arg_text = ""
                if isinstance(args[0], jt.MemberReference):
                    arg_text = f"{args[0].qualifier}.{args[0].member}" if args[0].qualifier else args[0].member
                elif isinstance(args[0], jt.ClassCreator):
                    arg_text = _type_name(args[0].type)
                # Flag known all-trusting verifier constants or anonymous/null implementations
                _UNSAFE_VERIFIERS = frozenset({
                    "ALLOW_ALL_HOSTNAME_VERIFIER",
                    "AllowAllHostnameVerifier",
                    "NoopHostnameVerifier",
                    "NullHostnameVerifier",
                    "TrustAllHostnameVerifier",
                    "SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER",
                    "HttpsURLConnection.ALLOW_ALL_HOSTNAME_VERIFIER",
                })
                if any(u in arg_text for u in _UNSAFE_VERIFIERS) or (
                    isinstance(args[0], jt.ClassCreator)
                    and _type_name(args[0].type) in _UNSAFE_VERIFIERS
                ):
                    _add(node, VulnType.WEAK_CRYPTOGRAPHY, Severity.HIGH, "JAST-SSL-001",
                         f"{node.member}() with all-trusting verifier disables hostname "
                         "verification — allows any server to impersonate a legitimate host "
                         "(MITM); remove the custom verifier or use the default strict verifier")
        except Exception:
            pass

        return findings
