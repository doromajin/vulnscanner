"""Java vulnerability analyzer using javalang AST.

Provides taint-aware detection with variable-flow tracking:
  source (request.getParameter) -> local var -> sink (executeQuery)

Falls back gracefully to empty list if javalang is not installed or
the file uses unsupported Java syntax.
"""
from __future__ import annotations

try:
    import javalang
    import javalang.tree as jt
    _HAS_JAVALANG = True
except ImportError:
    _HAS_JAVALANG = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# ── request source methods ─────────────────────────────────────────────────────

_REQUEST_METHODS = frozenset({
    "getParameter", "getParameterValues", "getParameterMap",
    "getHeader", "getHeaders", "getHeaderNames",
    "getInputStream", "getReader",
    "getQueryString", "getPathInfo", "getRequestURI", "getRequestURL",
    "getCookies", "getRemoteAddr", "getAttribute",
})

_REQUEST_OBJECTS = frozenset({
    "request", "req", "httpRequest", "servletRequest",
    "httpServletRequest", "hreq",
})

# ── sink sets ──────────────────────────────────────────────────────────────────

_SQL_EXEC_METHODS = frozenset({
    "execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
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


# ── taint helpers ──────────────────────────────────────────────────────────────

def _node_line(node) -> int:
    pos = getattr(node, "position", None)
    if pos and hasattr(pos, "line"):
        return pos.line
    return 0


def _is_request_source(node) -> bool:
    """True if node is a direct call to a servlet/framework request getter."""
    if not isinstance(node, jt.MethodInvocation):
        return False
    if node.member not in _REQUEST_METHODS:
        return False
    q = node.qualifier or ""
    return (not q) or str(q) in _REQUEST_OBJECTS


def _is_tainted(node, tainted: set[str]) -> bool:
    """Recursively check whether a javalang expression node carries taint."""
    if node is None:
        return False
    if isinstance(node, jt.MethodInvocation):
        if _is_request_source(node):
            return True
        return any(_is_tainted(a, tainted) for a in (node.arguments or []))
    if isinstance(node, jt.MemberReference):
        return node.member in tainted
    if isinstance(node, jt.BinaryOperation):
        return _is_tainted(node.operandl, tainted) or _is_tainted(node.operandr, tainted)
    if isinstance(node, jt.Literal):
        return False
    if isinstance(node, jt.ClassCreator):
        return any(_is_tainted(a, tainted) for a in (node.arguments or []))
    if hasattr(node, "expression"):
        return _is_tainted(node.expression, tainted)
    return False


def _collect_tainted(tree) -> set[str]:
    """Two-pass fixed-point variable taint collection across the whole file."""
    tainted: set[str] = set()
    for _ in range(3):
        changed = False
        try:
            for _, node in tree.filter(jt.LocalVariableDeclaration):
                for decl in node.declarators:
                    if decl.name not in tainted and decl.initializer:
                        if _is_tainted(decl.initializer, tainted):
                            tainted.add(decl.name)
                            changed = True
        except Exception:
            break
        if not changed:
            break
    return tainted


# ── analyzer ───────────────────────────────────────────────────────────────────

class JavaASTAnalyzer(BaseAnalyzer):
    """AST-level analyzer for .java files using javalang.

    Registers alongside the regex-based JavaAnalyzer.  Both run; the
    scanner deduplicates by (file, line, vuln_type) when results are reported.
    """

    supported_extensions = (".java",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _HAS_JAVALANG:
            return []
        try:
            tree = javalang.parse.parse(content)
        except Exception:
            return []

        lines = content.splitlines()
        tainted = _collect_tainted(tree)
        findings: list[Finding] = []

        def _add(node, vuln_type, severity, rule_id, desc):
            ln = _node_line(node)
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
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SQL_INJECTION, Severity.HIGH, "JAST-SQL-001",
                                 f"{node.member}() receives user-controlled value — "
                                 "SQL injection; use PreparedStatement with parameterized queries")
                            break
                elif node.member in _JPA_METHODS:
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SQL_INJECTION, Severity.HIGH, "JAST-SQL-002",
                                 f"JPA {node.member}() with user-controlled string — "
                                 "SQL injection; use named parameters (:param)")
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
                if node.type.name == "ProcessBuilder":
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.COMMAND_INJECTION, Severity.CRITICAL, "JAST-CMD-002",
                                 "new ProcessBuilder() with user-controlled argument — "
                                 "command injection; validate and allowlist commands")
                            break
        except Exception:
            pass

        # ── SSRF ──────────────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.ClassCreator):
                if node.type.name == "URL":
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.SSRF, Severity.HIGH, "JAST-SSRF-001",
                                 "new URL() with user-controlled string — "
                                 "SSRF; validate scheme/host against an allowlist")
                            break
        except Exception:
            pass

        # ── Path traversal ────────────────────────────────────────────────────
        try:
            for _, node in tree.filter(jt.ClassCreator):
                if node.type.name in _FILE_CLASSES:
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "JAST-PATH-001",
                                 f"new {node.type.name}() with user-controlled path — "
                                 "path traversal; canonicalize and validate within allowed root")
                            break
            for _, node in tree.filter(jt.MethodInvocation):
                if node.member in ("get", "of") and str(node.qualifier or "") in ("Paths", "Path"):
                    for arg in (node.arguments or []):
                        if _is_tainted(arg, tainted):
                            _add(node, VulnType.PATH_TRAVERSAL, Severity.HIGH, "JAST-PATH-002",
                                 f"Paths.{node.member}() with user-controlled path — "
                                 "path traversal; validate path does not escape allowed directory")
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
                if node.type.name in _DESER_CLASSES:
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
