"""JSP / JSPX / JSPF / tag files.

The scriptlets (`<% %>`), expressions (`<%= %>`) and declarations (`<%! %>`) of a page are stitched into one
synthetic servlet class (line numbers are kept 1:1 with the page, declarations are appended with their own
mapping) and handed to the Java AST analyzer, so the SQL / command / path / redirect / XXE / deserialization
sinks and the taint engine apply unchanged; findings are mapped back to the JSP file and line.

JSP-specific rules (CWE-79 / CWE-98):

JSP-XSS-001     `<%= expr %>` / `out.print*` / `response.getWriter().print*` of a request-derived value that is
                not passed through an HTML/URL encoder (variables assigned from the request are followed) - HIGH
JSP-XSS-002     EL `${param.x}` / `${header.x}` / `${cookie.x}` / `${pageContext.request.*}` printed in template
                text (EL is not auto-escaped there) - HIGH; `${requestScope.x}` and friends - MEDIUM
JSP-XSS-003     `<c:out value=<request data> escapeXml="false">` - HIGH
JSP-INCLUDE-001 `<jsp:include|forward page=<request data>>` - HIGH (CWE-98)

First version, known limits: custom tags / tag files / JSF / Struts output tags are not modelled; includes are
not resolved across files; a variable set with `<c:set>` and printed later is not followed; taint through
scriptlet variables is flow-insensitive (a variable that is ever re-assigned from an encoder is treated as clean).
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_COMMENT_RE = re.compile(r"<%--.*?--%>", re.DOTALL)
_BLOCK_RE = re.compile(r"<%([!=@]?)(.*?)%>", re.DOTALL)
_PREFIXED_TAG_RE = re.compile(r"</?[A-Za-z][\w.-]*:[\w.-]+\b[^>]*>", re.DOTALL)
_EL_RE = re.compile(r"[$#]\{([^{}]*)\}")
_COUT_RE = re.compile(r"<c:out\b([^>]*)>", re.DOTALL | re.IGNORECASE)
_INCLUDE_TAG_RE = re.compile(r"<jsp:(?:include|forward)\b((?:<%.*?%>|[^>])*)>", re.DOTALL | re.IGNORECASE)
_PAGE_ATTR_RE = re.compile(r"""\bpage\s*=\s*(?:"((?:<%.*?%>|[^"])*)"|'((?:<%.*?%>|[^'])*)')""", re.DOTALL)
_ESCAPE_FALSE_RE = re.compile(r"""\bescapeXml\s*=\s*["']\s*false\s*["']""", re.IGNORECASE)
_VALUE_ATTR_RE = re.compile(r"""\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.DOTALL)
_EL_IGNORED_RE = re.compile(r"""isELIgnored\s*=\s*["']true["']""", re.IGNORECASE)

# --- request-derived data -------------------------------------------------------------------------
_REQ_JAVA_RE = re.compile(
    r"\brequest\s*\.\s*(?:getParameter(?:Values|Map|Names)?|getHeaders?|getQueryString|getRequestURI|"
    r"getRequestURL|getCookies|getPathInfo|getPathTranslated|getRemoteUser|getInputStream|getReader)\s*\("
    r"|\bgetParameter\s*\(|\.getValue\s*\(\s*\)\s*(?=.*[Cc]ookie)"
)
_EL_HIGH_RE = re.compile(
    r"(?<![\w.])(?:param|paramValues|header|headerValues|cookie)\b(?!\s*:)"
    r"|(?<![\w.])pageContext\s*\.\s*request\s*\.\s*(?!contextPath|servletContext|scheme|serverName|"
    r"serverPort|session\b)\w+"
)
_EL_MEDIUM_RE = re.compile(r"(?<![\w.])(?:requestScope|sessionScope|param_?\w*)\s*[.\[]")
_SANITIZER_RE = re.compile(
    r"\b(?:encodeFor\w+|escapeHtml\w*|escapeXml\w*|escapeJava\w*|htmlEscape\w*|forHtml\w*|forJavaScript\w*|"
    r"forUriComponent\w*|URLEncoder\s*\.\s*encode|encodeURL|encodeRedirectURL|sanitize\w*|Jsoup\s*\.\s*clean|"
    r"HtmlUtils|StringEscapeUtils|Encode\s*\.\s*for\w+|escape\w*)\s*[.(]"
    r"|\bfn\s*:\s*escapeXml\b|\bencoder\s*\(\s*\)",
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(
    r"\b(?:Integer|Long|Double|Float|Short|Boolean|BigDecimal|BigInteger)\s*\.\s*(?:parse\w*|valueOf)\s*\(|"
    r"\bnew\s+(?:Integer|Long|Double|BigDecimal|BigInteger)\s*\(|\.(?:length|size|isEmpty|equals\w*|"
    r"hashCode|intValue|longValue)\s*\(\s*[^)]*\)\s*$"
)
_ASSIGN_RE = re.compile(
    r"(?:^|[;{}])\s*(?:final\s+)?(?:([\w.<>\[\]]+)\s+)?(\w+)\s*(\+?=)(?!=)\s*([^;]*)", re.DOTALL
)
_PRIMITIVES = frozenset({"int", "long", "boolean", "double", "float", "short", "byte", "char", "Integer", "Long",
                         "Boolean", "Double"})
_OUT_CALL_RE = re.compile(
    r"\b(?:out|(?:response\s*\.\s*getWriter\s*\(\s*\)))\s*\.\s*(?:print|println|write|append)\s*\(", re.IGNORECASE
)

_HEADER = ("import java.io.*; import java.util.*; import java.sql.*; import javax.servlet.*; "
           "import javax.servlet.http.*; import javax.servlet.jsp.*; ")
_CLASS_OPEN = ("public class JspPage_ { void _jspService(HttpServletRequest request, HttpServletResponse response, "
               "HttpSession session, JspWriter out, ServletContext application, ServletConfig config, "
               "PageContext pageContext) throws Exception { ")


def _blank(m: re.Match) -> str:
    return re.sub(r"[^\n]", " ", m.group(0))


def _balanced_args(text: str, open_idx: int) -> str:
    """Text between the parenthesis at *open_idx* and its match (string literals respected)."""
    depth, i, n, quote = 0, open_idx, len(text), ""
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:]


class JspAnalyzer(BaseAnalyzer):
    supported_extensions = (".jsp", ".jspx", ".jspf", ".tag")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if "<%" not in content and "${" not in content and "#{" not in content and "<c:" not in content:
            return []
        text = content.replace("\r\n", "\n").replace("\r", "\n")
        text = _COMMENT_RE.sub(_blank, text)
        lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")

        blocks = list(_BLOCK_RE.finditer(text))
        scriptlet_code = "\n".join(m.group(2) for m in blocks if m.group(1) == "")
        decl_code = "\n".join(m.group(2) for m in blocks if m.group(1) == "!")
        tainted = self._tainted_vars(scriptlet_code + "\n" + decl_code)

        findings: list[Finding] = []

        def add(rule: str, sev: Severity, vt: VulnType, ln: int, desc: str, cwe: int) -> None:
            ln = max(1, min(ln, len(lines)))
            findings.append(Finding(
                vuln_type=vt, severity=sev, file_path=file_path, line_number=ln,
                line_content=lines[ln - 1].strip(), description=desc, rule_id=rule,
                repo_url=repo_url, snippet=self._extract_snippet(lines, ln), cwe_id=cwe,
            ))

        def line_of(idx: int) -> int:
            return text.count("\n", 0, idx) + 1

        def req_derived(expr: str) -> bool:
            if _SANITIZER_RE.search(expr) or _NUMERIC_RE.search(expr.strip()):
                return False
            if _REQ_JAVA_RE.search(expr):
                return True
            return any(re.search(r"(?<![\w.])" + re.escape(v) + r"\b(?!\s*\()", expr) for v in tainted)

        # (a) Java-side XSS: <%= expr %> and out.print(expr)
        tag_spans = [(t.start(), t.end()) for t in _INCLUDE_TAG_RE.finditer(text)]
        for m in blocks:
            kind, code = m.group(1), m.group(2)
            if any(a <= m.start() < b for a, b in tag_spans):
                continue  # attribute of jsp:include/forward: JSP-INCLUDE-001 covers it
            base = m.start(2)
            if kind == "=":
                if req_derived(code):
                    add("JSP-XSS-001", Severity.HIGH, VulnType.XSS, line_of(base + len(code) - len(code.lstrip())),
                        "<%= ... %> prints a request-derived value without HTML encoding — reflected XSS "
                        "(use <c:out>, fn:escapeXml or ESAPI/OWASP Encoder)", 79)
            elif kind == "":
                for om in _OUT_CALL_RE.finditer(code):
                    arg = _balanced_args(code, om.end() - 1)
                    if req_derived(arg):
                        add("JSP-XSS-001", Severity.HIGH, VulnType.XSS, line_of(base + om.start()),
                            "out.print of a request-derived value without HTML encoding — reflected XSS", 79)

        # (b) <jsp:include/forward page=...> and <c:out escapeXml="false">
        for m in _INCLUDE_TAG_RE.finditer(text):
            am = _PAGE_ATTR_RE.search(m.group(1))
            val = (am.group(1) or am.group(2) or "") if am else ""
            if not val:
                continue
            exprs = re.findall(r"<%=(.*?)%>", val, re.DOTALL)
            el = [e for e in _EL_RE.findall(val)]
            if any(req_derived(e) for e in exprs) or any(_EL_HIGH_RE.search(e) for e in el):
                add("JSP-INCLUDE-001", Severity.HIGH, VulnType.PATH_TRAVERSAL, line_of(m.start()),
                    "jsp:include/forward target built from request data — local file inclusion / forced "
                    "browsing (CWE-98); map the parameter to a fixed allow-list of pages", 98)
        for m in _COUT_RE.finditer(text):
            attrs = m.group(1)
            if not _ESCAPE_FALSE_RE.search(attrs):
                continue
            vm = _VALUE_ATTR_RE.search(attrs)
            val = (vm.group(1) or vm.group(2) or "") if vm else ""
            exprs = re.findall(r"<%=(.*?)%>", val, re.DOTALL)
            if any(_EL_HIGH_RE.search(e) for e in _EL_RE.findall(val)) or any(req_derived(e) for e in exprs):
                add("JSP-XSS-003", Severity.HIGH, VulnType.XSS, line_of(m.start()),
                    '<c:out escapeXml="false"> prints a request-derived value as markup — reflected XSS', 79)

        # (c) EL in template text
        if not _EL_IGNORED_RE.search(text):
            tpl = _BLOCK_RE.sub(_blank, text)
            tpl = _PREFIXED_TAG_RE.sub(_blank, tpl)
            for m in _EL_RE.finditer(tpl):
                expr = m.group(1)
                if _SANITIZER_RE.search(expr):
                    continue
                if _EL_HIGH_RE.search(expr):
                    sev = Severity.HIGH
                elif _EL_MEDIUM_RE.search(expr):
                    sev = Severity.MEDIUM
                else:
                    continue
                add("JSP-XSS-002", sev, VulnType.XSS, line_of(m.start()),
                    f"EL ${{{expr.strip()[:50]}}} is printed in template text without escaping (JSP does not "
                    "auto-escape EL) — use <c:out value=...> or fn:escapeXml", 79)

        # (d) Java sinks via the existing Java AST analyzer
        if blocks:
            findings.extend(self._java_findings(file_path, repo_url, text, blocks, lines))
        return self._dedup(findings)

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def _dedup(findings: list[Finding]) -> list[Finding]:
        seen: set = set()
        out: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.line_number)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    @staticmethod
    def _tainted_vars(code: str) -> set[str]:
        """Names assigned (directly or transitively) from request data and never from an encoder."""
        assigns = [(t, n, op, rhs) for t, n, op, rhs in _ASSIGN_RE.findall(code)
                   if n not in {"return", "else", "new", "if", "while", "for"}]
        clean: set[str] = set()
        for t, n, _op, rhs in assigns:
            if (t in _PRIMITIVES) or _SANITIZER_RE.search(rhs) or _NUMERIC_RE.search(rhs.strip()):
                clean.add(n)
        tainted: set[str] = set()
        for _ in range(4):
            changed = False
            for _t, n, _op, rhs in assigns:
                if n in tainted or n in clean:
                    continue
                if _REQ_JAVA_RE.search(rhs) or any(
                        re.search(r"(?<![\w.])" + re.escape(v) + r"\b(?!\s*\()", rhs) for v in tainted):
                    tainted.add(n)
                    changed = True
            if not changed:
                break
        return tainted

    def _java_findings(self, file_path, repo_url, text, blocks, lines) -> list[Finding]:
        from vulnscanner.analyzers.ast_java import JavaASTAnalyzer  # local: heavy import

        java: list[str] = []      # synthetic source lines
        jmap: list[int] = []      # synthetic line (0-based) -> JSP line (1-based)
        decls: list[tuple[int, str]] = []
        out_parts: list[str] = []
        pos = 0
        cur_line = 1
        # Build the method body so that JSP line N is Java line N.
        body = [""]  # growing list of lines; body[i] is JSP line i+1
        def put(s: str, start_line: int) -> None:
            nonlocal body
            parts = s.split("\n")
            while len(body) < start_line:
                body.append("")
            body[start_line - 1] += parts[0]
            for k, p in enumerate(parts[1:], 1):
                while len(body) < start_line + k:
                    body.append("")
                body[start_line + k - 1] += p
        for m in blocks:
            kind, code = m.group(1), m.group(2)
            ln = text.count("\n", 0, m.start(2)) + 1
            if kind == "":
                put(code, ln)
            elif kind == "=":
                expr = code.strip().rstrip(";")
                if expr:
                    put("out.print(" + expr + ");", ln)
            elif kind == "!":
                decls.append((ln, code))
        header = _HEADER + _CLASS_OPEN
        body[0] = header + body[0]
        java = list(body)
        jmap = list(range(1, len(body) + 1))
        java.append("}")
        jmap.append(len(body))
        for ln, code in decls:
            for k, p in enumerate(code.split("\n")):
                java.append(p)
                jmap.append(ln + k)
        java.append("}")
        jmap.append(len(body))
        src = "\n".join(java)
        try:
            raw = JavaASTAnalyzer().analyze(file_path + ".java", src, repo_url)
        except Exception:
            return []
        res: list[Finding] = []
        for f in raw:
            i = f.line_number - 1
            if not (0 <= i < len(jmap)):
                continue
            ln = max(1, min(jmap[i], len(lines)))
            f.file_path = file_path
            f.line_number = ln
            f.line_content = lines[ln - 1].strip()
            f.snippet = self._extract_snippet(lines, ln)
            res.append(f)
        return res
