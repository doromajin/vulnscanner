"""Java guard idioms that make code safe (SpEL read-only context, SSRF / redirect / JSONP validators,
fixed-origin URIs, test-only severity noise).  Each group has a TP (vulnerable variant still fires),
an FP (safe variant is silent) and an FN-guard (a look-alike that does not really protect)."""
from vulnscanner.analyzers.ast_java import JavaASTAnalyzer

_H = ("import javax.servlet.http.*;\nimport java.io.*;\nimport java.net.*;\n"
      "import org.springframework.web.bind.annotation.*;\n"
      "import org.springframework.expression.*;\n"
      "import org.springframework.expression.spel.standard.*;\n"
      "import org.springframework.expression.spel.support.*;\npublic class A {\n")


def _find(body: str):
    return JavaASTAnalyzer().analyze("A.java", _H + body + "}\n")


def _rules(body: str) -> set[str]:
    return {f.rule_id for f in _find(body)}


def _m(stmts: str, params: str = "HttpServletRequest request") -> str:
    return f"  @RequestMapping(\"/x\")\n  public String h({params}) throws Exception {{\n{stmts}\n    return \"\";\n  }}\n"


_URL = '    String url = request.getParameter("url");\n'


# ── 1. SpEL evaluation context ────────────────────────────────────────────────

def test_spel_standard_context_is_reported():
    body = _m("    StandardEvaluationContext c = new StandardEvaluationContext();\n"
              "    SpelExpressionParser p = new SpelExpressionParser();\n"
              "    Expression e = p.parseExpression(request.getParameter(\"v\"));\n"
              "    Object x = e.getValue(c);")
    assert "JAST-SPEL-001" in _rules(body)


def test_spel_no_context_is_reported():
    body = _m("    SpelExpressionParser p = new SpelExpressionParser();\n"
              "    Object x = p.parseExpression(request.getParameter(\"v\")).getValue();")
    assert "JAST-SPEL-001" in _rules(body)


def test_spel_simple_evaluation_context_is_silent():
    body = _m("    SimpleEvaluationContext c = SimpleEvaluationContext.forReadOnlyDataBinding().build();\n"
              "    SpelExpressionParser p = new SpelExpressionParser();\n"
              "    Expression e = p.parseExpression(request.getParameter(\"v\"));\n"
              "    Object x = e.getValue(c);")
    assert "JAST-SPEL-001" not in _rules(body)


def test_spel_simple_context_in_other_method_does_not_protect():
    safe = _m("    SimpleEvaluationContext c = SimpleEvaluationContext.forReadOnlyDataBinding().build();\n"
              "    Object x = new SpelExpressionParser().parseExpression(request.getParameter(\"v\")).getValue(c);")
    vuln = ("  @RequestMapping(\"/y\")\n  public String g(HttpServletRequest request) throws Exception {\n"
            "    Object x = new SpelExpressionParser().parseExpression(request.getParameter(\"v\")).getValue();\n"
            "    return \"\";\n  }\n")
    hits = [f.line_number for f in _find(safe + vuln) if f.rule_id == "JAST-SPEL-001"]
    assert len(hits) == 1


# ── 2. SSRF validators / fixed-origin URIs ────────────────────────────────────

def test_ssrf_unvalidated_url_is_reported():
    assert "JAST-SSRF-001" in _rules(_m(_URL + "    URL u = new URL(url);"))


def test_ssrf_validator_guard_is_silent():
    body = _m(_URL + "    if (!SecurityUtil.checkSSRF(url)) { return \"bad\"; }\n    URL u = new URL(url);")
    assert "JAST-SSRF-001" not in _rules(body)


def test_ssrf_unsafe_predicate_guard_is_silent():
    body = _m(_URL + "    if (isInternalIp(url)) { throw new IllegalArgumentException(); }\n    URL u = new URL(url);")
    assert "JAST-SSRF-001" not in _rules(body)


def test_ssrf_host_allow_list_guard_is_silent():
    body = _m(_URL + "    String host = new URI(url).getHost();\n"
              "    if (!ALLOWED.contains(host)) { return \"bad\"; }\n    URL u = new URL(url);")
    assert "JAST-SSRF-001" not in _rules(body)


def test_ssrf_guard_with_null_precondition_still_reported():
    body = _m(_URL + "    if (url != null && !SecurityUtil.checkSSRF(url)) { return \"bad\"; }\n    URL u = new URL(url);")
    assert "JAST-SSRF-001" in _rules(body)


def test_ssrf_guard_in_sibling_method_does_not_protect():
    safe = _m(_URL + "    if (!SecurityUtil.checkSSRF(url)) { return \"bad\"; }\n    URL u = new URL(url);")
    vuln = ("  @RequestMapping(\"/y\")\n  public String g(HttpServletRequest request) throws Exception {\n"
            + _URL + "    URL u = new URL(url);\n    return \"\";\n  }\n")
    assert len([f for f in _find(safe + vuln) if f.rule_id == "JAST-SSRF-001"]) == 1


def test_uri_with_literal_path_prefix_is_not_ssrf():
    body = _m('    String id = request.getParameter("id");\n    URI u = new URI("/Lesson/pic?id=" + id);')
    assert "JAST-SSRF-001" not in _rules(body)


def test_uri_with_tainted_host_is_reported():
    body = _m('    String h = request.getParameter("h");\n    URI u = new URI("http://" + h + "/x");\n    u.toURL().openStream();')
    assert "JAST-SSRF-001" in _rules(body)


def test_uri_parse_inside_validator_method_is_silent():
    src = ("  public static boolean checkUrl(String url) throws Exception {\n"
           "    URI u = new URI(url);\n    return u.getHost() != null;\n  }\n")
    assert "JAST-SSRF-001" not in _rules(src + _m(_URL + "    checkUrl(url);"))


# ── 3. open redirect / JSONP validators ───────────────────────────────────────

def test_redirect_unvalidated_is_reported():
    body = _m(_URL + "    HttpServletResponse response = null;\n    response.sendRedirect(url);",
              "HttpServletRequest request, HttpServletResponse response")
    body = body.replace("    HttpServletResponse response = null;\n", "")
    assert "JAST-REDIRECT-001" in _rules(body)


def test_redirect_validator_guard_is_silent():
    body = _m(_URL + "    if (SecurityUtil.checkURL(url) == null) { return \"no\"; }\n    response.sendRedirect(url);",
              "HttpServletRequest request, HttpServletResponse response")
    assert "JAST-REDIRECT-001" not in _rules(body)


def test_redirect_regex_guard_is_silent():
    body = _m(_URL + "    if (!url.matches(\"/[a-z/]+\")) { throw new IllegalArgumentException(); }\n"
              "    response.sendRedirect(url);", "HttpServletRequest request, HttpServletResponse response")
    assert "JAST-REDIRECT-001" not in _rules(body)


def test_redirect_bare_slash_prefix_is_not_enough():
    body = _m(_URL + "    if (!url.startsWith(\"/\")) { return \"no\"; }\n    response.sendRedirect(url);",
              "HttpServletRequest request, HttpServletResponse response")
    assert "JAST-REDIRECT-001" in _rules(body)


def test_redirect_null_precondition_guard_still_reported():
    body = _m(_URL + "    if (url != null && SecurityUtil.checkURL(url) == null) { return \"no\"; }\n"
              "    response.sendRedirect(url);", "HttpServletRequest request, HttpServletResponse response")
    assert "JAST-REDIRECT-001" in _rules(body)


def test_jsonp_unvalidated_callback_is_reported():
    body = _m('    String callback = request.getParameter("callback");\n'
              '    return callback + "(" + data() + ")";')
    assert "JAST-JSONP-001" in _rules(body.replace('    return "";\n', ""))


def test_jsonp_allow_list_callback_is_silent():
    body = _m('    String callback = request.getParameter("callback");\n'
              '    if (!PATTERN.matcher(callback).matches()) { return "bad"; }\n'
              '    return callback + "(" + data() + ")";')
    assert "JAST-JSONP-001" not in _rules(body.replace('    return "";\n', ""))


# ── 4. severity noise ─────────────────────────────────────────────────────────

def test_random_for_file_name_is_low():
    body = _m("    java.util.Random r = new java.util.Random();\n    String name = \"f\" + r.nextInt();")
    sev = {f.severity.name for f in _find(body) if f.rule_id == "JAST-CRYPTO-001"}
    assert sev and sev == {"LOW"}


def test_random_for_token_is_high():
    body = _m("    java.util.Random tokenRandom = new java.util.Random();\n    String token = \"\" + tokenRandom.nextLong();")
    sev = {f.severity.name for f in _find(body) if f.rule_id == "JAST-CRYPTO-001"}
    assert sev == {"HIGH"}


def test_random_in_main_method_is_silent():
    src = ("  public static void main(String[] args) {\n    java.util.Random r = new java.util.Random();\n"
           "    String token = \"\" + r.nextInt();\n  }\n")
    assert "JAST-CRYPTO-001" not in _rules(src)


def test_math_random_for_delay_is_low():
    body = _m("    long delay = (long) (Math.random() * 100);")
    sev = {f.severity.name for f in _find(body) if f.rule_id == "JAST-CRYPTO-001B"}
    assert sev and sev == {"LOW"}
