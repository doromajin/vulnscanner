"""JSP / JSPX analyzer: scriptlets run through the Java taint engine, plus JSP-specific XSS and include rules."""
from vulnscanner.analyzers import ALL_ANALYZERS
from vulnscanner.analyzers.jsp_analyzer import JspAnalyzer
from vulnscanner.fetcher.local import _SCAN_EXTENSIONS


def _f(src: str, path: str = "webapp/page.jsp"):
    return JspAnalyzer().analyze(path, src)


def _hits(src: str, path: str = "webapp/page.jsp"):
    return {(f.rule_id, f.severity.name) for f in _f(src, path)}


def _lines(src: str, rule: str | None = None):
    return sorted(f.line_number for f in _f(src) if rule is None or f.rule_id == rule)


def test_extensions_are_scanned_and_routed():
    for ext in (".jsp", ".jspx", ".jspf", ".tag"):
        assert ext in _SCAN_EXTENSIONS
        assert JspAnalyzer().supports("a/b" + ext)
    assert any(isinstance(a, JspAnalyzer) for a in ALL_ANALYZERS)
    assert not JspAnalyzer().supports("a.java")


# --- TP ---
def test_scriptlet_sql_injection_maps_back_to_jsp_line():
    src = (
        '<%@ page import="java.sql.*" %>\n'
        "<html>\n"
        "<%\n"
        '  String id = request.getParameter("id");\n'
        "  Statement stmt = con.createStatement();\n"
        '  ResultSet rs = stmt.executeQuery("select * from t where id=" + id);\n'
        "%>\n"
    )
    fs = [f for f in _f(src) if f.vuln_type.name == "SQL_INJECTION"]
    assert fs and fs[0].line_number == 6
    assert fs[0].file_path == "webapp/page.jsp"
    assert "executeQuery" in fs[0].line_content


def test_scriptlet_command_and_redirect_and_path():
    src = (
        "<%\n"
        '  String h = request.getParameter("h");\n'
        '  Runtime.getRuntime().exec("ping " + h);\n'
        '  response.sendRedirect(request.getParameter("next"));\n'
        '  java.io.File f = new java.io.File(request.getParameter("p"));\n'
        "%>\n"
    )
    names = {f.vuln_type.name: f.line_number for f in _f(src)}
    assert names.get("COMMAND_INJECTION") == 3
    assert names.get("OPEN_REDIRECT") == 4
    assert names.get("PATH_TRAVERSAL") == 5


def test_expression_of_request_variable_is_xss_high():
    src = (
        "<html>\n"
        '<% String q = request.getParameter("keyword"); %>\n'
        "Results for <%= q %>\n"
    )
    assert ("JSP-XSS-001", "HIGH") in _hits(src)
    assert _lines(src, "JSP-XSS-001") == [3]


def test_direct_expression_and_out_print_xss():
    assert ("JSP-XSS-001", "HIGH") in _hits('<p><%= request.getParameter("x") %></p>')
    assert ("JSP-XSS-001", "HIGH") in _hits('<% out.println("<b>" + request.getHeader("User-Agent")); %>')


def test_el_param_in_template_text_is_flagged():
    src = "<p>Hello ${param.name}</p>\n<input value=\"${header['Referer']}\">\n"
    assert ("JSP-XSS-002", "HIGH") in _hits(src)
    assert _lines(src, "JSP-XSS-002") == [1, 2]


def test_el_request_scope_is_medium():
    assert ("JSP-XSS-002", "MEDIUM") in _hits("<p>${requestScope.msg}</p>")


def test_c_out_escape_false_with_request_value():
    assert ("JSP-XSS-003", "HIGH") in _hits('<c:out value="${param.q}" escapeXml="false"/>')


def test_jsp_include_from_request_value():
    assert ("JSP-INCLUDE-001", "HIGH") in _hits('<jsp:include page="<%= request.getParameter("p") %>"/>')
    assert ("JSP-INCLUDE-001", "HIGH") in _hits('<jsp:include page="${param.p}"/>')


def test_crlf_line_numbers():
    src = "<html>\r\n<p>\r\n<%= request.getParameter(\"a\") %>\r\n</p>\r\n"
    assert _lines(src, "JSP-XSS-001") == [3]


# --- FP ---
def test_constants_and_clean_scriptlets_stay_clean():
    src = (
        '<%@ page import="java.util.*" %>\n'
        "<%\n"
        '  String title = "Home";\n'
        "  int n = 3;\n"
        '  String path = request.getContextPath();\n'
        "%>\n"
        "<h1><%= title %> <%= n %></h1>\n"
        "<a href=\"<%= path %>/x\">x</a>\n"
    )
    assert _f(src) == []


def test_encoded_output_is_not_xss():
    src = (
        '<% String q = request.getParameter("q"); %>\n'
        "<%= org.owasp.esapi.ESAPI.encoder().encodeForHTML(q) %>\n"
        "<%= StringEscapeUtils.escapeHtml4(request.getParameter(\"x\")) %>\n"
        "<%= java.net.URLEncoder.encode(q, \"UTF-8\") %>\n"
        "<c:out value=\"${param.q}\"/>\n"
        "<c:out value=\"${param.q}\" escapeXml=\"true\"/>\n"
        "${fn:escapeXml(param.q)}\n"
    )
    assert _f(src) == []


def test_numeric_conversion_is_not_xss():
    src = '<% int id = Integer.parseInt(request.getParameter("id")); %>\n<%= id %>\n'
    assert not [f for f in _f(src) if f.rule_id.startswith("JSP-XSS")]


def test_comments_and_isELIgnored_and_tag_attrs():
    assert _f("<%-- ${param.x} <%= request.getParameter(\"x\") %> --%>\n") == []
    assert _f('<%@ page isELIgnored="true" %>\n<p>${param.x}</p>\n') == []
    assert _f('<c:if test="${not empty param.x}"><c:set var="a" value="${param.x}"/></c:if>\n') == []
    assert _f("<p>${user.name} ${items[0]}</p>\n") == []


def test_static_include_and_literal_jsp_include_clean():
    assert _f('<%@ include file="/header.jsp" %>\n<jsp:include page="footer.jsp"/>\n') == []


# --- FN guard: structure that must still be seen ---
def test_scriptlet_split_across_template_blocks():
    src = (
        "<%\n"
        '  String c = request.getParameter("cmd");\n'
        "  if (c != null) {\n"
        "%>\n"
        "<p>run</p>\n"
        "<%\n"
        '  Runtime.getRuntime().exec(c);\n'
        "  }\n"
        "%>\n"
    )
    names = {f.vuln_type.name: f.line_number for f in _f(src)}
    assert names.get("COMMAND_INJECTION") == 7


def test_declaration_block_and_unparsable_page_do_not_crash():
    assert isinstance(_f("<%! int counter = 0; String f(String s){ return s; } %>\n<%= f(\"a\") %>\n"), list)
    assert isinstance(_f("<% if ( ( %>\n<%= request.getParameter(\"q\") %>\n"), list)
