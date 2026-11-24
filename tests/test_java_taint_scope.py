"""Java: a sink is judged against the taint of its own method, not of the whole file.

`cmd` tainted in a() must not make `String cmd = "ls"` in b() look tainted at the same kinds of sinks
SQL already handled (command, ProcessBuilder, URL, redirect ...).  What must survive: taint inside
the method itself, class fields, and a tainted argument at an in-file call site reaching the callee's
parameter.  Findings on `new X(...)` carry a real line (javalang gives ClassCreator none).
"""
import pytest

from vulnscanner.analyzers.ast_java import JavaASTAnalyzer

_H = "import javax.servlet.http.*;\nimport java.io.*;\nimport java.net.*;\npublic class A {\n"


def _hits(body: str) -> list[tuple[int, str]]:
    return sorted({(f.line_number, f.rule_id) for f in JavaASTAnalyzer().analyze("A.java", _H + body + "}\n")})


def _two_methods(taint_stmt: str, sink: str, clean_stmt: str, var: str, extra_param: str = "") -> str:
    return (f"  void a(HttpServletRequest request{extra_param}) throws Exception {{\n"
            f"    String {var} = request.getParameter(\"c\");\n    {sink}\n  }}\n"
            f"  void b({extra_param.lstrip(', ')}) throws Exception {{\n"
            f"    String {var} = {clean_stmt};\n    {sink}\n  }}\n")


@pytest.mark.parametrize("sink,rule,var,clean", [
    ("Runtime.getRuntime().exec(cmd);", "JAST-CMD-001", "cmd", '"ls"'),
    ("new ProcessBuilder(cmd).start();", "JAST-CMD-002", "cmd", '"ls"'),
    ("new URL(u);", "JAST-SSRF-001", "u", '"http://x"'),
])
def test_literal_in_another_method_is_not_flagged_but_the_tainted_method_is(sink, rule, var, clean):
    hits = _hits(_two_methods("", sink, clean, var))
    assert hits == [(7, rule)]


def test_redirect_with_a_literal_in_another_method_is_not_flagged():
    body = ("  void a(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            "    String u = request.getParameter(\"c\");\n    response.sendRedirect(u);\n  }\n"
            "  void b(HttpServletResponse response) throws Exception {\n"
            "    String u = \"/home\";\n    response.sendRedirect(u);\n  }\n")
    assert _hits(body) == [(7, "JAST-REDIRECT-001")]


def test_tainted_argument_at_an_in_file_call_site_reaches_the_callee_parameter():
    body = ("  void a(HttpServletRequest request) throws Exception {\n    b(request.getParameter(\"c\"));\n  }\n"
            "  void b(String cmd) throws Exception {\n    Runtime.getRuntime().exec(cmd);\n  }\n")
    assert _hits(body) == [(9, "JAST-CMD-001")]


def test_class_field_is_shared_between_methods():
    body = ("  private String cmd;\n"
            "  void a(HttpServletRequest request) {\n    cmd = request.getParameter(\"c\");\n  }\n"
            "  void b() throws Exception {\n    Runtime.getRuntime().exec(cmd);\n  }\n")
    assert _hits(body) == [(10, "JAST-CMD-001")]


@pytest.mark.parametrize("stmt,rule", [
    ("new ProcessBuilder(request.getParameter(\"c\")).start();", "JAST-CMD-002"),
    ("new URL(request.getParameter(\"c\"));", "JAST-SSRF-001"),
])
def test_new_expression_findings_carry_a_real_line(stmt, rule):
    body = f"  void a(HttpServletRequest request) throws Exception {{\n    {stmt}\n  }}\n"
    assert _hits(body) == [(6, rule)]


def test_insecure_deserialization_finding_carries_a_real_line():
    body = "  void a(InputStream in) throws Exception {\n    ObjectInputStream o = new ObjectInputStream(in);\n  }\n"
    assert (6, "JAST-DESER-001") in _hits(body)


@pytest.mark.xfail(strict=True, reason="a parameter is not an assignment: a name tainted in another method "
                                       "still taints a parameter that only ever receives literals")
def test_parameter_that_only_receives_literals_is_clean():
    body = ("  void a(HttpServletRequest request) throws Exception {\n"
            "    String cmd = request.getParameter(\"c\");\n    Runtime.getRuntime().exec(cmd);\n  }\n"
            "  void b(String cmd) throws Exception {\n    Runtime.getRuntime().exec(cmd);\n  }\n"
            "  void c() throws Exception {\n    b(\"ls\");\n  }\n")
    assert _hits(body) == [(7, "JAST-CMD-001")]
