"""Java sinks, round AE (java-sec-code / JavaVulnerableLab gaps): argv-array command injection,
String.format into script engines, unannotated handler parameters, cross-file RestTemplate SSRF,
JDBC URL injection, redirect:/forward: view names, RequestDispatcher, XXE parsers (dom4j, POI,
xlsx-streamer) and QLExpress.  Each group has TP / FP / FN-guard cases."""
from vulnscanner.analyzers.ast_java import (
    JavaASTAnalyzer, build_java_cross_file_context, set_java_cross_file_context)

_H = ("import javax.servlet.http.*;\nimport java.io.*;\nimport java.util.*;\n"
      "import org.springframework.web.bind.annotation.*;\n"
      "import org.springframework.web.servlet.ModelAndView;\n"
      "import org.springframework.web.servlet.view.RedirectView;\n"
      "import org.springframework.web.multipart.MultipartFile;\n"
      "@RestController\npublic class A {\n")


def _find(body: str, header: str = _H):
    src = header + body + "}\n"
    return [(f.rule_id, f.severity.name) for f in JavaASTAnalyzer().analyze("A.java", src)
            if not f.rule_id.endswith("-SAFE")]


def _rules(body: str) -> set:
    return {r for r, _ in _find(body)}


def _m(stmts: str, params: str = "String p") -> str:
    return f"  @GetMapping(\"/x\")\n  public String h({params}) throws Exception {{\n{stmts}\n    return \"\";\n  }}\n"


# ── 1. command injection through argv arrays ─────────────────────────────────
def test_cmd_array_forms_tp():
    for s in ['String[] c = new String[]{"sh", "-c", "ls " + p};\n ProcessBuilder b = new ProcessBuilder(c);',
              'String[] c = {"/bin/sh", "-c", p};\n new ProcessBuilder(c);',
              'Runtime.getRuntime().exec(new String[]{"sh", "-c", p});',
              'new ProcessBuilder(Arrays.asList("sh", "-c", p));',
              'new ProcessBuilder("sh", "-c", p);']:
        assert {"JAST-CMD-001", "JAST-CMD-002"} & _rules(_m(s)), s


def test_cmd_shell_dash_c_is_critical():
    assert ("JAST-CMD-002", "CRITICAL") in _find(_m('new ProcessBuilder("sh", "-c", p);'))
    assert ("JAST-CMD-002", "CRITICAL") in _find(_m('new ProcessBuilder(new String[]{"cmd", "/c", p});'))


def test_cmd_literal_array_is_clean():
    for s in ['String[] c = new String[]{"sh", "-c", "ls -la"};\n new ProcessBuilder(c);',
              'new ProcessBuilder(Arrays.asList("ls", "-la"));',
              'Runtime.getRuntime().exec(new String[]{"ls", "-la"});']:
        assert not ({"JAST-CMD-001", "JAST-CMD-002"} & _rules(_m(s))), s


def test_cmd_argument_injection_only_is_medium():
    assert ("JAST-CMD-002", "MEDIUM") in _find(_m('new ProcessBuilder("ls", p);'))
    assert ("JAST-CMD-001", "MEDIUM") in _find(_m('Runtime.getRuntime().exec(new String[]{"ls", p});'))
    # a tainted program name stays critical
    assert ("JAST-CMD-002", "CRITICAL") in _find(_m('new ProcessBuilder(p, "-l");'))


# ── 2. String.format / concatenation into script engines ─────────────────────
def test_script_engine_format_tp_and_literal_fp():
    pre = "javax.script.ScriptEngine engine = new javax.script.ScriptEngineManager().getEngineByName(\"js\");\n"
    assert "JAST-SCRIPT-001" in _rules(_m(pre + 'String s = String.format("load(\\"%s\\")", p);\n engine.eval(s);'))
    assert "JAST-SCRIPT-001" in _rules(_m(pre + 'engine.eval("print(" + p + ")");'))
    assert "JAST-SCRIPT-001" in _rules(_m(pre + 'engine.eval(java.text.MessageFormat.format("x{0}", p));'))
    assert "JAST-SCRIPT-001" not in _rules(_m(pre + 'engine.eval(String.format("load(\\"%s\\")", "fixed.js"));'))


# ── 3. unannotated handler parameters reach cross-file callees ───────────────
_CTRL = '''package c;
import org.springframework.web.bind.annotation.*;
@RestController
public class SSRF {
  private HttpService httpService;
  @GetMapping("/v")
  public String v(String url) { return httpService.RequestHttp(url, null); }
  @GetMapping("/ok")
  public String ok() { return httpService.RequestHttp("http://a.example/x", null); }
}
'''
_IMPL = '''package c;
import org.springframework.web.client.RestTemplate;
import javax.annotation.Resource;
public class HttpServiceImpl {
  @Resource
  private RestTemplate restTemplateBanRedirects;
  public String RequestHttp(String url, Object headers) {
    return restTemplateBanRedirects.exchange(url, null, null, String.class).getBody();
  }
}
'''


def test_cross_file_unannotated_param_ssrf():
    ctx = build_java_cross_file_context({"SSRF.java": _CTRL, "HttpServiceImpl.java": _IMPL})
    set_java_cross_file_context(ctx)
    try:
        rules = {f.rule_id for f in JavaASTAnalyzer().analyze("HttpServiceImpl.java", _IMPL)}
    finally:
        set_java_cross_file_context(None)
    assert "JAST-SSRF-002" in rules


def test_cross_file_literal_caller_is_clean():
    ctx = build_java_cross_file_context({"SSRF.java": _CTRL.replace("v(String url) { return httpService.RequestHttp(url, null)",
                                                                  'v(String url) { return httpService.RequestHttp("http://a.example", null)'),
                                         "HttpServiceImpl.java": _IMPL})
    set_java_cross_file_context(ctx)
    try:
        rules = {f.rule_id for f in JavaASTAnalyzer().analyze("HttpServiceImpl.java", _IMPL)}
    finally:
        set_java_cross_file_context(None)
    assert "JAST-SSRF-002" not in rules


def test_unannotated_param_not_a_handler_is_clean():
    # no mapping annotation: the parameter is not request data
    assert "JAST-CMD-002" not in _rules("  public String h(String p) throws Exception {\n"
                                        "    new ProcessBuilder(\"sh\", \"-c\", p);\n    return \"\";\n  }\n")


# ── 4. JDBC connection-string injection ──────────────────────────────────────
def test_jdbc_url_tp_fp():
    assert "JAST-JDBC-URL-001" in _rules(_m("java.sql.DriverManager.getConnection(p);").replace("java.sql.", ""))
    assert "JAST-JDBC-URL-001" in _rules(_m("byte[] b = java.util.Base64.getDecoder().decode(p);\n"
                                            "String u = new String(b);\n DriverManager.getConnection(u);"))
    assert "JAST-JDBC-URL-001" not in _rules(_m('DriverManager.getConnection("jdbc:h2:mem:t");'))
    # tainted credentials only: not a connection-string injection
    assert "JAST-JDBC-URL-001" not in _rules(_m('DriverManager.getConnection("jdbc:h2:mem:t", "sa", p);'))


# ── 5. Spring redirect:/forward: view names, RequestDispatcher ───────────────
def test_redirect_prefix_tp_fp():
    assert "JAST-REDIRECT-002" in _rules(_m('return "redirect:" + p;').replace('return "";', ""))
    assert "JAST-REDIRECT-002" in _rules(_m('ModelAndView mv = new ModelAndView("redirect:" + p);'))
    assert "JAST-REDIRECT-002" in _rules(_m("RedirectView rv = new RedirectView(p);"))
    # a literal path prefix: the value cannot change the host
    assert "JAST-REDIRECT-002" not in _rules(_m('String s = "redirect:/home/" + p;'))
    assert "JAST-REDIRECT-002" not in _rules(_m('String s = "redirect:/home";'))
    assert "JAST-REDIRECT-002" not in _rules(_m('RedirectView rv = new RedirectView("/home");'))


def test_forward_tp_fp():
    assert "JAST-FORWARD-001" in _rules(_m('String s = "forward:" + p;'))
    assert "JAST-FORWARD-001" in _rules(_m("request.getRequestDispatcher(p).forward(request, response);",
                                           "HttpServletRequest request, HttpServletResponse response, String p"))
    assert "JAST-FORWARD-001" in _rules(_m("ModelAndView mv = new ModelAndView(p);"))
    assert "JAST-FORWARD-001" not in _rules(_m('request.getRequestDispatcher("/WEB-INF/x.jsp").forward(request, response);',
                                               "HttpServletRequest request, HttpServletResponse response"))
    assert "JAST-FORWARD-001" not in _rules(_m('ModelAndView mv = new ModelAndView("home");'))


# ── 6. XXE parsers ───────────────────────────────────────────────────────────
def test_xxe_parsers_tp_fp():
    assert "JAST-XXE-003" in _rules(_m("org.dom4j.DocumentHelper.parseText(p);").replace("org.dom4j.", ""))
    assert "JAST-XXE-003" in _rules(_m("new XSSFWorkbook(f.getInputStream());", "MultipartFile f"))
    assert "JAST-XXE-003" in _rules(_m("OPCPackage.open(f.getInputStream());", "MultipartFile f"))
    assert "JAST-XXE-003" in _rules(_m("StreamingReader.builder().open(f.getInputStream());", "MultipartFile f"))
    assert "JAST-XXE-003" not in _rules(_m('DocumentHelper.parseText("<a/>");'))
    assert "JAST-XXE-003" not in _rules(_m('new XSSFWorkbook(new FileInputStream("t.xlsx"));'))


def test_xxe_hardened_method_suppresses():
    body = _m('javax.xml.parsers.DocumentBuilderFactory f = javax.xml.parsers.DocumentBuilderFactory.newInstance();\n'
              'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
              'DocumentHelper.parseText(p);')
    assert "JAST-XXE-003" not in _rules(body)


# ── 7. QLExpress is expression injection, not SQL injection ──────────────────
def test_qlexpress_is_code_injection():
    body = _m("ExpressRunner runner = new ExpressRunner();\n Object r = runner.execute(p, null, null, true, false);")
    rules = _rules(body)
    assert "JAST-SCRIPT-001" in rules and "JAST-SQL-001" not in rules
    lit = _rules(_m('ExpressRunner runner = new ExpressRunner();\n runner.execute("1+1", null, null, true, false);'))
    assert "JAST-SCRIPT-001" not in lit and "JAST-SQL-001" not in lit


def test_real_jdbc_execute_still_sql():
    assert "JAST-SQL-001" in _rules(_m("java.sql.Statement st = null;\n st.execute(p);"))
