"""Java XXE parser sinks (SAXBuilder / SAXReader / Digester / XMLReader / XBProjector), method-scoped
safe-configuration suppression, unannotated Spring handler parameters (SpEL), script-engine sinks and
the Class.forName / basename false positives.  Each group has a TP, a FP and an FN case."""
import pytest

from vulnscanner.analyzers.ast_java import JavaASTAnalyzer

_H = ("import javax.servlet.http.*;\nimport java.io.*;\nimport org.xml.sax.*;\n"
      "import org.springframework.web.bind.annotation.*;\npublic class A {\n")


def _hits(body: str) -> list[tuple[int, str]]:
    src = _H + body + "}\n"
    return sorted({(f.line_number, f.rule_id) for f in JavaASTAnalyzer().analyze("A.java", src)})


def _rules(body: str) -> set[str]:
    return {r for _, r in _hits(body)}


def _m(stmts: str, params: str = "HttpServletRequest request") -> str:
    return f"  @RequestMapping(\"/x\")\n  public String h({params}) throws Exception {{\n{stmts}\n    return \"\";\n  }}\n"


_BODY = '    String body = request.getParameter("b");\n'

_HARDEN = ('    {v}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
           '    {v}.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
           '    {v}.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\n')

# (declaration line, variable, parse line)
_PARSERS = [
    ("XMLReader r = XMLReaderFactory.createXMLReader();", "r", "r.parse(new InputSource(new StringReader(body)));"),
    ("SAXBuilder r = new SAXBuilder();", "r", "r.build(new InputSource(new StringReader(body)));"),
    ("SAXReader r = new SAXReader();", "r", "r.read(new InputSource(new StringReader(body)));"),
    ("Digester r = new Digester();", "r", "r.parse(new StringReader(body));"),
]


# ── a. parser sinks ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("decl,v,parse", _PARSERS)
def test_parser_with_request_input_is_reported(decl, v, parse):
    assert "JAST-XXE-002" in _rules(_m(_BODY + f"    {decl}\n    {parse}"))


@pytest.mark.parametrize("decl,v,parse", _PARSERS)
def test_parser_with_constant_input_is_not_reported(decl, v, parse):
    body = _m(f'    String body = "<a/>";\n    {decl}\n    {parse}')
    assert "JAST-XXE-002" not in _rules(body)


def test_parser_input_from_input_stream_and_request_body_annotation():
    a = _m("    SAXReader r = new SAXReader();\n    r.read(request.getInputStream());")
    b = _m("    SAXBuilder r = new SAXBuilder();\n    r.build(new StringReader(xml));", "@RequestBody String xml")
    assert "JAST-XXE-002" in _rules(a)
    assert "JAST-XXE-002" in _rules(b)


def test_xbprojector_with_request_input_is_reported():
    src = _m(_BODY + "    XBProjector p = new XBProjector();\n    p.projectXMLString(body, Foo.class);")
    assert "JAST-XXE-002" in _rules(src)


def test_unrelated_read_and_build_calls_are_not_xxe_sinks():
    src = _m(_BODY + "    StringBuilder sb = new StringBuilder();\n    sb.append(body);\n"
             "    Reader rd = new BufferedReader(new StringReader(body));\n    rd.read();")
    assert "JAST-XXE-002" not in _rules(src)


# ── b. method-scoped safe configuration ──────────────────────────────────────

@pytest.mark.parametrize("decl,v,parse", _PARSERS)
def test_hardened_parser_is_suppressed(decl, v, parse):
    assert "JAST-XXE-002" not in _rules(_m(_BODY + f"    {decl}\n" + _HARDEN.format(v=v) + f"    {parse}"))


def test_doctype_feature_alone_suppresses():
    src = _m(_BODY + "    SAXReader r = new SAXReader();\n"
             '    r.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
             "    r.read(new StringReader(body));")
    assert "JAST-XXE-002" not in _rules(src)


@pytest.mark.parametrize("factory", ["DocumentBuilderFactory", "SAXParserFactory"])
def test_factory_hardened_in_same_method_is_suppressed_but_plain_factory_is_reported(factory):
    plain = _m(f"    {factory} f = {factory}.newInstance();")
    safe = _m(f"    {factory} f = {factory}.newInstance();\n" + _HARDEN.format(v="f"))
    assert "JAST-XXE-001" in _rules(plain)
    assert "JAST-XXE-001" not in _rules(safe)


def test_secure_processing_with_external_general_entities_off_suppresses():
    src = _m("    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
             "    f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n"
             '    f.setFeature("http://xml.org/sax/features/external-general-entities", false);')
    assert "JAST-XXE-001" not in _rules(src)


def test_access_external_dtd_empty_suppresses_transformer_and_parser_factory():
    src = _m("    TransformerFactory t = TransformerFactory.newInstance();\n"
             '    t.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n'
             '    t.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");')
    assert "JAST-XXE-001" not in _rules(src)


def test_feature_set_to_the_unsafe_value_does_not_suppress():
    f = ('    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
         '    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);')
    g = ('    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
         '    f.setFeature("http://xml.org/sax/features/external-general-entities", true);\n'
         '    f.setFeature("http://xml.org/sax/features/external-parameter-entities", true);')
    h = ('    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
         '    f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);')
    for stmts in (f, g, h):
        assert "JAST-XXE-001" in _rules(_m(stmts))
    p = _m(_BODY + "    SAXReader r = new SAXReader();\n"
           '    r.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);\n'
           "    r.read(new StringReader(body));")
    assert "JAST-XXE-002" in _rules(p)


def test_xinclude_and_expand_entities_alone_do_not_suppress():
    src = _m("    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
             "    f.setXIncludeAware(false);\n    f.setExpandEntityReferences(false);")
    assert "JAST-XXE-001" in _rules(src)


def test_hardening_in_another_method_or_on_another_variable_does_not_suppress():
    other_method = ("  void cfg() throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
                    + _HARDEN.format(v="f") + "  }\n"
                    + _m("    DocumentBuilderFactory g = DocumentBuilderFactory.newInstance();"))
    assert _hits(other_method) == [(14, "JAST-XXE-001")]
    other_var = _m("    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
                   "    DocumentBuilderFactory g = DocumentBuilderFactory.newInstance();\n" + _HARDEN.format(v="f"))
    assert [r for _, r in _hits(other_var)].count("JAST-XXE-001") == 1


# ── c. SpEL / script sinks ───────────────────────────────────────────────────

def test_spel_unannotated_string_handler_parameter_is_tainted():
    src = _m("    ExpressionParser p = new SpelExpressionParser();\n    p.parseExpression(value).getValue();", "String value")
    assert "JAST-SPEL-001" in _rules(src)


def test_spel_with_literal_expression_and_non_handler_param_is_not_reported():
    lit = _m('    ExpressionParser p = new SpelExpressionParser();\n    p.parseExpression("1+1");', "String value")
    helper = ("  String run(String value) {\n    return new SpelExpressionParser().parseExpression(value).getValue().toString();\n  }\n")
    assert "JAST-SPEL-001" not in _rules(lit)
    assert "JAST-SPEL-001" not in _rules(helper)


def test_unannotated_non_string_handler_params_are_not_sources():
    src = _m("    new SpelExpressionParser().parseExpression(model.toString());", "Model model")
    assert "JAST-SPEL-001" not in _rules(src)


@pytest.mark.parametrize("stmt", [
    "Velocity.evaluate(ctx, new StringWriter(), \"t\", body);",
    "new GroovyShell().evaluate(body);",
    "GroovyShell sh = new GroovyShell();\n    sh.parse(body);",
    "ScriptEngine e = new ScriptEngineManager().getEngineByName(\"js\");\n    e.eval(body);",
])
def test_script_sinks_with_request_input_are_reported(stmt):
    assert "JAST-SCRIPT-001" in _rules(_m(_BODY + "    " + stmt))


@pytest.mark.parametrize("stmt", [
    "Velocity.evaluate(ctx, new StringWriter(), \"t\", \"hello\");",
    "new GroovyShell().evaluate(\"1+1\");",
    "ScriptEngine e = new ScriptEngineManager().getEngineByName(\"js\");\n    e.eval(\"1+1\");",
])
def test_script_sinks_with_constants_are_not_reported(stmt):
    assert "JAST-SCRIPT-001" not in _rules(_m(_BODY + "    " + stmt))


def test_eval_on_unrelated_receiver_is_not_a_script_sink():
    assert "JAST-SCRIPT-001" not in _rules(_m(_BODY + "    Calculator c = new Calculator();\n    c.eval(body);"))


# ── d. Class.forName / basename ──────────────────────────────────────────────

def test_class_forname_with_request_value_is_reported():
    assert ("JAST-REFLECT-001" in _rules(_m('    Class.forName(request.getParameter("c"));')))


def test_class_forname_with_config_injected_field_is_not_reported():
    body = ('  @Value("${spring.datasource.driver-class-name}")\n  private String driver;\n'
            + _m("    Class.forName(driver);"))
    assert _hits(body) == []


def test_class_forname_with_constant_is_not_reported():
    assert _hits(_m('    Class.forName("com.mysql.cj.jdbc.Driver");')) == []


def test_basename_normalised_value_does_not_reach_file_sink():
    plain = _m('    String n = request.getParameter("f");\n    new File("/tmp", n);')
    named = _m('    String n = new File(request.getParameter("f")).getName();\n    new File("/tmp", n);')
    fio = _m('    String n = FilenameUtils.getName(request.getParameter("f"));\n    new File("/tmp", n);')
    paren = _m('    String n = (new File(request.getParameter("f"))).getName();\n    new File("/tmp", n);')
    assert any(r.startswith("JAST-") for _, r in _hits(plain))
    assert not any("PATH" in r for _, r in _hits(paren))
    assert not any("PATH" in r for _, r in _hits(named))
    assert not any("PATH" in r for _, r in _hits(fio))


def test_hardening_inside_a_conditional_block_does_not_suppress():
    src = _m("    boolean secure = true;\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
             "    if (secure) {\n"
             '      f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n    }\n')
    assert "JAST-XXE-001" in _rules(src)


def test_hardening_on_an_object_derived_from_the_factory_suppresses():
    src = _m("    SAXParserFactory spf = SAXParserFactory.newInstance();\n    SAXParser sp = spf.newSAXParser();\n"
             "    XMLReader xr = sp.getXMLReader();\n"
             '    xr.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
             "    xr.parse(new InputSource(new StringReader(\"<a/>\")));")
    assert "JAST-XXE-001" not in _rules(src)
