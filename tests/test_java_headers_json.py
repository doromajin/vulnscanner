"""Java round 3: HTTP header/CRLF injection (CWE-113), JSONP callback, unsafe JSON/XML deserialization.
Each group has TP / FP / FN cases."""
from vulnscanner.analyzers.ast_java import JavaASTAnalyzer

_H = ("import javax.servlet.http.*;\nimport java.io.*;\n"
      "import org.springframework.web.bind.annotation.*;\n"
      "import com.alibaba.fastjson.JSON;\nimport com.alibaba.fastjson.JSONObject;\n"
      "import com.alibaba.fastjson.JSONArray;\nimport com.alibaba.fastjson.support.spring.JSONPObject;\n"
      "import org.springframework.http.converter.json.MappingJacksonValue;\n"
      "import com.fasterxml.jackson.databind.ObjectMapper;\n"
      "import com.thoughtworks.xstream.XStream;\n"
      "public class A {\n")


def _rules(body: str, header: str = _H) -> set:
    src = header + body + "}\n"
    return {f.rule_id for f in JavaASTAnalyzer().analyze("A.java", src)}


def _m(stmts: str, params: str = "@RequestParam String v, HttpServletResponse response") -> str:
    return f"  @RequestMapping(\"/x\")\n  public String h({params}) throws Exception {{\n{stmts}\n    return \"\";\n  }}\n"


# ── 1. header / CRLF ─────────────────────────────────────────────────────────
def test_header_tp():
    for s in ['response.setHeader("X-A", v);',
              'response.addHeader("X-A", v);',
              'response.setHeader("Location", v);',
              'response.addHeader(v, "x");',
              'javax.servlet.http.Cookie c = new Cookie("a", v);\n response.addCookie(c);',
              'response.addHeader("X-A", "p" + v);']:
        assert "JAST-HEADER-001" in _rules(_m(s)), s


def test_header_tp_request_source():
    r = _rules(_m('response.setHeader("t", request.getParameter("t"));',
                  "HttpServletRequest request, HttpServletResponse response"))
    assert "JAST-HEADER-001" in r


def test_header_fp_safe_values():
    for s in ['response.setHeader("X-A", "fixed");',
              'response.setHeader("X-A", java.net.URLEncoder.encode(v, "UTF-8"));',
              'response.setHeader("X-A", v.replaceAll("[\\r\\n]", ""));',
              'String s = v.replaceAll("[^a-zA-Z0-9]", "");\n response.setHeader("X-A", s);',
              'response.setHeader("X-A", org.springframework.web.util.UriUtils.encode(v, "UTF-8"));',
              'response.setHeader("X-A", org.apache.commons.lang3.StringUtils.remove(v, "\\n"));',
              'Cookie c = new Cookie("a", "fixed");\n response.addCookie(c);',
              'java.util.Map<String,String> m = new java.util.HashMap<>();\n m.put("a", v);']:
        assert "JAST-HEADER-001" not in _rules(_m(s)), s


def test_header_fp_cors_header_left_to_cors_analyzer():
    assert "JAST-HEADER-001" not in _rules(_m('response.setHeader("Access-Control-Allow-Origin", v);'))


def test_header_fn_guard_non_response_receiver():
    # a header setter on a non-response object is not flagged
    assert "JAST-HEADER-001" not in _rules(_m('conn.setHeader("X-A", v);'))


# ── 2. JSONP ─────────────────────────────────────────────────────────────────
_CB = "@RequestParam String callback, HttpServletResponse response"


def test_jsonp_tp():
    for s in ['String json = "{}";\n response.getWriter().write(callback + "(" + json + ")");',
              'MappingJacksonValue mv = new MappingJacksonValue("x");\n mv.setJsonpFunction(v);',
              'JSONPObject o = new JSONPObject(v);',
              'String js = callback + "(" + "{}" + ")";\n response.getWriter().print(js);']:
        assert "JAST-JSONP-001" in _rules(_m(s, _CB if "callback" in s else
                                              "@RequestParam String v, HttpServletResponse response")), s


def test_jsonp_advice_informational():
    src = ("import org.springframework.web.bind.annotation.ControllerAdvice;\n"
           "import org.springframework.web.servlet.mvc.method.annotation.AbstractJsonpResponseBodyAdvice;\n"
           "@ControllerAdvice\npublic class J extends AbstractJsonpResponseBodyAdvice {\n"
           "  public J() { super(\"callback\", \"jsonp\"); }\n}\n")
    assert "JAST-JSONP-002" in {f.rule_id for f in JavaASTAnalyzer().analyze("J.java", src)}


def test_jsonp_fp():
    for s in ['String json = "{}";\n response.getWriter().write("cb(" + json + ")");',
              'MappingJacksonValue mv = new MappingJacksonValue("x");\n mv.setJsonpFunction("fixed");',
              'JSONPObject o = new JSONPObject("fixed");',
              'String q = "SELECT " + v;\n response.getWriter().write("n (" + q + ")");']:
        assert "JAST-JSONP-001" not in _rules(_m(s)), s


def test_jsonp_fn_guard_plain_concat_not_function_position():
    assert "JAST-JSONP-001" not in _rules(_m('String a = "x" + v + "(y)";'))


# ── 3. JSON / XML deserialization ───────────────────────────────────────────
def test_deser_tp():
    for s in ['JSON.parseObject(v);', 'JSON.parse(v);', 'JSONObject.parseObject(v);',
              'JSON.parseArray(v);', 'JSON.parseObject(v, Feature.SupportNonPublicField);']:
        assert "JAST-DESER-003" in _rules(_m(s)), s
    assert "JAST-DESER-004" in _rules(_m('ObjectMapper om = new ObjectMapper();\n om.enableDefaultTyping();'))
    assert "JAST-DESER-004" in _rules(_m(
        'ObjectMapper om = new ObjectMapper();\n om.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);'))
    assert "JAST-DESER-005" in _rules("  @com.fasterxml.jackson.annotation.JsonTypeInfo(use = com.fasterxml.jackson.annotation.JsonTypeInfo.Id.CLASS)\n  Object field;\n")
    assert "JAST-DESER-006" in _rules(_m('XStream xs = new XStream();\n xs.fromXML(v);'))


def test_deser_fp():
    for s in ['JSON.parseObject("{}");',
              'JSON.toJSONString(v);',
              'ObjectMapper om = new ObjectMapper();\n om.readValue(v, java.util.Map.class);',
              'ObjectMapper om = new ObjectMapper();\n om.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().build());',
              'XStream xs = new XStream();\n xs.allowTypes(new Class[]{String.class});\n xs.fromXML(v);',
              'XStream xs = new XStream();\n xs.fromXML("<a/>");']:
        r = _rules(_m(s))
        assert not ({"JAST-DESER-003", "JAST-DESER-004", "JAST-DESER-006"} & r), s


def test_deser_fn_guard_no_fastjson_import():
    src = ("public class B {\n  public Object h(String v) { return JSON.parse(v); }\n}\n")
    assert "JAST-DESER-003" not in {f.rule_id for f in JavaASTAnalyzer().analyze("B.java", src)}
