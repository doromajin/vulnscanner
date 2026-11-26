"""Java web sinks, round 2 (java-sec-code gaps): SSRF client APIs, CORS, MyBatis ${}, reflected XSS,
header/JSONP/fastjson.  Each group has TP / FP / FN cases."""
from vulnscanner.analyzers.ast_java import JavaASTAnalyzer

_H = ("import javax.servlet.http.*;\nimport java.io.*;\n"
      "import org.springframework.web.bind.annotation.*;\n"
      "import org.springframework.web.client.RestTemplate;\n"
      "import org.springframework.web.reactive.function.client.WebClient;\n"
      "import cn.hutool.http.HttpUtil;\nimport org.apache.http.client.fluent.Request;\n"
      "import org.apache.http.client.methods.HttpGet;\n"
      "public class A {\n")


def _rules(body: str, header: str = _H) -> set:
    src = header + body + "}\n"
    return {f.rule_id for f in JavaASTAnalyzer().analyze("A.java", src)}


def _m(stmts: str, params: str = "@RequestParam String url") -> str:
    return f"  @RequestMapping(\"/x\")\n  public String h({params}) throws Exception {{\n{stmts}\n    return \"\";\n  }}\n"


# ── 1. SSRF ──────────────────────────────────────────────────────────────────
_SSRF_TP = [
    "RestTemplate rt2 = new RestTemplate();\n rt2.getForObject(url, String.class);",
    "new RestTemplate().exchange(url, null, null, String.class);",
    "WebClient.create().get().uri(url).retrieve().bodyToMono(String.class).block();",
    "HttpUtil.get(url);",
    "HttpUtil.createGet(url).execute();",
    "Request.Get(url).execute();",
    "new okhttp3.Request.Builder().url(url).build();",
    "new HttpGet(url);",
]


def test_ssrf_tp():
    for s in _SSRF_TP:
        assert "JAST-SSRF-001" in _rules(_m(s)) or "JAST-SSRF-002" in _rules(_m(s)), s


def test_ssrf_fp_literal_and_unrelated():
    for s in ['RestTemplate rt2 = new RestTemplate();\n rt2.getForObject("http://a.example/x", String.class);',
              'HttpUtil.get("http://a.example/x");',
              'Request.Get("http://a.example/x").execute();',
              'WebClient.create().get().uri("/x").retrieve();',
              'new okhttp3.Request.Builder().url("http://a.example").build();',
              'java.util.Map<String,String> m = new java.util.HashMap<>();\n m.put(url, url);\n m.get(url);']:
        r = _rules(_m(s))
        assert "JAST-SSRF-001" not in r and "JAST-SSRF-002" not in r, s


def test_ssrf_fn_guard_other_param_not_url():
    # tainted value in a non-URL position (body/ variables) is not flagged
    r = _rules(_m('RestTemplate rt2 = new RestTemplate();\n rt2.postForObject("http://a.example/x", url, String.class);'))
    assert "JAST-SSRF-002" not in r


# ── 2. CORS ──────────────────────────────────────────────────────────────────
from vulnscanner.analyzers.cors_analyzer import CORSAnalyzer


def _cors(src: str) -> set:
    return {f.rule_id for f in CORSAnalyzer().analyze("A.java", src)}


def _ctl(stmts: str) -> str:
    return ("import javax.servlet.http.*;\nimport org.springframework.web.bind.annotation.*;\n"
            "@RestController\npublic class C {\n  @GetMapping(\"/x\")\n"
            "  public String h(HttpServletRequest request, HttpServletResponse response) {\n"
            f"{stmts}\n    return \"\";\n  }}\n}}\n")


def test_cors_reflected_origin_tp():
    assert "CORS-011" in _cors(_ctl(
        '    String origin = request.getHeader("Origin");\n'
        '    response.setHeader("Access-Control-Allow-Origin", origin);\n'
        '    response.setHeader("Access-Control-Allow-Credentials", "true");'))
    assert "CORS-011" in _cors(_ctl(
        '    response.addHeader("Access-Control-Allow-Origin", request.getHeader("origin"));'))


def test_cors_wildcard_and_config_tp():
    assert "CORS-012" in _cors(_ctl('    response.setHeader("Access-Control-Allow-Origin", "*");'))
    cfg = ("class K {\n void f(org.springframework.web.cors.CorsConfiguration c) {\n"
           '  c.addAllowedOrigin("*");\n  c.setAllowCredentials(true);\n }\n}\n')
    assert "CORS-012" in _cors(cfg)
    reg = 'class K { void f(R r){ r.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true); } }\n'
    assert "CORS-012" in _cors(reg)


def test_cors_fp_constant_allowlist_and_validated():
    assert not _cors(_ctl('    response.setHeader("Access-Control-Allow-Origin", "https://app.example.org");'))
    assert not _cors(_ctl(
        '    String origin = request.getHeader("Origin");\n'
        '    if (!ALLOWED.contains(origin)) { return "no"; }\n'
        '    response.setHeader("Access-Control-Allow-Origin", origin);'))
    assert not _cors(_ctl(
        '    String origin = request.getHeader("Origin");\n'
        '    if (origin != null && SecurityUtil.checkURL(origin) == null) { return "no"; }\n'
        '    response.setHeader("Access-Control-Allow-Origin", origin);'))
    assert not _cors('class K { void f(C c){ c.addAllowedOrigin("https://a.example.org"); } }\n')


def test_cors_fn_guard_unrelated_header():
    assert not _cors(_ctl('    String o = request.getHeader("Origin");\n    response.setHeader("X-Origin-Seen", o);'))


# ── 3. MyBatis ${} ───────────────────────────────────────────────────────────
from vulnscanner.analyzers.mybatis import MyBatisAnalyzer


def _mb(path: str, src: str) -> list:
    return MyBatisAnalyzer().analyze(path, src)


_XML_HEAD = '<?xml version="1.0"?>\n<mapper namespace="a.UserMapper">\n'


def test_mybatis_xml_tp():
    f = _mb("UserMapper.xml", _XML_HEAD + '  <select id="s" resultType="U">\n    select * from users order by ${order} asc\n'
            '  </select>\n</mapper>\n')
    assert [(x.rule_id, x.line_number, x.severity.name) for x in f] == [("MYBATIS-001", 4, "HIGH")]
    f = _mb("UserMapper.xml", _XML_HEAD + "  <select id=\"s\">\n select * from users where name like '%${_parameter}%'\n  </select>\n</mapper>\n")
    assert f and f[0].severity.name == "HIGH"


def test_mybatis_annotation_tp():
    src = ('public interface M {\n  @Select("select * from users where username = \'${username}\'")\n'
           '  User find(@Param("username") String username);\n}\n')
    f = _mb("M.java", src)
    assert [(x.rule_id, x.line_number, x.severity.name) for x in f] == [("MYBATIS-002", 2, "HIGH")]


def test_mybatis_fp_bound_params_comments_conditions():
    assert not _mb("U.xml", _XML_HEAD + '  <select id="s">\n select * from users where username = #{name}\n  </select>\n</mapper>\n')
    assert not _mb("U.xml", _XML_HEAD + '  <!-- old: order by ${order} -->\n  <select id="s">\n select 1\n'
                   '  <if test="${x} != null"> and a = #{a}</if>\n  </select>\n</mapper>\n')
    assert not _mb("pom.xml", '<project><x>${java.version}</x></project>\n')
    assert not _mb("M.java", 'public interface M {\n  @Select("select * from users where username = #{username}")\n  User f(String username);\n}\n')
    assert not _mb("M.java", 'public class M {\n  // @Select("x ${y}")\n  String s = "${placeholder}";\n}\n')


def test_mybatis_fn_other_annotation_mixed():
    src = ('public interface M {\n  @Update({"update t set a = #{a}", "where id = ${id}"})\n  int u(String a, String id);\n}\n')
    assert [x.rule_id for x in _mb("M.java", src)] == ["MYBATIS-002"]
