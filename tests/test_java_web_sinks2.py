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
