"""Java: a method called update/query is a JDBC sink only on a JDBC-looking receiver."""
import pytest

from vulnscanner.analyzers.ast_java import JavaASTAnalyzer


def _rules(src):
    return sorted((f.rule_id, f.line_number) for f in JavaASTAnalyzer().analyze("A.java", src) if not f.rule_id.endswith("-SAFE"))


def _cls(decl, call):
    return ("import org.springframework.web.bind.annotation.*;\n@RestController\npublic class A {\n"
            f"  {decl}\n"
            '  @GetMapping("/x")\n'
            "  public String h(@RequestParam String x) throws Exception {\n"
            f"    {call}\n    return \"\";\n  }}\n}}\n")


@pytest.mark.parametrize("decl,call", [
    ("", 'MessageDigest md = MessageDigest.getInstance("SHA-256"); md.update(x.getBytes());'),
    ("", 'MessageDigest md = MessageDigest.getInstance("SHA-256"); md.update(("a" + x).getBytes());'),
    ("", 'Mac mac = Mac.getInstance("HmacSHA256"); mac.update(x.getBytes());'),
    ("", 'Signature sig = Signature.getInstance("SHA256withRSA"); sig.update(x.getBytes());'),
    ("", 'Cipher c = Cipher.getInstance("AES"); byte[] b = c.update(x.getBytes());'),
    ("private MessageDigest digest;", "digest.update(x.getBytes());"),
])
def test_crypto_update_is_not_a_sql_sink(decl, call):
    assert _rules(_cls(decl, call)) == []


@pytest.mark.parametrize("decl,call", [
    ("private JdbcTemplate jdbcTemplate;", 'jdbcTemplate.update("DELETE FROM t WHERE n = \'" + x + "\'");'),
    ("private JdbcTemplate jdbc;", 'jdbc.update("DELETE FROM t WHERE n = \'" + x + "\'");'),
    ("private NamedParameterJdbcTemplate tpl;", 'tpl.update("DELETE FROM t WHERE n = \'" + x + "\'", new HashMap<>());'),
    ("", 'Statement stmt = conn.createStatement(); stmt.executeUpdate("DELETE FROM t WHERE n = \'" + x + "\'");'),
])
def test_real_jdbc_receivers_are_still_flagged(decl, call):
    assert [r for r, _ in _rules(_cls(decl, call))] == ["JAST-SQL-001"]


def test_unknown_receiver_with_parameterised_sql_is_clean():
    assert _rules(_cls("private JdbcTemplate jdbcTemplate;", 'jdbcTemplate.update("DELETE FROM t WHERE n = ?", x);')) == []


def test_unqualified_call_to_own_update_method_is_not_a_sql_sink():
    src = ("import org.springframework.web.bind.annotation.*;\n@RestController\npublic class A {\n"
           "  public void update(byte[] b, int n) { }\n"
           '  @GetMapping("/x")\n  public String h(@RequestParam String x) {\n'
           "    update(x.getBytes(), 1);\n    return \"\";\n  }\n}\n")
    assert _rules(src) == []
