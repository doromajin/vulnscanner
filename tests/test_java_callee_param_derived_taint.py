"""Java: a callee parameter seeded from its in-file caller also taints locals derived from it."""
from vulnscanner.analyzers.ast_java import JavaASTAnalyzer


def _rules(src):
    return sorted((f.rule_id, f.line_number) for f in JavaASTAnalyzer().analyze("A.java", src) if not f.rule_id.endswith("-SAFE"))


_SRC = '''import java.sql.*;
import org.springframework.web.bind.annotation.*;
@RestController
public class A {
  @PostMapping("/x")
  public String h(@RequestParam String account, @RequestParam String op) {
    return inj(account + " " + op);
  }
  protected String inj(String name) {
    String query = "";
    try (Connection c = ds.getConnection()) {
      query = "SELECT * FROM t WHERE n = '" + name + "'";
      try (Statement st = c.createStatement()) {
        ResultSet rs = st.executeQuery(query);
      }
    } catch (Exception e) { }
    return "";
  }
}
'''


def test_preinitialised_local_reassigned_in_try_with_resources_is_flagged():
    assert _rules(_SRC) == [("JAST-SQL-001", 14)]


def test_declared_without_initialiser_is_flagged():
    assert _rules(_SRC.replace('String query = "";', "String query;")) == [("JAST-SQL-001", 14)]


def test_derived_through_second_local_is_flagged():
    src = _SRC.replace('      query = "SELECT', '      String t = name.trim();\n      query = "SELECT').replace("'\" + name", "'\" + t")
    assert _rules(src) == [("JAST-SQL-001", 15)]


def test_caller_passes_literal_is_clean():
    assert _rules(_SRC.replace('inj(account + " " + op)', 'inj("fixed")')) == []


def test_reassigned_literal_only_is_clean():
    src = _SRC.replace('"SELECT * FROM t WHERE n = \'" + name + "\'"', '"SELECT 1"')
    assert _rules(src) == []


def test_preparedstatement_with_bound_param_is_clean():
    src = _SRC.replace('Statement st = c.createStatement()', 'PreparedStatement st = c.prepareStatement("SELECT * FROM t WHERE n = ?")') \
              .replace("st.executeQuery(query)", "st.executeQuery()")
    assert _rules(src) == []
