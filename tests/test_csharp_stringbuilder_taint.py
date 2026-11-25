"""C#: a StringBuilder that received tainted text is tainted, and so is its ToString()."""
from vulnscanner.analyzers.ast_csharp import CSharpASTAnalyzer

_HEAD = "public class C : ControllerBase {\n [HttpGet] public IActionResult X(string id) {\n"
_TAIL = "  return Ok();\n }\n}\n"


def _rules(body):
    return sorted((f.rule_id, f.line_number) for f in CSharpASTAnalyzer().analyze("C.cs", _HEAD + body + _TAIL))


def test_append_tainted_then_fromsqlraw_is_flagged():
    body = ('  var sb = new StringBuilder("SELECT * FROM t WHERE n=");\n'
            "  sb.Append(id);\n"
            "  var r = ctx.Movies.FromSqlRaw(sb.ToString());\n")
    assert _rules(body) == [("CSAST-SQL-001", 5)]


def test_interpolated_hole_in_append_taints_builder_for_sqlcommand():
    body = ("  var sb = new StringBuilder();\n"
            '  sb.Append($"SELECT * FROM t WHERE n={id}");\n'
            "  var c = new SqlCommand(sb.ToString(), conn);\n")
    assert _rules(body) == [("CSAST-SQL-001", 5)]


def test_appendformat_insert_and_chained_append_are_tainted():
    for stmt in ('sb.AppendFormat("{0}", id);', "sb.Insert(0, id);", 'sb.Append("a").Append(id);',
                 'sb.AppendLine(id);'):
        body = f"  var sb = new StringBuilder();\n  {stmt}\n  var r = ctx.Movies.FromSqlRaw(sb.ToString());\n"
        assert _rules(body) == [("CSAST-SQL-001", 5)], stmt


def test_literal_only_builder_is_clean():
    body = ('  var sb = new StringBuilder();\n  sb.Append("SELECT 1 ");\n  sb.AppendLine("FROM t");\n'
            "  var r = ctx.Movies.FromSqlRaw(sb.ToString());\n")
    assert _rules(body) == []


def test_interpolated_and_parameterised_calls_stay_clean():
    assert _rules("  var r = ctx.Movies.FromSqlInterpolated($\"SELECT * FROM t WHERE n={id}\");\n") == []
    body = ('  var sb = new StringBuilder();\n  sb.Append("SELECT * FROM t WHERE n=@n");\n'
            '  var r = ctx.Movies.FromSqlRaw(sb.ToString(), new SqlParameter("@n", id));\n')
    assert _rules(body) == []


def test_tainted_value_in_a_different_builder_does_not_leak():
    body = ('  var a = new StringBuilder();\n  var b = new StringBuilder("SELECT 1");\n  a.Append(id);\n'
            "  var r = ctx.Movies.FromSqlRaw(b.ToString());\n")
    assert _rules(body) == []
