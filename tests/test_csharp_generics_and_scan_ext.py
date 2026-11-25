"""C# analysis: generic method calls (Dapper Query<T>), Path.Combine propagation, and .cs files being scanned at all."""
from vulnscanner.analyzers.ast_csharp import CSharpASTAnalyzer
from vulnscanner.fetcher.local import _SCAN_EXTENSIONS

_HEAD = "public class C : ControllerBase {\n [HttpGet] public IActionResult X(string id) {\n"
_TAIL = "  return Ok();\n }\n}\n"


def _rules(body):
    return sorted((f.rule_id, f.line_number) for f in CSharpASTAnalyzer().analyze("C.cs", _HEAD + body + _TAIL))


def test_dapper_generic_query_with_tainted_sql_is_flagged():
    assert _rules('  var r = conn.Query<Foo>("SELECT * FROM t WHERE n=" + id);\n') == [("CSAST-SQL-001", 3)]


def test_dapper_generic_query_through_a_local_is_flagged():
    body = '  var s = "SELECT 1 WHERE n=" + id;\n  var r = conn.QueryFirstOrDefault<Foo>(s);\n'
    assert _rules(body) == [("CSAST-SQL-001", 4)]


def test_dapper_generic_query_with_literal_sql_is_clean():
    assert _rules('  var r = conn.Query<Foo>("SELECT 1");\n') == []


def test_dapper_generic_query_with_bound_parameter_is_clean():
    assert _rules('  var r = conn.Query<Foo>("SELECT * FROM t WHERE n=@n", new { n = id });\n') == []


def test_path_combine_keeps_taint_of_the_user_segment():
    assert _rules("  var b = System.IO.File.ReadAllBytes(Path.Combine(root, id));\n") == [("CSAST-PATH-001", 3)]


def test_path_combine_of_literals_is_clean():
    assert _rules('  var b = System.IO.File.ReadAllBytes(Path.Combine(root, "a.txt"));\n') == []


def test_cs_files_are_scanned():
    assert ".cs" in _SCAN_EXTENSIONS


def test_directory_exists_alone_is_not_a_path_traversal_sink():
    assert _rules("  var ok = Directory.Exists(id);\n") == []


def test_directory_delete_with_tainted_path_is_still_flagged():
    assert _rules("  Directory.Delete(id, true);\n") == [("CSAST-PATH-001", 3)]


def test_delete_on_a_service_is_not_a_file_sink():
    assert _rules("  _blocklistService.Delete(id);\n") == []


def test_get_files_on_a_service_is_not_a_directory_sink():
    assert _rules("  var f = _mediaFileService.GetFiles(id);\n") == []


def test_file_delete_with_tainted_path_is_flagged_even_when_fully_qualified():
    assert _rules("  System.IO.File.Delete(id);\n") == [("CSAST-PATH-001", 3)]


def test_delete_async_on_a_repository_is_not_ssrf():
    assert _rules("  await _repo.DeleteAsync(id);\n") == []


def test_http_client_get_async_with_tainted_url_is_flagged():
    assert _rules("  var r = await _httpClient.GetAsync(id);\n") == [("CSAST-SSRF-001", 3)]


def test_get_string_async_is_flagged_whatever_the_receiver_is_called():
    assert _rules("  var r = await c.GetStringAsync(id);\n") == [("CSAST-SSRF-001", 3)]


def test_very_long_concatenation_chain_does_not_exhaust_the_recursion_limit():
    chain = " + ".join('"a%d"' % i for i in range(3000))
    code = "public class C {\n void X() {\n  var s = %s;\n }\n}\n" % chain
    CSharpASTAnalyzer().analyze("C.cs", code)
