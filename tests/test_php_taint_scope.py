"""Scope of the PHP taint map (`ast_php._build_taint_scoped`).

Variables belong to one method or named function (or to the file's top level).  Before, `tainted`
was one dict for the whole file keyed by variable name: a name tainted in one method was tainted in
every method, so an unrelated clean parameter of the same name reached a sink as if it carried client
data (found by rescanning snipe-it: `$model = $request->handleImages($model)` in store() made
update() report a finding, and removing that unrelated line made the finding vanish).

Still open, marked xfail(strict=True) so the run fails the day it is fixed: a value stored on an
object other than `$this` (`$o->f = $request->input()`) is not tracked, so a later `... . $o->f`
reaches a sink unnoticed.
"""
import pytest

from vulnscanner.analyzers.ast_php import PhpASTAnalyzer

_PATH = "app/Http/Controllers/X.php"


def _sql_lines(php: str) -> list[int]:
    return sorted({f.line_number for f in PhpASTAnalyzer().analyze(_PATH, php)
                   if f.rule_id.startswith("PHAST-SQL")})


def test_direct_flow_in_one_method_is_flagged():
    php = ("<?php\nclass C {\n    public function b(Request $request) {\n"
           "        $m = $request->input('x');\n"
           "        return DB::select('select * from t where a = ' . $m);\n    }\n}\n")
    assert _sql_lines(php) == [5]


def test_clean_parameter_is_not_tainted_by_another_method_using_the_same_name():
    php = ("<?php\nclass C {\n    public function a(Request $request) {\n"
           "        $m = $request->input('x');\n        return $m;\n    }\n"
           "    public function b($m) {\n"
           "        return DB::select('select * from t where a = ' . $m);\n    }\n}\n")
    assert _sql_lines(php) == []


@pytest.mark.xfail(strict=True, reason="values stored on objects other than $this are not tracked")
def test_value_stored_on_another_object_is_tracked():
    php = ("<?php\nclass C {\n    public function b(Request $request, $o) {\n"
           "        $o->f = $request->input('x');\n"
           "        return DB::select('select * from t where a = ' . $o->f);\n    }\n}\n")
    assert _sql_lines(php) == [5]


# ── flows that must survive the scoping ───────────────────────────────────────────────────

_FLOWS = {
    "this_method": (
        "<?php\nclass C {\n  public function a(Request $request) {\n    return $this->h($request->input('x'));\n  }\n"
        "  private function h($v) {\n    return DB::select('select * from t where a = ' . $v);\n  }\n}\n", [7]),
    "self_static_method": (
        "<?php\nclass C {\n  public function a(Request $request) {\n    return self::h($request->input('x'));\n  }\n"
        "  private static function h($v) {\n    return DB::select('select * from t where a = ' . $v);\n  }\n}\n", [7]),
    "plain_function": (
        "<?php\nfunction run($q) {\n  return mysql_query('select ' . $q);\n}\nrun($_GET['q']);\n", [3]),
    "global_statement": (
        "<?php\n$id = $_GET['id'];\nfunction f() {\n  global $id;\n  return mysql_query('select ' . $id);\n}\n", [5]),
    "closure_use": (
        "<?php\nclass C {\n  public function a(Request $request) {\n    $v = $request->input('x');\n"
        "    $f = function () use ($v) { return DB::select('select ' . $v); };\n    return $f();\n  }\n}\n", [5]),
    "arrow_function": (
        "<?php\nclass C {\n  public function a(Request $request) {\n    $v = $request->input('x');\n"
        "    $f = fn() => DB::select('select ' . $v);\n    return $f();\n  }\n}\n", [5]),
    "this_property_across_methods": (
        "<?php\nclass C {\n  private $q;\n  public function a(Request $request) { $this->q = $request->input('x'); }\n"
        "  public function b() { return DB::select('select ' . $this->q); }\n}\n", [5]),
    "top_level_script": (
        "<?php\n$id = $_GET['id'];\nmysql_query('select * from t where id = ' . $id);\n", [3]),
    "function_returning_tainted": (
        "<?php\nfunction src() { return $_GET['x']; }\nfunction use_it() { $v = src(); return mysql_query('select ' . $v); }\n", [3]),
}


@pytest.mark.parametrize("name", sorted(_FLOWS))
def test_legitimate_flow_is_still_found(name):
    php, expected = _FLOWS[name]
    assert _sql_lines(php) == expected


def test_helper_called_only_with_literals_is_not_flagged():
    php = ("<?php\nclass C {\n  public function a() { return $this->h('abc'); }\n"
           "  private function h($v) { return DB::select('select ' . $v); }\n}\n")
    assert _sql_lines(php) == []


def test_helper_reached_from_two_callers_is_flagged_when_one_passes_data():
    php = ("<?php\nclass C {\n  public function a() { return $this->h('abc'); }\n"
           "  public function b(Request $request) { return $this->h($request->input('x')); }\n"
           "  private function h($v) { return DB::select('select ' . $v); }\n}\n")
    assert _sql_lines(php) == [5]
