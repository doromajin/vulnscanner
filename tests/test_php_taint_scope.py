"""Known limits of the PHP taint map (`ast_php._build_taint`).

`tainted` is one dict for the whole file, keyed by variable name, with no function or method scope:

* a name that is tainted in one method is tainted in every method of the file, so an unrelated
  clean parameter of the same name reaches a sink as if it carried client data (found by rescanning
  snipe-it: `$model = $request->handleImages($model)` in store() made update() report a finding,
  and removing that unrelated line made the finding vanish);
* a value stored on an object other than `$this` (`$o->f = $request->input()`) is not tracked, so a
  later `... . $o->f` reaches a sink unnoticed.

Both are marked xfail(strict=True): when the taint map gets proper scopes the test starts passing
and the strict marker fails the run, which is the cue to delete the marker.
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


@pytest.mark.xfail(strict=True, reason="taint map is file-wide: a clean parameter inherits taint from another method")
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
