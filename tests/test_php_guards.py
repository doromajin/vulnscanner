"""Validation guards in PHP: a value that was checked is not client data any more.

`if (in_array($sort, ['id', 'name'], true)) { ... $sort ... }` and
`if (!is_numeric($id)) { abort(404); } ... $id ...` leave a value the client could not choose freely.
The taint map stays flow-insensitive; a guard is a byte range in which the variable counts as clean.
What is NOT a guard matters as much: a check on another variable, a query outside the guarded
branch, a negative check that does not stop the request, `||` with an unrelated test, a loose
in_array over integers, an unanchored or permissive regex, a value reassigned inside the range.
"""
import pytest

from vulnscanner.analyzers.ast_php import PhpASTAnalyzer

_Q = "DB::select('select * from t where a = ' . $m);"


def _flagged(body: str) -> bool:
    php = ("<?php\nclass C {\n  public function b(Request $request) {\n    $m = $request->input('x');\n"
           + body + "\n  }\n}\n")
    return any(f.rule_id == "PHAST-SQL-001"
               for f in PhpASTAnalyzer().analyze("app/Http/Controllers/X.php", php))


GUARDED = {
    "in_array strict": "if (in_array($m, ['a','b'], true)) {\n return " + _Q + "\n}",
    "in_array loose over strings": "if (in_array($m, ['a','b'])) {\n return " + _Q + "\n}",
    "is_numeric": "if (is_numeric($m)) {\n return " + _Q + "\n}",
    "ctype_digit": "if (ctype_digit($m)) {\n return " + _Q + "\n}",
    "early return": "if (!is_numeric($m)) {\n return null;\n}\nreturn " + _Q,
    "early abort": "if (!in_array($m, ['a','b'], true)) {\n abort(404);\n}\nreturn " + _Q,
    "early throw": "if (!ctype_digit($m)) {\n throw new Exception('x');\n}\nreturn " + _Q,
    "early die": "if (!is_numeric($m)) {\n die('bad');\n}\nreturn " + _Q,
    "abort_unless": "abort_unless(is_numeric($m), 404);\nreturn " + _Q,
    "abort_if negated": "abort_if(!is_numeric($m), 404);\nreturn " + _Q,
    "equality with a literal": "if ($m === 'asc') {\n return " + _Q + "\n}",
    "equality chain": "if ($m === 'asc' || $m === 'desc') {\n return " + _Q + "\n}",
    "not-equal then leave": "if ($m !== 'asc') {\n return null;\n}\nreturn " + _Q,
    "and with an unrelated test": "if ($request->has('y') && is_numeric($m)) {\n return " + _Q + "\n}",
    "else of a negative check": "if (!is_numeric($m)) {\n return null;\n} else {\n return " + _Q + "\n}",
    "elseif chain": "if ($m === 'a') {\n return null;\n} elseif (is_numeric($m)) {\n return " + _Q + "\n}",
    "array_key_exists on a server array": "if (!array_key_exists($m, $this->columns)) {\n return null;\n}\nreturn " + _Q,
    "equality with a property read off an object": "foreach ($fields as $f) {\n if ($f->col == $m) {\n return " + _Q + "\n }\n}",
    "preg_match, letters digits dash": "if (preg_match('/^[a-z0-9_-]+$/i', $m)) {\n return " + _Q + "\n}",
    "preg_match, \\d": r"if (!preg_match('/^\d+$/', $m)) { die('x'); }" + "\nreturn " + _Q,
    "preg_match, \\A \\z": r"if (preg_match('/\A[a-z]+\z/', $m)) {" + "\n return " + _Q + "\n}",
}

NOT_GUARDED = {
    "no check": "return " + _Q,
    "check on another variable": "if (is_numeric($other)) {\n return " + _Q + "\n}",
    "query after the guarded block": "if (is_numeric($m)) {\n $ok = 1;\n}\nreturn " + _Q,
    "negative check that does not stop": "if (!is_numeric($m)) {\n $bad = 1;\n}\nreturn " + _Q,
    "or with an unrelated test": "if ($request->has('y') || is_numeric($m)) {\n return " + _Q + "\n}",
    "equality with another variable": "if ($m === $other) {\n return " + _Q + "\n}",
    "equality with request input": "if ($m === $request->input('z')) {\n return " + _Q + "\n}",
    "in_array over request data": "if (in_array($m, $request->input('list'), true)) {\n return " + _Q + "\n}",
    "loose in_array over integers": "if (in_array($m, [1, 2, 3])) {\n return " + _Q + "\n}",
    "equality is the wrong way round": "if ($m !== 'asc') {\n return " + _Q + "\n}",
    "abort_if on the positive check": "abort_if(is_numeric($m), 404);\nreturn " + _Q,
    "reassigned inside the guard": "if (is_numeric($m)) {\n $m = $request->input('y');\n return " + _Q + "\n}",
    "reassigned after the early exit": "if (!is_numeric($m)) {\n return null;\n}\n$m = $request->input('y');\nreturn " + _Q,
    "unanchored regex": "if (preg_match('/[a-z]+/', $m)) {\n return " + _Q + "\n}",
    "regex with the multiline flag": "if (preg_match('/^[a-z]+$/m', $m)) {\n return " + _Q + "\n}",
    "regex allowing a dot": "if (preg_match('/^[a-z.]+$/', $m)) {\n return " + _Q + "\n}",
    "regex allowing a space": "if (preg_match('/^[a-z ]+$/', $m)) {\n return " + _Q + "\n}",
    "regex range from 0 to z": "if (preg_match('/^[0-z]+$/', $m)) {\n return " + _Q + "\n}",
    "regex class with a negation": "if (preg_match('/^[^a-z]+$/', $m)) {\n return " + _Q + "\n}",
    "regex class hiding an escaped quote": "if (preg_match('/^[a-z" + "\\" + "']+$/', $m)) {\n return " + _Q + "\n}",
    "regex with alternation": "if (preg_match('/^(a|b)$/', $m)) {\n return " + _Q + "\n}",
}


@pytest.mark.parametrize("name", sorted(GUARDED))
def test_checked_value_is_not_flagged(name):
    assert not _flagged(GUARDED[name])


@pytest.mark.parametrize("name", sorted(NOT_GUARDED))
def test_unchecked_or_badly_checked_value_is_still_flagged(name):
    assert _flagged(NOT_GUARDED[name])


def test_guard_on_a_superglobal_element():
    php = ("<?php\nif (!is_numeric($_GET['id'])) {\n  die('x');\n}\n"
           "mysql_query('select * from t where id = ' . $_GET['id']);\n")
    assert not any(f.rule_id == "PHAST-SQL-001" for f in PhpASTAnalyzer().analyze("a.php", php))


def test_guard_on_one_superglobal_key_does_not_cover_another():
    php = ("<?php\nif (!is_numeric($_GET['id'])) {\n  die('x');\n}\n"
           "mysql_query('select * from t where n = ' . $_GET['name']);\n")
    assert any(f.rule_id == "PHAST-SQL-001" for f in PhpASTAnalyzer().analyze("a.php", php))


def test_a_guarded_value_copied_into_another_variable_stays_clean():
    body = "if (!is_numeric($m)) {\n return null;\n}\n$n = $m . 'x';\nreturn DB::select('select ' . $n);"
    assert not _flagged(body)


def test_guard_in_one_method_does_not_leak_into_another():
    php = ("<?php\nclass C {\n"
           "  public function a(Request $request) {\n    $m = $request->input('x');\n"
           "    if (!is_numeric($m)) { return null; }\n    return DB::select('select ' . $m);\n  }\n"
           "  public function b(Request $request) {\n    $m = $request->input('x');\n"
           "    return DB::select('select ' . $m);\n  }\n}\n")
    lines = sorted({f.line_number for f in PhpASTAnalyzer().analyze("app/Http/Controllers/X.php", php)
                    if f.rule_id == "PHAST-SQL-001"})
    assert lines == [10]
