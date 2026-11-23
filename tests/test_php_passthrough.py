"""String functions that reshape a value without making it safe keep the client's data in the result.

`$m = trim($_GET['x']); DB::select('... ' . $m)` went unreported before: only assignments from sources
and from functions known to return tainted data carried taint.  The list in `ast_php._PASSTHROUGH_FUNCS`
is deliberately an allow-list: sanitizers (intval, htmlspecialchars, urlencode ...) are not in it.
"""
import pytest

from vulnscanner.analyzers.ast_php import PhpASTAnalyzer

_PATH = "app/Http/Controllers/X.php"


def _ids(php: str) -> set[str]:
    return {f.rule_id for f in PhpASTAnalyzer().analyze(_PATH, php)}


def _sql(expr: str) -> bool:
    php = ("<?php\nclass C {\n    public function b(Request $request) {\n"
           f"        $m = {expr};\n"
           "        return DB::select('select * from t where a = ' . $m);\n    }\n}\n")
    return "PHAST-SQL-001" in _ids(php)


@pytest.mark.parametrize("expr", [
    "trim($_GET['x'])",
    "rtrim($request->input('x'))",
    "strtolower($request->input('x'))",
    "ucfirst($_POST['x'])",
    "substr($request->input('x'), 0, 5)",
    "str_replace(\"'\", '', $request->input('x'))",
    "str_ireplace('a', 'b', $_GET['x'])",
    "strtr($_GET['x'], 'ab', 'cd')",
    "preg_replace('/\\s+/', ' ', $_GET['x'])",
    "sprintf('id=%s', $request->input('x'))",
    "sprintf('%s-%d', $_GET['x'], 1)",
    "implode(',', $_GET['ids'])",
    "urldecode($_GET['x'])",
    "base64_decode($_GET['x'])",
    "stripslashes($_POST['x'])",
    "html_entity_decode($_GET['x'])",
    "trim(strtolower($_POST['x']))",
    "json_decode($_POST['d'], true)['k']",
    "explode(',', $_GET['x'])[0]",
    "(string) trim($_GET['x'])",
])
def test_value_passed_through_a_string_function_is_still_tainted(expr):
    assert _sql(expr)


@pytest.mark.parametrize("expr", [
    "intval(trim($_GET['x']))",
    "(int) trim($_GET['x'])",
    "trim(addslashes($_GET['x']))",
    "trim(htmlspecialchars($_GET['x']))",
    "strtolower(urlencode($_GET['x']))",
    "implode(',', array_map('intval', $_GET['ids']))",
    "sprintf('%d', $_GET['x'])",
    "sprintf('%05.2f|%d', $_GET['x'], $_GET['y'])",
    "trim('abc')",
    "str_replace('a', 'b', 'literal')",
    "trim($config)",
    "sprintf('limit %d', count($_GET))",
])
def test_sanitized_numeric_or_constant_values_are_not_flagged(expr):
    assert not _sql(expr)


def test_namespaced_call_is_recognised():
    php = ("<?php\nclass C {\n    public function b(Request $request) {\n"
           "        $m = " + chr(92) + "trim($_GET['x']);\n"
           "        return DB::select('select ' . $m);\n    }\n}\n")
    assert "PHAST-SQL-001" in _ids(php)


def test_xss_through_a_string_function():
    php = "<?php\n$n = strtoupper($_GET['name']);\necho 'Hello ' . $n;\n"
    assert "PHAST-XSS-001" in _ids(php)


def test_escaped_output_stays_clean():
    php = "<?php\n$n = strtoupper(htmlspecialchars($_GET['name']));\necho 'Hello ' . $n;\n"
    assert "PHAST-XSS-001" not in _ids(php)


# ── the server's own upload fields and the client's extension ─────────────────────────────

def test_uploaded_tmp_name_is_the_servers_path_not_the_clients():
    php = ("<?php\n$name = 'avatar.png';\n"
           "$ok = rename($_FILES['f']['tmp_name'], '/srv/tmp/' . $name);\n")
    assert "PHAST-PATH-001" not in _ids(php)


def test_client_file_name_in_a_path_is_still_flagged():
    php = "<?php\nfile_put_contents('/srv/up/' . $_FILES['f']['name'], 'x');\n"
    assert "PHAST-PATH-001" in _ids(php)


def test_client_extension_is_an_upload_problem_not_a_traversal():
    php = ("<?php\nclass E {\n    public function s(Request $request) {\n"
           "        $path = public_path() . '/img';\n"
           "        $filename = 'e-' . md5(time()) . '.' . strtolower($request->file('f')->getClientOriginalExtension());\n"
           "        $request->file('f')->move($path, $filename);\n"
           "        \\Storage::put('img/' . $filename, 'x');\n    }\n}\n")
    found = _ids(php)
    assert "PHAST-UPLOAD-001" in found
    assert "PHAST-PATH-001" not in found
