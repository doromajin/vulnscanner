"""Laravel request objects as taint sources and the matching Eloquent / facade sinks."""
import pytest

from vulnscanner.analyzers import ast_php
from vulnscanner.analyzers.ast_php import (
    PhpASTAnalyzer,
    PhpCrossFileContext,
    collect_php_file,
    merge_php_cross_file_parts,
    set_php_cross_file_context,
)

pytestmark = pytest.mark.skipif(not ast_php._TS_AVAILABLE, reason="tree-sitter-php not installed")

_HEAD = "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nclass C {\n"


def _scan(body: str, path: str = "app/Http/Controllers/C.php"):
    src = _HEAD + body + "\n}\n"
    return {(f.rule_id, f.severity.name) for f in PhpASTAnalyzer().analyze(path, src)}


def _rules(body: str) -> set[str]:
    return {r for r, _ in _scan(body)}


@pytest.fixture(autouse=True)
def _no_context():
    set_php_cross_file_context(None)
    yield
    set_php_cross_file_context(None)


# ── sources and sinks ─────────────────────────────────────────────────────────

def test_where_raw_with_request_input_is_sql_injection():
    body = "function f(Request $request) { return Post::whereRaw(\"a = '\" . $request->input('t') . \"'\")->get(); }"
    assert "PHAST-SQL-001" in _rules(body)


def test_db_select_with_concatenated_request_value():
    body = "function f(Request $request) { return DB::select(\"select * from t where id = \" . $request->get('id')); }"
    assert "PHAST-SQL-001" in _rules(body)


def test_bound_placeholders_are_not_flagged():
    body = "function f(Request $request) { return DB::select('select * from t where id = ?', [$request->input('id')]); }"
    assert "PHAST-SQL-001" not in _rules(body)


def test_cast_request_value_is_clean():
    body = "function f(Request $request) { $id = (int) $request->input('id'); return DB::select('select * from t where id = ' . $id); }"
    assert "PHAST-SQL-001" not in _rules(body)


def test_request_user_is_not_client_data():
    body = "function f(Request $request) { return DB::select('select * from t where id = ' . $request->user()->id); }"
    assert "PHAST-SQL-001" not in _rules(body)


def test_request_helper_function_is_a_source():
    body = "function f() { return DB::select('select * from t where id = ' . request('id')); }"
    assert "PHAST-SQL-001" in _rules(body)


def test_open_redirect_from_request():
    assert "PHAST-REDIR-001" in _rules("function f(Request $request) { return redirect($request->input('next')); }")


def test_redirect_with_route_prefix_is_internal():
    body = "function f(Request $request) { return redirect(route('index') . $request->input('from')); }"
    assert "PHAST-REDIR-001" not in _rules(body)


def test_redirect_after_same_host_check_is_fine():
    body = (
        "function f(Request $request) {\n"
        "  $to = $request->input('next');\n"
        "  if (parse_url($to, PHP_URL_HOST) !== 'example.test') { return redirect('/'); }\n"
        "  return redirect($to);\n"
        "}"
    )
    assert "PHAST-REDIR-001" not in _rules(body)


def test_download_path_from_request():
    body = "function f(Request $request) { return response()->download(storage_path($request->input('file'))); }"
    assert "PHAST-PATH-001" in _rules(body)


def test_http_facade_url_from_request():
    body = "function f(Request $request) { return Http::get($request->input('url'))->body(); }"
    assert "PHAST-SSRF-001" in _rules(body)


def test_uploaded_file_server_path_is_safe_but_client_name_is_not():
    safe = "function f(Request $request) { $file = $request->file('f'); unlink($file->getRealPath()); }"
    unsafe = "function f(Request $request) { $file = $request->file('f'); unlink($file->getClientOriginalName()); }"
    assert "PHAST-PATH-001" not in _rules(safe)
    assert "PHAST-PATH-001" in _rules(unsafe)


def test_pdo_style_fetch_is_not_template_injection():
    body = "function f(Request $request) { return $siblingFetcher->fetch($request->input('type'), 1); }"
    assert "PHAST-SSTI-001" not in _rules(body)


# ── mass assignment needs an unguarded model ──────────────────────────────────

_MASS = (
    "function f(Request $request, Post $post) {\n"
    "  $post->update($request->all());\n"
    "  return Post::create($request->all());\n"
    "}"
)


def test_mass_assignment_not_reported_without_unguarded_models():
    assert "PHAST-MASS-001" not in _rules(_MASS)


def test_mass_assignment_reported_for_unguarded_model():
    set_php_cross_file_context(PhpCrossFileContext(unguarded_models=frozenset({"Post"})))
    found = _scan(_MASS)
    assert ("PHAST-MASS-001", "MEDIUM") in found     # Post::create on a `$guarded = []` model
    assert ("PHAST-MASS-001", "LOW") in found        # $post->update: type not resolved


def test_whitelisted_input_is_not_mass_assignment():
    set_php_cross_file_context(PhpCrossFileContext(unguarded_models=frozenset({"Post"})))
    body = "function f(Request $request) { return Post::create($request->only(['title'])); }"
    assert "PHAST-MASS-001" not in _rules(body)


def test_unguarded_model_collection_ignores_vendor_and_tests():
    model = "<?php\nclass Post extends Model { protected $guarded = []; }\n"
    parts = [
        collect_php_file("app/Models/Post.php", model),
        collect_php_file("vendor/acme/Thing.php", model.replace("Post", "Thing")),
        collect_php_file("tests/Fixtures/Other.php", model.replace("Post", "Other")),
    ]
    assert merge_php_cross_file_parts(parts).unguarded_models == frozenset({"Post"})


def test_redirect_to_literal_host_is_fixed_destination():
    body = (
        "function f(Request $request) { return redirect()->away("
        "\"https://www.example.test/oauth?client_id=\" . $request->route('key')); }"
    )
    assert "PHAST-REDIR-001" not in _rules(body)


def test_host_taken_from_request_is_still_open_redirect():
    body = "function f(Request $request) { return redirect()->away(\"https://\" . $request->input('h') . \"/x\"); }"
    assert "PHAST-REDIR-001" in _rules(body)


def test_integer_cast_of_superglobal_is_clean():
    src = "<?php\n$id = (int) $_GET['id'];\nmysqli_query($c, 'select ' . $id);\n"
    assert not PhpASTAnalyzer().analyze("a.php", src)


def test_passing_the_request_object_to_own_method_is_not_template_injection():
    body = "function f(Request $request) { return $this->createTemplate($request, $repo); }"
    assert "PHAST-SSTI-001" not in _rules(body)


def test_twig_create_template_with_request_data_still_reported():
    body = "function f(Request $request) { return $twig->createTemplate($request->input('tpl')); }"
    assert "PHAST-SSTI-001" in _rules(body)
