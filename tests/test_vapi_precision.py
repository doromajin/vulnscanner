from vulnscanner.analyzers.ast_php import PhpASTAnalyzer
from vulnscanner.analyzers.cors_analyzer import CORSAnalyzer


def _php(src: str):
    return {(f.rule_id) for f in PhpASTAnalyzer().analyze("app/Http/Controllers/SurferController.php", src)}


def _cors(src: str):
    return [f.rule_id for f in CORSAnalyzer().analyze("app/Http/Controllers/X.php", src)]


_FETCH = "<?php\nclass C { function show(Request $request) {\n  $url = $request->input('url');\n  $data = file_get_contents($url);\n} }\n"


def test_file_get_contents_of_a_request_url_is_ssrf_as_well_as_path():
    ids = _php(_FETCH)
    assert {"PHAST-SSRF-001", "PHAST-PATH-001"} <= ids


def test_file_get_contents_of_a_request_path_is_not_ssrf():
    src = "<?php\nclass C { function show(Request $request) {\n  $name = $request->input('name');\n  $d = file_get_contents($name);\n} }\n"
    ids = _php(src)
    assert "PHAST-PATH-001" in ids and "PHAST-SSRF-001" not in ids


def test_fixed_host_url_is_not_ssrf():
    src = ("<?php\nclass C { function show(Request $request) {\n  $id = $request->input('id');\n"
           "  $url = 'https://api.example.com/items/' . $id;\n  $d = file_get_contents($url);\n} }\n")
    assert "PHAST-SSRF-001" not in _php(src)


def test_laravel_reflected_origin_is_flagged():
    src = "<?php\nreturn response($u)->header('Access-Control-Allow-Origin', $request->header('Origin'));\n"
    assert "CORS-009" in _cors(src)


def test_native_php_reflected_origin_is_flagged():
    assert "CORS-009" in _cors("<?php\nheader('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);\n")


def test_fixed_origin_is_not_flagged():
    assert _cors("<?php\nreturn response($u)->header('Access-Control-Allow-Origin', 'https://app.example.com');\n") == []


def test_laravel_wildcard_origin_is_flagged():
    assert "CORS-010" in _cors("<?php\nreturn response($u)->header('Access-Control-Allow-Origin', '*');\n")
