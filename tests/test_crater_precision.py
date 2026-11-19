import pytest

from vulnscanner.analyzers import ast_php
from vulnscanner.analyzers.ast_php import PhpASTAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.sql_injection import SQLInjectionAnalyzer

_php = pytest.mark.skipif(not ast_php._TS_AVAILABLE, reason="tree-sitter-php not installed")


def _php_ids(src: str):
    return {f.rule_id for f in PhpASTAnalyzer().analyze("app/Models/P.php", src)}


def _wrap(body: str) -> str:
    return "<?php\nclass P { function a(Request $request) {\n" + body + "\n} }\n"


@_php
def test_http_get_with_fixed_host_is_not_ssrf():
    body = ("$url = \"https://api.example.com/latest?apikey=\" . $request->input('key');\n"
            "return Http::get($url)->json();")
    assert "PHAST-SSRF-001" not in _php_ids(_wrap(body))


@_php
def test_http_get_with_request_url_is_still_ssrf():
    assert "PHAST-SSRF-001" in _php_ids(_wrap("$url = $request->input('u');\nreturn Http::get($url)->json();"))
    assert "PHAST-SSRF-001" in _php_ids(_wrap("return Http::get($request->input('u'))->json();"))


@_php
def test_url_reassigned_from_request_is_still_ssrf():
    body = ("$url = 'https://api.example.com/x?k=' . $request->input('k');\n"
            "if ($request->input('o')) { $url = $request->input('o'); }\n"
            "return Http::get($url)->json();")
    assert "PHAST-SSRF-001" in _php_ids(_wrap(body))


@_php
def test_switch_arms_are_judged_separately():
    body = ("switch ($request['driver']) {\n"
            "  case 'a':\n    $url = 'https://api.example.com/x?k=' . $request['key'];\n    $r = Http::get($url);\n    break;\n"
            "  case 'b':\n    $url = $request['base'];\n    $r = Http::get($url);\n    break;\n}")
    ids = [f.line_number for f in PhpASTAnalyzer().analyze("app/Models/P.php", _wrap(body))
           if f.rule_id == "PHAST-SSRF-001"]
    assert len(ids) == 1


def _sec(src: str, path: str = "app/Env.php"):
    return {f.rule_id for f in HardcodedSecretsAnalyzer().analyze(path, src)}


def test_env_line_built_by_concatenation_is_not_a_hardcoded_password():
    src = "$s = 'MAIL_PASSWORD='.$request->mail_password.\"\\n\";\n$t = 'DB_PASSWORD='.config('database.pw').\"\\n\";\n"
    assert "SEC-001" not in _sec(src)


def test_real_hardcoded_password_is_still_reported():
    assert "SEC-001" in _sec("$password = 'hunter2hunter2';\n")


def test_guid_raw_in_js_is_not_django_raw_sql():
    ids = {f.rule_id for f in SQLInjectionAnalyzer().analyze("resources/scripts/s.js", "const id = Guid.raw()\n")}
    assert "SQL-005" not in ids


def test_raw_call_outside_js_is_still_checked():
    ids = {f.rule_id for f in SQLInjectionAnalyzer().analyze("app/R.java", "var x = repo.raw(q);\n")}
    assert "SQL-005" in ids
