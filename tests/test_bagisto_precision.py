import pytest

from vulnscanner.analyzers import ast_php
from vulnscanner.analyzers.ast_php import PhpASTAnalyzer
from vulnscanner.analyzers.deserialization import DeserializationAnalyzer

_php = pytest.mark.skipif(not ast_php._TS_AVAILABLE, reason="tree-sitter-php not installed")


def _php_ids(body: str):
    src = "<?php\nclass C { function a(Request $request) {\n" + body + "\n} }\n"
    return {f.rule_id for f in PhpASTAnalyzer().analyze("app/Http/C.php", src)}


@_php
def test_application_execute_method_is_not_a_sql_sink():
    assert "PHAST-SQL-001" not in _php_ids("return $this->cacheManager->execute($request->input('action'));")


@_php
def test_database_execute_with_request_data_is_still_flagged():
    assert "PHAST-SQL-001" in _php_ids("return $this->db->execute($request->input('q'));")
    assert "PHAST-SQL-001" in _php_ids("return $pdo->query($request->input('q'));")


def _deser(src: str, path: str = "app/Helpers/S.php"):
    return {(f.rule_id, f.severity.name) for f in DeserializationAnalyzer().analyze(path, src)}


def test_unserialize_without_request_input_in_file_is_medium_review():
    src = "<?php\nfunction p($payload) { return unserialize(base64_decode($payload)); }\n"
    assert _deser(src) == {("DESER-004", "MEDIUM")}


def test_unserialize_of_request_data_stays_critical():
    src = "<?php\n$d = unserialize($_COOKIE['c']);\n"
    assert ("DESER-004", "CRITICAL") in _deser(src)
    src2 = "<?php\nfunction a(Request $request) { return unserialize($request->input('x')); }\n"
    assert ("DESER-004", "CRITICAL") in _deser(src2)
