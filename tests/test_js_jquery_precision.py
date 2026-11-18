import pytest

from vulnscanner.analyzers import ast_js
from vulnscanner.analyzers.ast_js import JSASTAnalyzer

pytestmark = pytest.mark.skipif(
    not getattr(ast_js, "_TS_JS_AVAILABLE", True), reason="tree-sitter-javascript not installed"
)


def _rules(src: str) -> set[str]:
    return {f.rule_id for f in JSASTAnalyzer().analyze("app.js", src)}


_SRC = (
    "function go(req) {\n"
    "  var input = req.body;\n"
    "  %s\n"
    "}\n"
)


def test_jquery_shallow_extend_is_not_pollution():
    assert "JSAST-PROTO-001" not in _rules(_SRC % "var o = $.extend({}, defaults, input);")


def test_jquery_merge_is_array_concat():
    assert "JSAST-PROTO-001" not in _rules(_SRC % "$.merge(list, input);")


def test_jquery_deep_extend_still_reported():
    assert "JSAST-PROTO-001" in _rules(_SRC % "var o = $.extend(true, {}, defaults, input);")


def test_lodash_merge_still_reported():
    assert "JSAST-PROTO-001" in _rules(_SRC % "_.merge(target, input);")


def test_jquery_selection_find_is_not_nosql():
    assert "JSAST-NOSQL-001" not in _rules(_SRC % "this.$body.find(input.sel);")


def test_collection_find_still_reported():
    assert "JSAST-NOSQL-001" in _rules(_SRC % "db.users.find(input);")
