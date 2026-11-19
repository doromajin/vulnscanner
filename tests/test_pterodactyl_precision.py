import re

import pytest
import yaml

from vulnscanner.analyzers import ast_js, ast_php
from vulnscanner.analyzers.ast_js import JSASTAnalyzer
from vulnscanner.analyzers.ast_php import PhpASTAnalyzer

_js = pytest.mark.skipif(not getattr(ast_js, "_TS_JS_AVAILABLE", True), reason="tree-sitter-javascript not installed")
_php = pytest.mark.skipif(not ast_php._TS_AVAILABLE, reason="tree-sitter-php not installed")


def _js_ids(src: str):
    return {f.rule_id for f in JSASTAnalyzer().analyze("src/app.js", src)}


def _php_ids(src: str):
    return {f.rule_id for f in PhpASTAnalyzer().analyze("app/Http/C.php", src)}


@_js
def test_regexp_exec_is_not_command_injection():
    src = "function f(){var q=decodeURIComponent(window.location.href);return new RegExp('a'+q).exec(q)}"
    assert "JSAST-CMD-001" not in _js_ids(src)
    assert "JSAST-CMD-001" not in _js_ids("var m = /x=(.*)/.exec(decodeURIComponent(window.location.href));")


@_js
def test_child_process_exec_with_user_input_still_flagged():
    src = ("const cp = require('child_process');\n"
           "app.get('/p', (req, res) => { cp.exec('ping ' + req.query.host); });\n")
    assert "JSAST-CMD-001" in _js_ids(src)


@_php
def test_translation_loader_load_is_not_xxe():
    src = ("<?php\nclass C { function __invoke(Request $request) {\n"
           "  $locale = $request->input('locale');\n  return $this->loader->load($locale, 'ns');\n} }\n")
    assert "PHAST-XXE-001" not in _php_ids(src)


@_php
def test_dom_load_with_user_input_still_flagged():
    src = ("<?php\nclass C { function a(Request $request) {\n"
           "  $dom = new DOMDocument();\n  $dom->load($request->input('f'));\n} }\n")
    assert "PHAST-XXE-001" in _php_ids(src)


def _redir_regex():
    import pathlib
    p = pathlib.Path(ast_js.__file__).parents[1] / "rules" / "builtin" / "javascript.yaml"
    rules = yaml.safe_load(p.read_text(encoding="utf-8"))
    rules = rules if isinstance(rules, list) else rules.get("rules", rules)
    return re.compile(next(r for r in rules if r["id"] == "JS-REDIR-001")["regex"])


def test_location_assignment_of_a_fixed_string_is_not_flagged():
    rx = _redir_regex()
    assert not rx.search("window.location = '/';")
    assert not rx.search('window.location = "/login";')
    assert rx.search("window.location = next;")
    assert rx.search("window.location = '/a/' + next;")
