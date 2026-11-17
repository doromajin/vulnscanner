from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
from vulnscanner.analyzers.command_injection import _CMD004_RE


def _rules(src: str):
    return [(f.rule_id, f.severity.name) for f in PythonASTAnalyzer().analyze("app.py", src)
            if f.rule_id == "AST-CMD-005"]


def test_unknown_module_name_is_low_needs_review():
    src = "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n"
    hits = [f for f in PythonASTAnalyzer().analyze("app.py", src) if f.rule_id == "AST-CMD-005"]
    assert hits and all(f.severity.name in ("LOW", "MEDIUM") for f in hits)
    assert all("dynamic module name" in f.description for f in hits)


def test_settings_attribute_not_flagged():
    src = "import importlib\nimport settings\n\ndef load():\n    return importlib.import_module(settings.BACKEND)\n"
    assert _rules(src) == []


def test_request_supplied_module_name_is_critical():
    src = (
        "import importlib\nfrom flask import request\n\n"
        "def load():\n    name = request.args.get('m')\n    return importlib.import_module(name)\n"
    )
    assert ("AST-CMD-005", "CRITICAL") in _rules(src)


def test_literal_module_name_not_flagged():
    src = "import importlib\n\ndef load():\n    return importlib.import_module('json')\n"
    assert _rules(src) == []


def test_empty_call_is_prose_not_code():
    assert not _CMD004_RE.search("this needs eval() enabled")
    assert not _CMD004_RE.search("exec() is disabled")
    assert _CMD004_RE.search("run(eval(x))")
