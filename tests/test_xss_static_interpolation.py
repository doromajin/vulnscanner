"""XSS-001 / JS-XSS-001: `${NAME}` in an innerHTML template is safe for a static string constant."""
from pathlib import Path

from vulnscanner.analyzers.custom_rule_analyzer import CustomRuleAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer
from vulnscanner.rules.loader import load_rules

XSS = XSSAnalyzer()
_BUILTIN = str(Path(__file__).resolve().parent.parent / "vulnscanner" / "rules" / "builtin")
RULES = CustomRuleAnalyzer(load_rules([_BUILTIN]))


def _flagged(js):
    return [f for f in XSS.analyze("static/widget.js", js) if f.rule_id == "XSS-001"]


def _js_rule(js):
    return [f for f in RULES.analyze("static/widget.js", js) if f.rule_id == "JS-XSS-001"]


# ── false positives ───────────────────────────────────────────────────────────

def test_static_constant_interpolated_into_a_template_is_not_flagged():
    js = (
        'var TITLE_ID = "dialog-title";\n'
        "dialog.innerHTML = `<span id=\"${TITLE_ID}\">Column actions</span>`;\n"
    )
    assert not _flagged(js)


def test_const_and_let_string_constants_are_recognised():
    js = (
        "const PREFIX = 'nav';\n"
        "el.innerHTML = `<div class=\"${PREFIX}-box\"></div>`;\n"
    )
    assert not _flagged(js)


def test_several_static_constants_in_one_template_are_not_flagged():
    js = (
        "const A = 'one';\nconst B = \"two\";\n"
        "el.innerHTML = `<i class=\"${A}\"></i><b class=\"${B}\"></b>`;\n"
    )
    assert not _flagged(js)


def test_js_rule_allows_only_static_constants_in_a_template():
    js = (
        'var TITLE_ID = "dialog-title";\n'
        "dialog.innerHTML = `<span id=\"${TITLE_ID}\">Column actions</span>`;\n"
    )
    assert not _js_rule(js)


# ── true positives must stay ──────────────────────────────────────────────────

def test_unknown_variable_is_still_flagged():
    assert _flagged("el.innerHTML = `<span>${userName}</span>`;\n")
    assert _js_rule("el.innerHTML = `<span>${userName}</span>`;\n")


def test_js_rule_still_flags_function_call_interpolations():
    assert _js_rule("el.innerHTML = `<span>${render(x)}</span>`;\n")


def test_constant_assigned_from_user_controlled_source_is_still_flagged():
    js = (
        "const TITLE = location.hash;\n"
        "el.innerHTML = `<span>${TITLE}</span>`;\n"
    )
    assert _flagged(js)
    assert _js_rule(js)


def test_constant_reassigned_later_is_still_flagged():
    js = (
        "var LABEL = 'safe';\n"
        "LABEL = location.search;\n"
        "el.innerHTML = `<span>${LABEL}</span>`;\n"
    )
    assert _flagged(js)
    assert _js_rule(js)


def test_static_constant_next_to_a_user_value_is_still_flagged():
    js = (
        "const CLS = 'box';\n"
        "el.innerHTML = `<div class=\"${CLS}\">${comment.body}</div>`;\n"
    )
    assert _flagged(js)
    assert _js_rule(js)


def test_property_access_is_not_treated_as_a_constant():
    js = (
        "const CFG = 'x';\n"
        "el.innerHTML = `<div>${CFG.label}</div>`;\n"
    )
    assert _flagged(js)
    assert _js_rule(js)
