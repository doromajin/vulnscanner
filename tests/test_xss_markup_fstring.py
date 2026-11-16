"""AST-XSS-001: Markup()/mark_safe() of an f-string built from escaped parts."""
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer

AST = PythonASTAnalyzer()


def _xss(code):
    return [f for f in AST.analyze("views.py", code)
            if f.rule_id == "AST-XSS-001" and not f.suppression_reason]


def _fn(body):
    return "def render(value, request):\n" + "".join(f"    {line}\n" for line in body.splitlines())


# ── false positives: escaped value in text content, or a fixed URL scheme ─────

def test_escaped_name_in_element_text_is_not_flagged():
    assert not _xss(_fn("escaped = markupsafe.escape(value)\nreturn markupsafe.Markup(f'<pre>{escaped}</pre>')"))


def test_escaped_name_after_a_fixed_scheme_is_not_flagged():
    assert not _xss(_fn(
        "escaped = markupsafe.escape(value.strip())\n"
        "return markupsafe.Markup(f'<a href=\"mailto:{escaped}\">{escaped}</a>')"))


def test_inline_escape_in_text_and_numbers_are_not_flagged():
    assert not _xss(_fn("return Markup(f'<b>{escape(value)}</b> ({len(value)})')"))


def test_escaped_value_in_a_data_attribute_is_not_a_url_context():
    assert not _xss(_fn("e = escape(value)\nreturn Markup(f'<div data-href=\"{e}\" id=\"{e}\">x</div>')"))


# ── true positives and unknowns stay flagged ──────────────────────────────────

def test_escaped_value_as_a_whole_href_is_still_flagged():
    # HTML escaping does not stop `javascript:` URLs
    assert _xss(_fn("e = markupsafe.escape(value.strip())\nreturn markupsafe.Markup(f'<a href=\"{e}\">{e}</a>')"))


def test_inline_escape_as_a_whole_src_is_still_flagged():
    assert _xss(_fn("return Markup(f\"<img src='{escape(value)}'>\")"))


def test_url_quoted_value_in_href_is_not_flagged():
    assert not _xss(_fn("return Markup(f'<a href=\"{quote(value)}\">link</a>')"))


def test_request_value_is_a_confirmed_finding():
    findings = _xss(_fn("return Markup(f\"<b>{request.args.get('x')}</b>\")"))
    assert findings and findings[0].severity.value == "HIGH"


def test_unescaped_unknown_value_stays_needs_review():
    findings = _xss(_fn("return Markup(f'<b>{value}</b>')"))
    assert findings and findings[0].severity.value == "MEDIUM"


def test_name_reassigned_after_escaping_is_still_flagged():
    assert _xss(_fn("e = escape(value)\ne = request.args.get('x')\nreturn Markup(f'<b>{e}</b>')"))


def test_str_format_of_an_unescaped_value_is_still_flagged():
    assert _xss(_fn("return Markup('<strong>{}</strong>'.format(value))"))
