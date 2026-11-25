from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.ssti import SSTIAnalyzer


def _ssti(src, path="static/app.js"):
    return [f for f in SSTIAnalyzer().analyze(path, src) if f.rule_id == "SSTI-007"]


def _sec(src, path="src/config.ts"):
    return [f for f in HardcodedSecretsAnalyzer().analyze(path, src) if f.rule_id == "SEC-001"]


# ---- SSTI-007 ----------------------------------------------------------

def test_handlebars_compile_of_dom_template_is_not_flagged():
    assert not _ssti('var t = Handlebars.compile($("#row-tpl").html());\n')
    assert not _ssti("var t = Handlebars.compile($('#row-tpl').text());\n")
    assert not _ssti('var t = Handlebars.compile(document.getElementById("row-tpl").innerHTML);\n')
    assert not _ssti("var t = Handlebars.compile(document.querySelector('#tpl').textContent);\n")


def test_handlebars_compile_of_variable_from_dom_read_is_not_flagged():
    src = 'var source = $("#row-tpl").html();\nvar t = Handlebars.compile(source);\n'
    assert not _ssti(src)


def test_handlebars_compile_of_request_data_is_flagged():
    assert _ssti("const t = Handlebars.compile(req.body.t);\n")
    assert _ssti("const t = Handlebars.compile(location.hash.slice(1));\n")


def test_handlebars_compile_with_dynamic_selector_is_flagged():
    assert _ssti("var t = Handlebars.compile($(location.hash).html());\n")
    assert _ssti("var t = Handlebars.compile($(req.query.sel).html());\n")


def test_handlebars_compile_of_variable_from_network_is_flagged():
    src = "var source = req.body.t;\nvar t = Handlebars.compile(source);\n"
    assert _ssti(src)


# ---- SEC-001 -----------------------------------------------------------

def test_identifier_constants_naming_the_field_are_not_flagged():
    assert not _sec('const FieldNamePassword = "password"\n', "internal/model.go")
    assert not _sec('\tMFAMethodPassword MFAMethod = "password"\n', "internal/mfa.go")
    assert not _sec("  Password = 'password',\n")
    assert not _sec("static final String PASSWORD_KEY = \"Password\";\n", "A.java")


def test_real_looking_password_is_still_flagged():
    assert _sec('password = "xK9fQ2mZpL7vR4tYw8Nc3Bd"\n', "app/settings.py")
    assert _sec("const password = 'q8Zr5LmT2vXw9KpY4hJd7GsB';\n")


def test_weak_but_unrelated_password_literal_is_still_flagged():
    assert _sec('db_password = "hunter2hunter2"\n', "app/settings.py")


def test_other_secret_rules_unaffected():
    ids = {f.rule_id for f in HardcodedSecretsAnalyzer().analyze(
        "app/aws.py", 'key = "AKIAIOSFODNN7ABCDEFG"\n')}
    assert "SEC-004" in ids
