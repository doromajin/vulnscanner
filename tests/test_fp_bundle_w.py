"""Precision fixes found on deliberately vulnerable apps: Sequelize ORM options are not NoSQL
injection, SQL fragments / PEM markers / label values are not hard-coded secrets, and a redirect
to a fixed local path prefix is not an open redirect."""
from vulnscanner.analyzers.ast_js import JSASTAnalyzer
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer


# ── 1. Sequelize vs MongoDB ──────────────────────────────────────────────────

def _nosql(src: str, path: str = "core/handler.js"):
    return [f for f in JSASTAnalyzer().analyze(path, src) if f.rule_id == "JSAST-NOSQL-001"]


def test_sequelize_where_option_object_is_not_nosql():
    src = ("exports.get = function (req, res) {\n"
           "  db.Product.find({ where: { id: req.query.id } }).then(p => res.json(p));\n}\n")
    assert _nosql(src) == []


def test_file_importing_sequelize_is_not_nosql():
    src = ("const { Op } = require('sequelize');\n"
           "exports.get = function (req, res) {\n"
           "  User.findOne(req.body.opts).then(u => res.json(u));\n}\n")
    assert _nosql(src) == []


def test_mongo_filter_from_request_stays_nosql():
    src = ("exports.get = function (req, res) {\n"
           "  users.findOne({ user: req.query.user }).then(u => res.json(u));\n}\n")
    assert len(_nosql(src)) == 1


def test_mongoose_find_with_request_body_value_stays_nosql():
    src = ("const mongoose = require('mongoose');\n"
           "exports.get = function (req, res) {\n"
           "  const q = req.body.filter;\n  User.find(q).then(u => res.json(u));\n}\n")
    assert len(_nosql(src)) == 1


# ── 2. hard-coded secrets ────────────────────────────────────────────────────

def _sec(src: str, path: str = "src/x.php"):
    return [f.rule_id for f in HardcodedSecretsAnalyzer().analyze(path, src)]


def test_sql_string_with_interpolated_password_is_not_a_secret():
    src = "<?php\n$q = \"SELECT * FROM `users` WHERE user='$user' AND password='$pass';\";\n"
    assert _sec(src) == []


def test_sql_update_with_interpolated_password_is_not_a_secret():
    src = "<?php\n$i = \"UPDATE `users` SET password = '$pass_new' WHERE user = '\" . $cur . \"';\";\n"
    assert _sec(src) == []


def test_literal_php_password_still_fires():
    assert "SEC-001" in _sec("<?php\n$password = 'hunter2abc';\n")
    assert "SEC-017" in _sec("<?php\n$db_pass = 'Xk29fjw0qzLm';\n")


def test_sql_with_literal_password_value_still_fires():
    src = "<?php\n$q = \"UPDATE users SET password = 'Zq8wLm3xYt' WHERE id = 1\";\n"
    assert "SEC-001" in _sec(src)


def test_label_colon_number_token_is_not_a_secret():
    assert _sec("<?php\n$token = \"userid:2\";\n") == []


def test_random_token_value_still_fires():
    assert _sec("<?php\n$token = \"Qm93d0xwMk5kS3pYOHZSdA\";\n") != []


def test_pem_marker_constant_is_not_a_key():
    src = ("class U {\n"
           "    public static final String BEGIN_PRIVATE_KEY_TOKEN = \"-----BEGIN PRIVATE KEY-----\";\n"
           "    public static final String END_PRIVATE_KEY_TOKEN = \"-----END PRIVATE KEY-----\";\n}\n")
    assert "SEC-005" not in _sec(src, "U.java")


def test_pem_with_body_still_fires():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
    one = 'const k = "-----BEGIN PRIVATE KEY-----\\n' + body + '\\n-----END PRIVATE KEY-----";\n'
    assert "SEC-005" in _sec(one, "key.js")
    split = 'const k = "-----BEGIN PRIVATE KEY-----\\n" +\n  "' + body + '\\n";\n'
    assert "SEC-005" in _sec(split, "key.js")


def test_aws_key_still_fires():
    assert "SEC-004" in _sec("k = 'AKIAABCDEFGHIJKLMNOP'\n", "a.py")


# ── 3. open redirect to a fixed local prefix ─────────────────────────────────

def _redir(src: str):
    return [(f.rule_id) for f in PythonASTAnalyzer().analyze("app/views.py", src)
            if f.rule_id.startswith("AST-REDIR")]


def test_redirect_with_fixed_local_prefix_is_not_open_redirect():
    src = ("def v(request, project_id):\n"
           "    project_id = request.POST.get('p')\n"
           "    return redirect('/app/' + project_id + '/')\n")
    assert _redir(src) == []


def test_redirect_with_local_prefix_fstring_is_not_open_redirect():
    src = ("def v(request):\n    p = request.GET['p']\n    return redirect(f'/app/{p}/')\n")
    assert _redir(src) == []


def test_redirect_with_reverse_prefix_is_not_open_redirect():
    src = ("def v(request):\n    p = request.GET['p']\n    return redirect(reverse('home') + p)\n")
    assert _redir(src) == []


def test_redirect_to_request_value_stays_open_redirect():
    src = "def v(request):\n    return redirect(request.GET['next'])\n"
    assert _redir(src) == ["AST-REDIR-001"]


def test_redirect_with_tainted_prefix_or_double_slash_stays_open_redirect():
    a = "def v(request):\n    p = request.GET['p']\n    return redirect(p + '/home')\n"
    b = "def v(request):\n    p = request.GET['p']\n    return redirect('//' + p)\n"
    assert _redir(a) != []
    assert _redir(b) != []


def _js_redir(src: str):
    return [f.rule_id for f in JSASTAnalyzer().analyze("routes/r.js", src) if f.rule_id == "JSAST-REDIR-001"]


def test_js_redirect_with_local_prefix_is_not_open_redirect():
    a = "exports.r = function (req, res) {\n  res.redirect('/items/' + req.query.id);\n}\n"
    b = "exports.r = function (req, res) {\n  res.redirect(`/items/${req.query.id}`);\n}\n"
    assert _js_redir(a) == [] and _js_redir(b) == []


def test_js_redirect_to_request_value_or_double_slash_stays():
    a = "exports.r = function (req, res) {\n  res.redirect(req.query.url);\n}\n"
    b = "exports.r = function (req, res) {\n  res.redirect('//' + req.query.id);\n}\n"
    c = "exports.r = function (req, res) {\n  res.redirect(req.query.id + '/x');\n}\n"
    assert _js_redir(a) and _js_redir(b) and _js_redir(c)
