"""Hard-coded secrets stored as dict/map subscripts, JS object properties, PHP variables and define()."""
import pytest

from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer


def _ids(path, code):
    return [(f.rule_id, f.line_number) for f in HardcodedSecretsAnalyzer().analyze(path, code)]


def _hit(path, code):
    return any(r == "SEC-017" for r, _ in _ids(path, code))


# ---- TP ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("path,code", [
    ("app.py", "app.config['SECRET_KEY_HMAC'] = 'secret'\n"),
    ("app.py", 'app.config["SECRET_KEY"] = "Zq8d7f3a91bc"\n'),
    ("app.py", "app.config['SECRET_KEY'] = 'secret'\n"),
    ("settings.rb", "Rails.application.config['session_secret'] = 'hunter2hunter2'\n"),
    ("env/all.js", 'module.exports = {\n    cookieSecret: "session_cookie_secret_key_here_x9",\n    cryptoKey: "a_secure_key_for_crypto_here",\n};\n'),
    ("server.js", "app.use(session({ secret: 'keyboardcat42' }));\n"),
    ("server.ts", "const h = crypto.createHmac('sha256', 'my-hmac-literal');\n"),
    ("db.php", "$db_pass = 'supersecret123';\n"),
    ("db.php", "define('DB_PASSWORD', 'rootroot1');\n"),
    ("db.php", "$config['password'] = 'letmein99';\n"),
])
def test_literal_secret_is_reported(path, code):
    assert _hit(path, code)


# ---- FP ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("path,code", [
    ("app.py", "app.config['SECRET_KEY'] = os.environ['SECRET_KEY']\n"),
    ("app.py", "app.config['SECRET_KEY'] = ''\n"),
    ("app.py", "app.config['SECRET_KEY'] = '{{ secret }}'\n"),
    ("app.py", "app.config['SECRET_KEY'] = '<set me>'\n"),
    ("app.py", "app.config['SECRET_FIELD_LABEL'] = 'Enter the secret value here'\n"),
    ("app.py", "messages['password_hint'] = 'Use at least eight characters'\n"),
    ("app.py", "app.config['PASSWORD_MIN_LENGTH'] = '8'\n"),
    ("form.js", "const labels = { password: 'Password', token: 'token' };\n"),
    ("form.js", "const t = { password: 'Mot de passe oublie' };\n"),
    ("form.js", "const cfg = { secret: process.env.SECRET };\n"),
    ("form.js", "const cfg = { secret: `${base}` };\n"),
    ("db.php", "$db_pass = getenv('DB_PASS');\n"),
    ("db.php", "$password_label = 'Password';\n"),
    ("db.php", "define('DB_PASSWORD', getenv('DB_PASSWORD'));\n"),
    ("db.php", "define('PASSWORD_FIELD', 'password');\n"),
    ("db.php", "$config['password'] = config('db.password');\n"),
    ("enum.py", "AUTH['token'] = 'token'\n"),
])
def test_non_secret_is_not_reported(path, code):
    assert not _hit(path, code)


# ---- FN guard: not double-reported, other rules untouched -------------------------------------
def test_no_double_report_on_same_line():
    ids = _ids("db.php", "$password = 'supersecret123';\n")
    assert [r for r, _ in ids] == ["SEC-001"]


def test_existing_jwt_rule_still_fires_once():
    ids = _ids("a.js", "jwt.sign(payload, 'literal-secret-1');\n")
    assert [r for r, _ in ids] == ["SEC-008"]


def test_google_api_key_shape_in_php_variable():
    assert _ids("db.php", "$api_key = 'AIzaQ8x7Lr2mNpV4tYb1cKd9WsHj3GfEo5U0';\n")


@pytest.mark.parametrize("code", [
    'fetch(url, { credentials: "include" });\n',
    'const o = { token: "disable-auth" };\n',
])
def test_fetch_option_and_sentinel_word_are_not_secrets(code):
    assert not _hit("web.ts", code)


def test_cypress_config_credentials_are_test_data():
    from vulnscanner.analyzers.file_context import is_test_path
    assert is_test_path("cypress.config.ts")
    assert is_test_path("web/playwright.config.js")
    assert not is_test_path("src/config.ts")
    assert not is_test_path("webpack.config.js")
