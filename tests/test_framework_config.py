from vulnscanner.analyzers.framework_config import FrameworkConfigAnalyzer


def _scan(path: str, src: str):
    return [(f.rule_id, f.severity.name) for f in FrameworkConfigAnalyzer().analyze(path, src)]


_DJ = "from pathlib import Path\nINSTALLED_APPS = []\n"


def test_django_debug_true_in_settings_is_medium():
    assert ("CFG-DJ-001", "MEDIUM") in _scan("proj/settings.py", _DJ + "DEBUG = True\n")


def test_django_debug_from_the_environment_is_fine():
    src = _DJ + "DEBUG = os.environ.get('DEBUG') == '1'\nDEBUG_PROPAGATE_EXCEPTIONS = False\n"
    assert _scan("proj/settings.py", src) == []


def test_django_debug_true_in_a_dev_settings_file_is_low():
    assert ("CFG-DJ-001", "LOW") in _scan("proj/settings/local.py", _DJ + "DEBUG = True\n")
    assert ("CFG-DJ-001", "LOW") in _scan("proj/settings_dev.py", _DJ + "DEBUG = True\n")


def test_django_debug_true_outside_settings_files_is_ignored():
    assert _scan("app/views.py", "INSTALLED_APPS = []\nDEBUG = True\n") == []


def test_django_wildcard_allowed_hosts():
    assert ("CFG-DJ-002", "MEDIUM") in _scan("proj/settings.py", _DJ + "ALLOWED_HOSTS = ['*']\n")
    assert _scan("proj/settings.py", _DJ + "ALLOWED_HOSTS = ['example.com']\n") == []


def test_django_cookie_flags():
    ids = {r for r, _ in _scan("proj/settings.py", _DJ + "SESSION_COOKIE_SECURE = False\nSESSION_COOKIE_HTTPONLY = False\n")}
    assert {"CFG-DJ-003", "CFG-DJ-004"} <= ids


def test_django_indented_assignment_is_not_a_module_setting():
    assert _scan("proj/settings.py", _DJ + "if X:\n    DEBUG = True\n") == []


_APP = "<?php\nreturn [\n%s\n];\n"


def test_laravel_debug_defaulting_to_true():
    assert ("CFG-LV-001", "MEDIUM") in _scan("config/app.php", _APP % "    'debug' => env('APP_DEBUG', true),")
    assert ("CFG-LV-001", "MEDIUM") in _scan("config/app.php", _APP % "    'debug' => true,")


def test_laravel_debug_defaulting_to_false_is_fine():
    assert _scan("config/app.php", _APP % "    'debug' => (bool) env('APP_DEBUG', false),") == []


def test_laravel_app_key_with_a_hardcoded_fallback_is_high():
    assert ("CFG-LV-002", "HIGH") in _scan("config/app.php", _APP % "    'key' => env('APP_KEY', '0123456789abcdef0123456789abcdef'),")
    assert _scan("config/app.php", _APP % "    'key' => env('APP_KEY'),") == []


def test_laravel_session_cookie_flags():
    ids = {r for r, _ in _scan("config/session.php", _APP % "    'http_only' => false,\n    'secure' => false,")}
    assert {"CFG-LV-003", "CFG-LV-004"} <= ids
    assert _scan("config/session.php", _APP % "    'http_only' => true,\n    'secure' => env('SESSION_SECURE_COOKIE'),") == []


def test_laravel_cors_wildcard_needs_credentials():
    both = _APP % "    'allowed_origins' => ['*'],\n    'supports_credentials' => true,"
    only_wild = _APP % "    'allowed_origins' => ['*'],\n    'supports_credentials' => false,"
    assert ("CFG-LV-005", "HIGH") in _scan("config/cors.php", both)
    assert _scan("config/cors.php", only_wild) == []


def test_php_outside_a_config_directory_is_ignored():
    assert _scan("app/Support/app.php", _APP % "    'debug' => true,") == []


def test_laravel_placeholder_fallback_key_is_only_medium():
    assert ("CFG-LV-002", "MEDIUM") in _scan("config/app.php", _APP % "    'key' => env('APP_KEY', 'JustAKeyForInstallation'),")


def test_laravel_usable_fallback_key_is_high_for_raw_and_base64_forms():
    raw = "0123456789abcdef0123456789abcdef"
    b64 = "base64:" + "A" * 43 + "="
    assert ("CFG-LV-002", "HIGH") in _scan("config/app.php", _APP % ("    'key' => env('APP_KEY', '%s')," % raw))
    assert ("CFG-LV-002", "HIGH") in _scan("config/app.php", _APP % ("    'key' => env('APP_KEY', '%s')," % b64))
