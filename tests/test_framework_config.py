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


def test_framework_misconfiguration_has_its_own_fix_advice():
    from vulnscanner.models import VulnType
    from vulnscanner.reporters.fix_suggestions import get_cwe, get_fix
    assert get_cwe(VulnType.FRAMEWORK_MISCONFIGURATION) == 16
    advice = get_fix(VulnType.FRAMEWORK_MISCONFIGURATION)
    assert "environment" in advice["text"] and "APP_KEY" in advice["markdown"] and "DEBUG" in advice["markdown"]


def test_django_empty_password_validators_and_samesite_off():
    ids = {r for r, _ in _scan("proj/settings.py", _DJ + "AUTH_PASSWORD_VALIDATORS = []\nSESSION_COOKIE_SAMESITE = None\n")}
    assert {"CFG-DJ-005", "CFG-DJ-006"} <= ids
    assert _scan("proj/settings.py", _DJ + "AUTH_PASSWORD_VALIDATORS = [{'NAME': 'x'}]\nSESSION_COOKIE_SAMESITE = 'Lax'\n") == []


def test_old_django_cors_allow_all_name_is_flagged():
    from vulnscanner.analyzers.cors_analyzer import CORSAnalyzer
    assert any(f.rule_id == "CORS-002" for f in CORSAnalyzer().analyze("proj/settings.py", "CORS_ORIGIN_ALLOW_ALL = True\n"))


def test_laravel_session_same_site_off():
    assert ("CFG-LV-009", "LOW") in _scan("config/session.php", _APP % "    'same_site' => null,")
    assert _scan("config/session.php", _APP % "    'same_site' => 'lax',") == []


def test_committed_env_with_a_real_app_key_is_high_and_the_key_is_not_echoed():
    findings = FrameworkConfigAnalyzer().analyze(".env", "APP_NAME=x\nAPP_KEY=base64:SECRETSECRETSECRET=\n")
    assert [(f.rule_id, f.severity.name) for f in findings] == [("CFG-LV-007", "HIGH")]
    assert "SECRET" not in findings[0].line_content


def test_env_example_and_empty_keys_are_not_flagged():
    assert _scan(".env.example", "APP_KEY=base64:SECRETSECRETSECRET=\nAPP_DEBUG=true\n") == []
    assert _scan(".env", "APP_KEY=\nAPP_DEBUG=false\n") == []


def test_committed_env_debug_is_medium_and_high_for_production():
    assert ("CFG-LV-008", "MEDIUM") in _scan(".env", "APP_ENV=local\nAPP_DEBUG=true\n")
    assert ("CFG-LV-008", "HIGH") in _scan(".env.production", "APP_ENV=production\nAPP_DEBUG=true\n")


_GATE_OPEN = ("<?php\nprotected function gate()\n{\n    Gate::define('viewTelescope', function ($user) {\n"
              "        return true;\n    });\n}\n")
_GATE_RESTRICTED = ("<?php\nprotected function gate()\n{\n    Gate::define('viewTelescope', function ($user) {\n"
                    "        return in_array($user->email, ['admin@example.com']);\n    });\n}\n")


def test_open_telescope_gate_is_high_and_a_restricted_one_is_not():
    assert ("CFG-LV-006", "HIGH") in _scan("app/Providers/TelescopeServiceProvider.php", _GATE_OPEN)
    assert _scan("app/Providers/TelescopeServiceProvider.php", _GATE_RESTRICTED) == []
