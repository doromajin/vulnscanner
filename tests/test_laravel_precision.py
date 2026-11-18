from vulnscanner.analyzers.client_side import ClientSideAnalyzer
from vulnscanner.analyzers.deserialization import DeserializationAnalyzer
from vulnscanner.analyzers.file_context import is_fixture_path
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.weak_crypto import WeakCryptoAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer


def _ids(analyzer, path, src):
    return {(f.rule_id, f.severity.name) for f in analyzer.analyze(path, src)}


def test_blade_expression_is_not_a_hardcoded_password():
    src = "<script>\nvar needSecurePassword = '{{ trans('validation.secure_password') }}';\n</script>\n"
    assert not any(r == "SEC-001" for r, _ in _ids(HardcodedSecretsAnalyzer(), "register.blade.php", src))


def test_literal_password_still_reported():
    src = "<?php\n$password = 'Sup3rS3cretValue';\n"
    assert any(r == "SEC-001" for r, _ in _ids(HardcodedSecretsAnalyzer(), "config.php", src))


def test_laravel_factories_are_fixtures():
    assert is_fixture_path("database/factories/User.php")
    assert not is_fixture_path("app/Models/Factories.php")


def test_hibp_sha1_is_not_password_hashing():
    src = ("<?php\n$hash = sha1($password);\n"
           "$url = sprintf('https://api.pwnedpasswords.com/range/%s', substr($hash, 0, 5));\n")
    assert not any(r == "WCRYPTO-004" for r, _ in _ids(WeakCryptoAnalyzer(), "Verifier.php", src))


def test_sha1_password_hash_still_reported():
    src = "<?php\n$hash = sha1($password);\n"
    assert any(r == "WCRYPTO-004" for r, _ in _ids(WeakCryptoAnalyzer(), "Auth.php", src))


def test_unserialize_in_migration_is_low():
    src = "<?php\n$p = unserialize($row->preferences);\n"
    ids = _ids(DeserializationAnalyzer(), "database/migrations/2022_convert.php", src)
    assert ("DESER-004", "LOW") in ids
    assert not any(r == "DESER-004" and s == "CRITICAL"
                   for r, s in ids)


def test_unserialize_outside_migration_keeps_severity():
    src = "<?php\n$p = unserialize($row->preferences);\n"
    assert any(r == "DESER-004" and s != "LOW" for r, s in _ids(DeserializationAnalyzer(), "app/Foo.php", src))


def test_service_worker_message_listener_not_flagged():
    src = "navigator.serviceWorker?.addEventListener('message', event => { run(event.data) })\n"
    assert not any(r == "CLIENT-MSG-001" for r, _ in _ids(ClientSideAnalyzer(), "app.js", src))


def test_window_message_listener_still_flagged():
    src = "window.addEventListener('message', event => { run(event.data) })\n"
    assert any(r == "CLIENT-MSG-001" for r, _ in _ids(ClientSideAnalyzer(), "app.js", src))


def test_innerhtml_copy_of_dom_markup_not_flagged():
    src = "new_element.innerHTML = old_element.innerHTML;\n"
    assert not any(r == "XSS-001" for r, _ in _ids(XSSAnalyzer(), "app.js", src))



def test_innerhtml_copy_not_flagged_by_broad_js_rule():
    from pathlib import Path

    from vulnscanner.analyzers.custom_rule_analyzer import CustomRuleAnalyzer
    from vulnscanner.rules.loader import load_rules

    builtin = str(Path(__file__).resolve().parent.parent / "vulnscanner" / "rules" / "builtin")
    rules = CustomRuleAnalyzer(load_rules([builtin]))
    copy = "new_element.innerHTML = old_element.innerHTML;\n"
    risky = "el.innerHTML = userHtml;\n"
    assert not [f for f in rules.analyze("app.js", copy) if f.rule_id == "JS-XSS-001"]
    assert [f for f in rules.analyze("app.js", risky) if f.rule_id == "JS-XSS-001"]
