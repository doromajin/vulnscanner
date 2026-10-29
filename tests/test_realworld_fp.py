"""Regression tests for false-positive classes found by triaging real OSS scans
(bludit, Lychee, kimai).  Each class has FP cases (must stay quiet) and TP cases
(must keep firing) so the fix cannot silently turn into a blanket suppression."""
from pathlib import Path

import pytest

from vulnscanner.analyzers.ast_php import PhpASTAnalyzer
from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
from vulnscanner.analyzers.custom_rule_analyzer import CustomRuleAnalyzer
from vulnscanner.analyzers.file_context import is_fixture_path
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer
from vulnscanner.models import Severity
from vulnscanner.rules.loader import load_rules

_BUILTIN = str(Path(__file__).resolve().parent.parent / "vulnscanner" / "rules" / "builtin")


def _ids(findings):
    return {f.rule_id for f in findings}


# ── 1. fixture directories with a prefix (Doctrine DataFixtures) ──────────────

class TestFixturePathSuffix:
    @pytest.mark.parametrize("path", [
        "src/DataFixtures/UserFixtures.php",
        "app/TestFixtures/seed.php",
        "src/Fixtures/a.php",
    ])
    def test_fixture_dirs(self, path):
        assert is_fixture_path(path)

    @pytest.mark.parametrize("path", [
        "src/Controller/FixController.php",
        "src/Service/Fixer.php",
        "app/Models/User.php",
    ])
    def test_non_fixture_dirs(self, path):
        assert not is_fixture_path(path)


# ── 2. SEC-001: constant whose value just names the field ─────────────────────

class TestPasswordLabelConstants:
    def _scan(self, code):
        return HardcodedSecretsAnalyzer().analyze("src/Thing.php", code)

    @pytest.mark.parametrize("code", [
        "    public const PASSWORD = 'password';\n",
        "    private const PASSWORD = 'password';\n",
        "    case PASSWORD = 'password';\n",
        "    public const SAME_AS_CURRENT_PASSWORD = 'kimai-password-01';\n",
    ])
    def test_label_constants_not_flagged(self, code):
        assert "SEC-001" not in _ids(self._scan(code))

    @pytest.mark.parametrize("code", [
        "$password = 'hunter2xyz';\n",
        "    const DB_PASSWORD = 'Sup3rS3cret!';\n",
        "$password = 'password123';\n",
        "    public const ADMIN_PASSWORD = 'Winter2024!';\n",
    ])
    def test_real_looking_passwords_still_flagged(self, code):
        assert "SEC-001" in _ids(self._scan(code))


# ── 3. CMD-004: "exec()" inside a message string is not a call ────────────────

class TestCmd004StringMentions:
    def _scan(self, code):
        return CommandInjectionAnalyzer().analyze("app/Thing.php", code)

    @pytest.mark.parametrize("code", [
        "$data[] = DiagnosticData::warn('opt set but exec() is not enabled.', self::class);\n",
        "$results['requirements'][$type]['Php exec() available'] = true;\n",
        'echo "eval() is disabled on this host";\n',
    ])
    def test_mentions_in_strings_not_flagged(self, code):
        assert "CMD-004" not in _ids(self._scan(code))

    @pytest.mark.parametrize("code", [
        "exec($command, $output);\n",
        "$r = exec($cmd);\n",
        "eval($code);\n",
        "$r = exec($prefix . $dir);\n",
        "$msg = 'run'; exec($cmd);\n",
    ])
    def test_real_calls_still_flagged(self, code):
        assert "CMD-004" in _ids(self._scan(code))


# ── 4. DOM sinks fed only by the app's own responses ──────────────────────────

class TestDomSinkReach:
    def _custom(self, path, code):
        return CustomRuleAnalyzer(load_rules([_BUILTIN])).analyze(path, code)

    def test_innerhtml_without_browser_source_is_low(self):
        code = "function show(html) {\n    el.innerHTML = html;\n}\n"
        f = [x for x in XSSAnalyzer().analyze("assets/a.js", code) if x.rule_id == "XSS-001"]
        assert f and all(x.severity == Severity.LOW for x in f)
        r = [x for x in self._custom("assets/a.js", code) if x.rule_id == "JS-XSS-001"]
        assert r and all(x.severity == Severity.LOW for x in r)

    def test_innerhtml_with_browser_source_stays_high(self):
        code = "const q = location.hash.slice(1);\nel.innerHTML = q;\n"
        f = [x for x in XSSAnalyzer().analyze("assets/a.js", code) if x.rule_id == "XSS-001"]
        assert f and all(x.severity == Severity.HIGH for x in f)
        r = [x for x in self._custom("assets/a.js", code) if x.rule_id == "JS-XSS-001"]
        assert r and all(x.severity == Severity.HIGH for x in r)

    def test_location_redirect_gated_the_same_way(self):
        quiet = self._custom("a.js", "window.location = res.headers.get('x-next');\n")
        assert [x.severity for x in quiet if x.rule_id == "JS-REDIR-001"] == [Severity.LOW]
        loud = self._custom("a.js", "const n = new URLSearchParams(location.search).get('n');\nwindow.location = n;\n")
        assert [x.severity for x in loud if x.rule_id == "JS-REDIR-001"] == [Severity.MEDIUM]


class TestPhpEscapedInnerHtml:
    def _scan(self, code):
        return [f for f in XSSAnalyzer().analyze("plugin.php", code) if f.rule_id == "XSS-001"]

    def test_sanitized_variable_not_flagged(self):
        code = (
            "$updating = Sanitize::html(addslashes($L->g('Updating')));\n"
            "$html .= '<form onsubmit=\"b.innerHTML=\\'<i></i> ' . $updating . '\\'; return true;\">';\n"
        )
        assert not self._scan(code)

    def test_unsanitized_variable_flagged(self):
        code = (
            "$updating = $_GET['msg'];\n"
            "$html .= '<form onsubmit=\"b.innerHTML=\\'<i></i> ' . $updating . '\\'; return true;\">';\n"
        )
        assert self._scan(code)


# ── 5. PHP echo: isset() is not output, sanitizer wrappers are recognised ─────

@pytest.mark.skipif(not hasattr(PhpASTAnalyzer, "analyze"), reason="php analyzer unavailable")
class TestPhpEchoSanitizers:
    def _scan(self, code):
        return [f for f in PhpASTAnalyzer().analyze("view.php", "<?php\n" + code) if f.rule_id == "PHAST-XSS-001"]

    def test_isset_and_static_sanitizer_not_flagged(self):
        code = (
            "echo '<input value=\"' . (isset($_POST['u']) ? Sanitize::html($_POST['u']) : '') . '\">';\n"
        )
        assert not self._scan(code)

    @pytest.mark.parametrize("wrapper", ["e", "h", "esc_html", "Html::encode", "Sanitize::html"])
    def test_framework_escapers(self, wrapper):
        assert not self._scan(f"echo {wrapper}($_GET['x']);\n")

    def test_raw_superglobal_still_flagged(self):
        assert self._scan("echo '<input value=\"' . $_POST['u'] . '\">';\n")

    def test_unsanitized_part_after_sanitized_part_flagged(self):
        assert self._scan("echo htmlspecialchars($a) . $_GET['b'];\n")

    def test_isset_alone_with_raw_value_flagged(self):
        assert self._scan("echo isset($_GET['a']) ? $_GET['a'] : '';\n")
