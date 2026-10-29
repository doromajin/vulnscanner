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


# ── 6. SSTI-003: Twig render with the sandbox actually enabled ────────────────

class TestTwigSandbox:
    def _scan(self, code):
        from vulnscanner.analyzers.ssti import SSTIAnalyzer
        return [f for f in SSTIAnalyzer().analyze("src/Renderer.php", code) if f.rule_id == "SSTI-003"]

    def test_enable_sandbox_suppresses(self):
        code = (
            "$sandbox = $twig->getExtension(SandboxExtension::class);\n"
            "$sandbox->enableSandbox();\n"
            "$content = $twig->render($template, $options);\n"
        )
        assert not self._scan(code)

    def test_global_sandbox_flag_suppresses(self):
        code = (
            "$twig->addExtension(new SandboxExtension($policy, true));\n"
            "$content = $twig->render($template, $options);\n"
        )
        assert not self._scan(code)

    def test_extension_registered_but_not_enabled_still_flagged(self):
        code = (
            "$twig->addExtension(new SandboxExtension($policy));\n"
            "$content = $twig->render($template, $options);\n"
        )
        assert self._scan(code)

    def test_no_sandbox_still_flagged(self):
        assert self._scan("$content = $twig->render($template, $options);\n")


# ── 7. CMD-004 reach: exec() in a PHP file with no request-derived input ──────

class TestCmd004Reach:
    def _sev(self, code):
        f = [x for x in CommandInjectionAnalyzer().analyze("app/Thing.php", code) if x.rule_id == "CMD-004"]
        assert f
        return {x.severity for x in f}

    def test_no_request_input_is_medium(self):
        code = "function size($dir) {\n    $c = \"ls -lLR {$dir}\";\n    exec($c, $out);\n}\n"
        assert self._sev(code) == {Severity.MEDIUM}

    @pytest.mark.parametrize("src", [
        "$c = $_GET['c'];",
        "$c = $request->input('c');",
        "$c = $this->request->get('c');",
        "$c = Request::get('c');",
        "$c = $_SERVER['argv'][1];",
    ])
    def test_request_input_stays_critical(self, src):
        assert self._sev(f"{src}\nexec($c, $out);\n") == {Severity.CRITICAL}


# ── 8. REDIR-002 reach + shared request-input evidence ────────────────────────

class TestRedirectReach:
    def _sev(self, code):
        from vulnscanner.analyzers.open_redirect import OpenRedirectAnalyzer
        f = [x for x in OpenRedirectAnalyzer().analyze("lib/Redirect.php", code) if x.rule_id == "REDIR-002"]
        assert f
        return {x.severity for x in f}

    def test_helper_without_request_input_is_low(self):
        code = "function go($url) {\n    header(\"Location: \" . $url, true, 302);\n}\n"
        assert self._sev(code) == {Severity.LOW}

    def test_server_derived_script_name_is_not_request_input(self):
        code = "$base = dirname($_SERVER['SCRIPT_NAME']);\nheader('Location:' . $base . '/install.php');\n"
        assert self._sev(code) == {Severity.LOW}

    @pytest.mark.parametrize("src", [
        "$t = $request->get('next');",
        "$t = $_SERVER['HTTP_REFERER'];",
        "$t = $_SERVER['REQUEST_URI'];",
        "$t = $_COOKIE['back'];",
    ])
    def test_request_input_keeps_medium(self, src):
        assert self._sev(f"{src}\nheader('Location: ' . $t);\n") == {Severity.MEDIUM}


# ── 9. second OSS batch (flask, gogs, BookStack, node-red, petclinic) ──────────

class TestExampleAndTestPaths:
    @pytest.mark.parametrize("path", ["examples/celery/views.py", "src/example/a.php", "docs/examples/x.js"])
    def test_example_dirs_are_fixture_like(self, path):
        assert is_fixture_path(path)

    @pytest.mark.parametrize("path", ["src/exemplar/a.py", "src/examplesuite/a.py", "app/Counterexamples.php"])
    def test_lookalike_dirs_are_not(self, path):
        assert not is_fixture_path(path)

    @pytest.mark.parametrize("path", [
        "internal/dbx/dsn_test.go", "tests/helper_test.rb", "src/UserTests.cs", "src/UserTest.cs".replace("UserTest", "OrderTests"),
    ])
    def test_more_test_file_names(self, path):
        from vulnscanner.analyzers.file_context import is_test_path
        assert is_test_path(path)

    @pytest.mark.parametrize("path", ["internal/dbx/dsn.go", "src/Contest.cs", "src/Latests.cs", "src/protest.go"])
    def test_non_test_file_names(self, path):
        from vulnscanner.analyzers.file_context import is_test_path
        assert not is_test_path(path)


class TestGoPathSources:
    def _ids(self, code):
        from vulnscanner.analyzers.go_analyzer import GoAnalyzer
        return {f.rule_id for f in GoAnalyzer().analyze("h.go", code)}

    @pytest.mark.parametrize("code", [
        'RemoveAll(filepath.Join(conf.Server.AppDataPath, "tmp"))\n',
        "p := filepath.Join(conf.Picture.Dir, strconv.FormatInt(r.ID, 10))\n",
        "b, _ := os.ReadFile(filepath.Join(cfg.Root, user.Name))\n",
    ])
    def test_config_and_receiver_fields_not_flagged(self, code):
        assert "GO-PATH-001" not in self._ids(code)

    @pytest.mark.parametrize("code", [
        "b, _ := os.ReadFile(filepath.Join(dir, r.URL.Path))\n",
        'f, _ := os.Open(r.FormValue("file"))\n',
        'p := filepath.Join(base, c.Param("name"))\n',
        "b, _ := ioutil.ReadFile(req.Header.Get(\"X-File\"))\n",
    ])
    def test_request_derived_paths_still_flagged(self, code):
        assert "GO-PATH-001" in self._ids(code)


class TestSstiDefinition:
    def _ids(self, code):
        from vulnscanner.analyzers.ssti import SSTIAnalyzer
        return {f.rule_id for f in SSTIAnalyzer().analyze("t.py", code)}

    def test_definition_not_flagged(self):
        assert "SSTI-001" not in self._ids("def render_template_string(source, **context):\n    pass\n")
        assert "SSTI-001" not in self._ids("async def render_template_string(source):\n    pass\n")

    def test_dynamic_call_still_flagged(self):
        assert "SSTI-001" in self._ids("return render_template_string(tpl)\n")


class TestPythonDocstringSecrets:
    def _ids(self, code):
        return {f.rule_id for f in HardcodedSecretsAnalyzer().analyze("cfg.py", code)}

    def test_secret_in_docstring_not_flagged(self):
        code = 'def f():\n    """Example::\n\n        SECRET_KEY = \'development key\'\n    """\n    return 1\n'
        assert "SEC-003" not in self._ids(code)

    def test_real_assignment_still_flagged(self):
        assert "SEC-003" in self._ids("SECRET_KEY = 'prod-7f3a9c1d2b'\n")

    def test_secret_after_docstring_still_flagged(self):
        code = 'def f():\n    """doc"""\n    SECRET_KEY = \'prod-7f3a9c1d2b\'\n'
        assert "SEC-003" in self._ids(code)


class TestStorageIsNotDomEvidence:
    def test_storage_only_file_is_low(self):
        code = "const h = JSON.parse(window.localStorage.getItem('k') || '{}');\nel.innerHTML = tpl;\n"
        f = [x for x in XSSAnalyzer().analyze("a.js", code) if x.rule_id == "XSS-001"]
        assert f and all(x.severity == Severity.LOW for x in f)

    def test_postmessage_data_is_evidence(self):
        code = "window.addEventListener('message', e => { el.innerHTML = e.data; });\n"
        f = [x for x in XSSAnalyzer().analyze("a.js", code) if x.rule_id == "XSS-001"]
        assert f and all(x.severity == Severity.HIGH for x in f)


class TestPostMessageNamedHandler:
    def _ids(self, code):
        from vulnscanner.analyzers.client_side import ClientSideAnalyzer
        return {f.rule_id for f in ClientSideAnalyzer().analyze("a.ts", code)}

    def test_named_handler_with_origin_check_ok(self):
        code = (
            "function onMsg(event) {\n    if (event.origin !== trusted) return;\n    use(event.data);\n}\n"
            "window.addEventListener('message', onMsg);\n"
        )
        assert "CLIENT-MSG-001" not in self._ids(code)

    def test_named_handler_without_check_flagged(self):
        code = "function onMsg(event) {\n    use(event.data);\n}\nwindow.addEventListener('message', onMsg);\n"
        assert "CLIENT-MSG-001" in self._ids(code)

    def test_inline_handler_without_check_flagged(self):
        assert "CLIENT-MSG-001" in self._ids("window.addEventListener('message', e => use(e.data));\n")


class TestRedosOptionalGroup:
    def _issue(self, src):
        from vulnscanner.analyzers.ast_js import _is_redos_pattern
        return _is_redos_pattern(src)

    @pytest.mark.parametrize("src", [r"^(\d+(?:\.\d+)?)px$", r"^\d+\.\d+\.\d+(-.*)?"])
    def test_optional_group_not_flagged(self, src):
        assert self._issue(src) is None

    @pytest.mark.parametrize("src", [r"(a+)+$", r"([a-z]+\s*)*x", r"(\w+){2,}"])
    def test_unbounded_nested_quantifier_still_flagged(self, src):
        assert self._issue(src)


class TestGoExecArguments:
    def _scan(self, call):
        from vulnscanner.analyzers.ast_go import GoASTAnalyzer
        code = (
            "package main\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\n"
            "func h(w http.ResponseWriter, r *http.Request) {\n"
            "\tv := r.FormValue(\"v\")\n\t" + call + "\n}\n"
        )
        return [f for f in GoASTAnalyzer().analyze("h.go", code) if f.rule_id == "GOAST-CMD-001"]

    def test_fixed_program_tainted_args_is_high(self):
        f = self._scan('cmd := exec.Command("git", v, "--stateless-rpc")\n\t_ = cmd')
        assert f and {x.severity for x in f} == {Severity.HIGH}

    def test_tainted_program_is_critical(self):
        f = self._scan("cmd := exec.Command(v)\n\t_ = cmd")
        assert f and {x.severity for x in f} == {Severity.CRITICAL}

    @pytest.mark.parametrize("prog", ["sh", "bash", "/bin/sh", "cmd.exe", "python3"])
    def test_shell_like_program_stays_critical(self, prog):
        f = self._scan(f'cmd := exec.Command("{prog}", "-c", v)\n\t_ = cmd')
        assert f and {x.severity for x in f} == {Severity.CRITICAL}


class TestPasswordPathLabels:
    def _ids(self, code, path="internal/email/email.go"):
        return {f.rule_id for f in HardcodedSecretsAnalyzer().analyze(path, code)}

    @pytest.mark.parametrize("code", [
        '\ttmplAuthResetPassword  = "auth/reset_passwd"\n',
        '\ttmplUserSettingsPassword = "user/settings/password"\n',
        'const RESET_PASSWORD_VIEW = "auth/reset-password";\n',
    ])
    def test_template_path_constants_not_flagged(self, code):
        assert "SEC-001" not in self._ids(code)

    @pytest.mark.parametrize("code", [
        '\tdbPassword = "Sup3rS3cret!"\n',
        '\tadminPassword = "hunter2xyz"\n',
        '\tpassword = "Winter/2024"\n',
    ])
    def test_real_passwords_still_flagged(self, code):
        assert "SEC-001" in self._ids(code)
