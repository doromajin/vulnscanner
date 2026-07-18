import json
import tempfile
from pathlib import Path

import pytest

from vulnscanner.analyzers.ast_java import JavaASTAnalyzer, _HAS_JAVALANG

_skip_no_javalang = pytest.mark.skipif(not _HAS_JAVALANG, reason="javalang not installed")
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
from vulnscanner.analyzers.java_analyzer import JavaAnalyzer
from vulnscanner.analyzers.dependencies import (
    DependencyAnalyzer,
    _parse_gemfile_lock,
    _parse_go_mod,
    _parse_package_json,
    _parse_requirements,
)
from vulnscanner.analyzers.deserialization import DeserializationAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.open_redirect import OpenRedirectAnalyzer
from vulnscanner.analyzers.prototype_pollution import PrototypePollutionAnalyzer
from vulnscanner.analyzers.client_side import ClientSideAnalyzer
from vulnscanner.analyzers.sql_injection import SQLInjectionAnalyzer
from vulnscanner.analyzers.ssrf import SSRFAnalyzer
from vulnscanner.analyzers.ssti import SSTIAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer
from vulnscanner.models import Finding, Severity, ScanResult, VulnType
from vulnscanner.reporters.sarif import write_sarif
from vulnscanner.scanner import _is_excluded, _is_suppressed, _parse_ignore_file

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestSQLInjection:
    def test_detects_concat(self):
        content = _load("vulnerable_sql.py")
        findings = SQLInjectionAnalyzer().analyze("test.py", content)
        rule_ids = {f.rule_id for f in findings}
        assert "SQL-001" in rule_ids

    def test_detects_percent_format(self):
        content = _load("vulnerable_sql.py")
        findings = SQLInjectionAnalyzer().analyze("test.py", content)
        rule_ids = {f.rule_id for f in findings}
        assert "SQL-002" in rule_ids

    def test_no_false_positive_parameterized(self):
        safe = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'
        findings = SQLInjectionAnalyzer().analyze("test.py", safe)
        assert findings == []


class TestCommandInjection:
    def test_detects_os_system(self):
        content = _load("vulnerable_cmd.py")
        findings = CommandInjectionAnalyzer().analyze("test.py", content)
        rule_ids = {f.rule_id for f in findings}
        assert "CMD-001" in rule_ids

    def test_detects_shell_true(self):
        content = _load("vulnerable_cmd.py")
        findings = CommandInjectionAnalyzer().analyze("test.py", content)
        rule_ids = {f.rule_id for f in findings}
        assert "CMD-002" in rule_ids

    def test_detects_eval(self):
        content = _load("vulnerable_cmd.py")
        findings = CommandInjectionAnalyzer().analyze("test.py", content)
        rule_ids = {f.rule_id for f in findings}
        assert "CMD-004" in rule_ids

    def test_safe_subprocess_list(self):
        safe = 'subprocess.run(["ping", host])'
        findings = CommandInjectionAnalyzer().analyze("test.py", safe)
        assert findings == []

    def test_php_method_exec_not_flagged(self):
        # PHP object/static method calls named exec() are not OS exec
        php_cases = [
            '$this->command_executor->exec($command, $output);',
            '$this->optimize->exec();',
            'CommandExecutor::exec($cmd);',
            'public function exec(string $command): void {',
        ]
        for code in php_cases:
            findings = CommandInjectionAnalyzer().analyze("test.php", code)
            rule_ids = {f.rule_id for f in findings}
            assert "CMD-004" not in rule_ids, f"CMD-004 FP on: {code}"


class TestXSS:
    # ── true positives ────────────────────────────────────────────────────────

    def test_detects_bare_variable(self):
        code = 'element.innerHTML = userInput;'
        findings = XSSAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "XSS-001" for f in findings)

    def test_detects_bare_property_in_template(self):
        code = 'el.innerHTML = `<p>${c.id}</p>`;'
        findings = XSSAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "XSS-001" for f in findings)

    def test_detects_bare_variable_in_template(self):
        code = 'el.innerHTML = `Hello ${name}`;'
        findings = XSSAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "XSS-001" for f in findings)

    def test_detects_multiline_template_with_unsafe_interpolation(self):
        code = (
            'item.innerHTML = `\n'
            '  <div>${escHtml(title)}</div>\n'
            '  <button onclick="go(\'${id}\')">x</button>\n'
            '`;'
        )
        findings = XSSAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "XSS-001" for f in findings)

    def test_detects_string_concatenation(self):
        code = "el.innerHTML = '<p>' + userInput;"
        findings = XSSAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "XSS-001" for f in findings)

    def test_detects_document_write(self):
        code = 'document.write(location.search)'
        findings = XSSAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "XSS-002" for f in findings)

    # ── false-positive guards ─────────────────────────────────────────────────

    def test_no_fp_empty_string(self):
        assert XSSAnalyzer().analyze("app.js", "el.innerHTML = '';") == []

    def test_no_fp_string_literal(self):
        assert XSSAnalyzer().analyze("app.js", 'el.innerHTML = "<div>static</div>";') == []

    def test_no_fp_template_no_interpolation(self):
        assert XSSAnalyzer().analyze("app.js", "el.innerHTML = `<svg><path/></svg>`;") == []

    def test_no_fp_known_safe_function(self):
        assert XSSAnalyzer().analyze("app.js", "el.innerHTML = `${escHtml(title)}`;") == []

    def test_no_fp_any_function_call(self):
        # Unknown function calls are treated as safer than bare variable references
        assert XSSAnalyzer().analyze("app.js", "el.innerHTML = `${formatDate(ts)}`;") == []

    def test_no_fp_multiline_all_safe_functions(self):
        code = (
            'item.innerHTML = `\n'
            '  <div class="title">${escHtml(c.title)}</div>\n'
            '  <div class="date">${formatDate(c.updatedAt)}</div>\n'
            '`;'
        )
        assert XSSAnalyzer().analyze("app.js", code) == []

    def test_no_fp_ternary_no_interpolation(self):
        code = "name.innerHTML = model === 'ultra' ? '⚡ Ultra' : `<svg></svg>`;"
        assert XSSAnalyzer().analyze("app.js", code) == []

    def test_no_fp_direct_function_call(self):
        # innerHTML = func(x) — function application treated as safer than bare var ref
        assert XSSAnalyzer().analyze("app.js", "el.innerHTML = DOMPurify.sanitize(userInput);") == []

    def test_no_fp_direct_any_function(self):
        # Unknown function: developer is at least transforming the value (consistent
        # with the template-literal branch policy)
        assert XSSAnalyzer().analyze("app.js", "el.innerHTML = escapeHtml(content);") == []

    # ── PHP XSS-008 precision ─────────────────────────────────────────────────

    def test_no_fp_php_2hop_sanitization(self):
        # Tainted var ($raw) is sanitized into $esc; echo outputs $esc, not $raw.
        code = (
            '$raw = $_GET["name"];\n'
            '$esc = htmlspecialchars($raw, ENT_QUOTES, "UTF-8");\n'
            'echo $esc;\n'
        )
        rule_ids = {f.rule_id for f in XSSAnalyzer().analyze("page.php", code)}
        assert "XSS-008" not in rule_ids

    def test_no_fp_php_inline_htmlspecialchars(self):
        # echo wraps the tainted var in htmlspecialchars inline — sanitized at echo point.
        code = '$name = $_GET["name"];\necho htmlspecialchars($name, ENT_QUOTES, "UTF-8");\n'
        rule_ids = {f.rule_id for f in XSSAnalyzer().analyze("page.php", code)}
        assert "XSS-008" not in rule_ids

    def test_no_fp_php_inline_intval(self):
        # intval() at echo point: numeric output cannot introduce HTML.
        code = '$id = $_GET["id"];\necho intval($id);\n'
        rule_ids = {f.rule_id for f in XSSAnalyzer().analyze("page.php", code)}
        assert "XSS-008" not in rule_ids

    def test_no_fp_php_wp_sanitize_text_field(self):
        # WordPress sanitize_text_field strips tags/whitespace — now in _PHP_XSS_CLEAN_RE.
        code = (
            '$title = sanitize_text_field($_POST["title"]);\n'
            'echo "<h1>" . $title . "</h1>";\n'
        )
        rule_ids = {f.rule_id for f in XSSAnalyzer().analyze("template.php", code)}
        assert "XSS-008" not in rule_ids

    def test_no_fp_php_esc_url(self):
        # esc_url (WordPress) is now in _PHP_XSS_CLEAN_RE.
        code = (
            '$link = esc_url($_GET["redirect"]);\n'
            'echo \'<a href="\' . $link . \'">Go</a>\';\n'
        )
        rule_ids = {f.rule_id for f in XSSAnalyzer().analyze("template.php", code)}
        assert "XSS-008" not in rule_ids

    def test_still_fires_php_bare_echo_tainted(self):
        # Regression: unescaped echo of tainted variable must still fire XSS-008.
        code = '$name = $_GET["name"];\necho "<h1>Hello " . $name . "</h1>";\n'
        rule_ids = {f.rule_id for f in XSSAnalyzer().analyze("page.php", code)}
        assert "XSS-008" in rule_ids


class TestHardcodedSecrets:
    def test_detects_password(self):
        code = 'password = "supersecret123"'
        findings = HardcodedSecretsAnalyzer().analyze("config.py", code)
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_skips_placeholder(self):
        code = 'password = "your-password-here"'
        findings = HardcodedSecretsAnalyzer().analyze("config.py", code)
        assert findings == []

    def test_detects_aws_key(self):
        # 20-char pattern: AKIA + 16 uppercase alphanumerics, no allowlist keywords
        code = 'key = "AKIAIOSFODNN7ABCD123"'
        findings = HardcodedSecretsAnalyzer().analyze("deploy.py", code)
        assert any(f.rule_id == "SEC-004" for f in findings)

    def test_prod_password_is_high(self):
        code = 'password = "supersecret123"'
        findings = HardcodedSecretsAnalyzer().analyze("src/main/Config.java", code)
        assert findings[0].severity == Severity.HIGH

    def test_analyzer_reports_test_file_finding_at_full_severity(self):
        # Analyzer itself no longer downgrades severity — scanner handles suppression.
        # SEC-001 in a test file is reported at HIGH by the analyzer.
        # The scanner would suppress it before it reaches result.findings.
        code = 'password = "supersecret123"'
        findings = HardcodedSecretsAnalyzer().analyze("src/test/java/UserServiceTest.java", code)
        assert findings, "Analyzer should detect the pattern"
        assert findings[0].severity == Severity.HIGH

    def test_analyzer_reports_critical_in_test_file(self):
        # Analyzer reports at CRITICAL regardless of path. Scanner suppresses.
        code = 'String key = "-----BEGIN RSA PRIVATE KEY-----";'
        findings = HardcodedSecretsAnalyzer().analyze("src/test/CryptoTest.java", code)
        crit = [f for f in findings if f.rule_id == "SEC-005"]
        assert crit and crit[0].severity == Severity.CRITICAL

    def test_analyzer_reports_spec_directory_at_full_severity(self):
        # Severity downgrade removed — scanner suppresses test/spec findings instead.
        code = 'password = "testpass"'
        findings = HardcodedSecretsAnalyzer().analyze("spec/auth_spec.rb", code)
        assert findings and findings[0].severity == Severity.HIGH

    def test_analyzer_reports_test_suffix_at_full_severity(self):
        code = 'String password = "MyP@ssw0rd";'
        findings = HardcodedSecretsAnalyzer().analyze("AuthControllerTest.java", code)
        assert findings and findings[0].severity == Severity.HIGH


# ── AST-based Python analyzer ─────────────────────────────────────────────────

AST = PythonASTAnalyzer()
FIXTURE_AST = _load("vulnerable_ast_python.py")


class TestPythonASTSQLInjection:
    def test_detects_fstring(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SQL-001" in rule_ids

    def test_detects_concat(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SQL-002" in rule_ids

    def test_detects_percent_format(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SQL-003" in rule_ids

    def test_detects_dot_format(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SQL-004" in rule_ids

    def test_no_false_positive_parameterized(self):
        safe = 'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))'
        assert AST.analyze("t.py", safe) == []

    def test_no_false_positive_in_string_literal(self):
        # Pattern inside a docstring — must NOT fire
        code = 'doc = "avoid: cursor.execute(query + var)"'
        assert AST.analyze("t.py", code) == []


class TestPythonASTCommandInjection:
    def test_detects_os_system(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-CMD-001" in rule_ids

    def test_detects_shell_true(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-CMD-002" in rule_ids

    def test_detects_eval(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-CMD-003" in rule_ids

    def test_detects_exec(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-CMD-004" in rule_ids

    def test_no_false_positive_literal_os_system(self):
        # os.system with a string literal is low-risk (no user input)
        safe = 'os.system("ls -la")'
        rule_ids = {f.rule_id for f in AST.analyze("t.py", safe)}
        assert "AST-CMD-001" not in rule_ids

    def test_no_false_positive_safe_subprocess(self):
        safe = 'subprocess.run(["ping", host])'
        assert AST.analyze("t.py", safe) == []

    def test_no_false_positive_method_named_exec(self):
        # A method called exec() on an object must NOT trigger AST-CMD-004
        code = "regex.exec(text)"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-CMD-004" not in rule_ids

    def test_no_false_positive_eval_in_string(self):
        code = 'doc = "never use eval(user_input)"'
        assert AST.analyze("t.py", code) == []


class TestPythonASTPathTraversal:
    def test_detects_user_input(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-PATH-001" in rule_ids

    def test_detects_fstring_path(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-PATH-002" in rule_ids

    def test_no_false_positive_literal_path(self):
        safe = 'open("config/settings.json")'
        assert AST.analyze("t.py", safe) == []


class TestPythonASTHardcodedSecrets:
    def test_detects_secret_key(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SEC-001" in rule_ids

    def test_skips_placeholder(self):
        code = 'password = "your-password-here"'
        assert AST.analyze("t.py", code) == []

    def test_no_false_positive_secret_in_docstring(self):
        code = 'help = "set SECRET_KEY=mysecret in your env"'
        assert AST.analyze("t.py", code) == []


# ── new vulnerability types ───────────────────────────────────────────────────

class TestDeserializationAnalyzer:
    def test_detects_php_unserialize(self):
        code = '$obj = unserialize($data);'
        findings = DeserializationAnalyzer().analyze("app.php", code)
        assert any(f.rule_id == "DESER-004" for f in findings)

    def test_detects_java_object_input_stream(self):
        code = 'ObjectInputStream ois = new ObjectInputStream(input);'
        findings = DeserializationAnalyzer().analyze("App.java", code)
        assert any(f.rule_id == "DESER-005" for f in findings)

    def test_detects_ruby_marshal(self):
        code = 'obj = Marshal.load(data)'
        findings = DeserializationAnalyzer().analyze("app.rb", code)
        assert any(f.rule_id == "DESER-006" for f in findings)

    def test_detects_node_serialize(self):
        code = "const serialize = require('node-serialize');"
        findings = DeserializationAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "DESER-008" for f in findings)


class TestSSRFAnalyzer:
    def test_detects_php_curl_user_url(self):
        code = 'curl_setopt($ch, CURLOPT_URL, $_GET["url"]);'
        findings = SSRFAnalyzer().analyze("app.php", code)
        assert any(f.rule_id == "SSRF-001" for f in findings)

    def test_detects_node_fetch_user_url(self):
        code = 'const resp = await fetch(req.query.url);'
        findings = SSRFAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "SSRF-005" for f in findings)


class TestOpenRedirectAnalyzer:
    def test_detects_express_redirect(self):
        code = 'res.redirect(req.query.next);'
        findings = OpenRedirectAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "REDIR-005" for f in findings)

    def test_detects_rails_redirect(self):
        code = 'redirect_to params[:url]'
        findings = OpenRedirectAnalyzer().analyze("app.rb", code)
        assert any(f.rule_id == "REDIR-007" for f in findings)

    def test_detects_java_send_redirect(self):
        code = 'response.sendRedirect(request.getParameter("next"));'
        findings = OpenRedirectAnalyzer().analyze("Ctrl.java", code)
        assert any(f.rule_id == "REDIR-003" for f in findings)


class TestSSTIAnalyzer:
    def test_detects_ejs_render(self):
        code = 'const html = ejs.render(req.body.template);'
        findings = SSTIAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "SSTI-006" for f in findings)

    def test_detects_handlebars_compile(self):
        code = 'const fn = Handlebars.compile(userTemplate);'
        findings = SSTIAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "SSTI-007" for f in findings)

    def test_no_fp_literal_template(self):
        code = "const fn = Handlebars.compile('<p>{{name}}</p>');"
        findings = SSTIAnalyzer().analyze("app.js", code)
        assert not any(f.rule_id == "SSTI-007" for f in findings)

    def test_detects_ruby_erb_new(self):
        code = 'tmpl = ERB.new(user_input)'
        findings = SSTIAnalyzer().analyze("app.rb", code)
        assert any(f.rule_id == "SSTI-005" for f in findings)


class TestPrototypePollutionAnalyzer:
    def test_detects_proto_assignment(self):
        code = 'obj.__proto__[key] = value;'
        findings = PrototypePollutionAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "PROTO-001" for f in findings)

    def test_detects_object_assign_req_body(self):
        code = 'Object.assign(config, req.body);'
        findings = PrototypePollutionAnalyzer().analyze("app.js", code)
        assert any(f.rule_id == "PROTO-003" for f in findings)

    def test_detects_dangerous_innerhtml_react(self):
        code = '<div dangerouslySetInnerHTML={{ __html: content }} />'
        findings = PrototypePollutionAnalyzer().analyze("App.tsx", code)
        assert any(f.rule_id == "PROTO-005" for f in findings)


# ── AST-based tests for new Python vuln types ─────────────────────────────────

class TestPythonASTDeserialization:
    def test_detects_pickle_loads(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-DESER-001" in rule_ids

    def test_detects_marshal_loads(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-DESER-002" in rule_ids

    def test_detects_yaml_unsafe_load(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-DESER-003" in rule_ids

    def test_detects_yaml_load_no_loader(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-DESER-004" in rule_ids

    def test_no_fp_yaml_safe_load(self):
        code = "import yaml\nresult = yaml.safe_load(stream)"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-DESER-004" not in rule_ids

    def test_no_fp_yaml_load_with_safe_loader(self):
        code = "import yaml\nresult = yaml.load(stream, Loader=yaml.SafeLoader)"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-DESER-004" not in rule_ids


class TestPythonTLSVerify:
    def test_requests_verify_false_flagged(self):
        code = "import requests\nrequests.get(url, verify=False)"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-TLS-001" in rule_ids

    def test_requests_post_verify_false_flagged(self):
        code = "import requests\nrequests.post(url, data=body, verify=False)"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-TLS-001" in rule_ids

    def test_requests_verify_true_not_flagged(self):
        code = "import requests\nrequests.get(url, verify=True)"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-TLS-001" not in rule_ids

    def test_requests_verify_capath_not_flagged(self):
        code = "import requests\nrequests.get(url, verify='/etc/ssl/certs/ca-bundle.crt')"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-TLS-001" not in rule_ids

    def test_requests_no_verify_kwarg_not_flagged(self):
        code = "import requests\nrequests.get(url)"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-TLS-001" not in rule_ids


def _java_class(body: str) -> str:
    return f"public class T {{\n{body}\n}}"


@_skip_no_javalang
class TestJavaInterproceduralTaint:
    def test_this_method_tainted_arg_passthrough(self):
        code = """
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;
public class T {
    private String wrap(String x) { return x; }
    public void handle(HttpServletRequest req, Connection conn) throws Exception {
        String raw = req.getParameter("q");
        String val = this.wrap(raw);
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x='" + val + "'");
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" in rule_ids, "this.method(tainted) passthrough not detected"

    def test_this_method_inherent_request_source(self):
        code = """
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;
public class T {
    HttpServletRequest req;
    private String getInput() { return req.getParameter("input"); }
    public void handle(Connection conn) throws Exception {
        String val = getInput();
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x='" + val + "'");
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" in rule_ids, "bare call to inherent taint-source method not detected"


@_skip_no_javalang
class TestJavaSnakeYAML:
    def test_new_yaml_no_arg_flagged(self):
        code = _java_class("public Object p(String s){Yaml yaml=new Yaml();return yaml.load(s);}")
        findings = JavaASTAnalyzer().analyze("Test.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-DESER-002" in rule_ids

    def test_new_yaml_unsafe_constructor_flagged(self):
        code = _java_class("public Object p(String s){Yaml y=new Yaml(new Constructor(Foo.class));return y.load(s);}")
        findings = JavaASTAnalyzer().analyze("Test.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-DESER-002" in rule_ids

    def test_new_yaml_safe_constructor_not_flagged(self):
        code = _java_class("public Object p(String s){Yaml y=new Yaml(new SafeConstructor(new LoaderOptions()));return y.load(s);}")
        findings = JavaASTAnalyzer().analyze("Test.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-DESER-002" not in rule_ids


@_skip_no_javalang
class TestJavaSSLBypass:
    def test_allow_all_hostname_verifier_flagged(self):
        code = "conn.setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);"
        findings = JavaAnalyzer().analyze("Test.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAVA-TLS-001" in rule_ids

    def test_noop_hostname_verifier_flagged(self):
        code = "builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);"
        findings = JavaAnalyzer().analyze("Test.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAVA-TLS-001" in rule_ids

    def test_allow_all_no_false_positives_on_safe_yaml(self):
        # JAVA-TLS-001 must not fire on SnakeYAML SafeConstructor usage
        code = "Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));"
        findings = JavaAnalyzer().analyze("Test.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAVA-TLS-001" not in rule_ids


@_skip_no_javalang
class TestSpringJdbcTemplate:
    """Spring JdbcTemplate: tainted SQL string = TP; bound param args = FP-free."""

    _PREAMBLE = (
        "import javax.servlet.http.HttpServletRequest;\n"
        "import org.springframework.jdbc.core.JdbcTemplate;\n"
    )

    def test_tainted_sql_first_arg_flagged(self):
        code = self._PREAMBLE + """
public class T {
    JdbcTemplate tpl;
    public String get(HttpServletRequest req) {
        String id = req.getParameter("id");
        return tpl.queryForObject("SELECT name FROM users WHERE id = " + id, String.class);
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" in rule_ids, "tainted SQL first arg must be flagged"

    def test_parameterized_bound_arg_not_flagged(self):
        code = self._PREAMBLE + """
public class T {
    JdbcTemplate tpl;
    public String get(HttpServletRequest req) {
        String id = req.getParameter("id");
        return tpl.queryForObject("SELECT name FROM users WHERE id = ?", String.class, id);
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" not in rule_ids, "bound parameter must NOT be flagged as SQLi"

    def test_query_tainted_sql_flagged(self):
        code = self._PREAMBLE + """
public class T {
    JdbcTemplate tpl;
    public void list(HttpServletRequest req) {
        String name = req.getParameter("name");
        tpl.query("SELECT * FROM users WHERE name = '" + name + "'",
                  (rs, r) -> rs.getString("id"));
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" in rule_ids, "tainted SQL in query() must be flagged"

    def test_query_parameterized_not_flagged(self):
        code = self._PREAMBLE + """
public class T {
    JdbcTemplate tpl;
    public void list(HttpServletRequest req) {
        String name = req.getParameter("name");
        tpl.query("SELECT * FROM users WHERE name = ?", (rs, r) -> rs.getString("id"), name);
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" not in rule_ids, "parameterized query() with bound arg must NOT be flagged"


class TestPythonASTSSRF:
    def test_detects_requests_get_user_url(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SSRF-001" in rule_ids

    def test_detects_requests_post_dynamic(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SSRF-002" in rule_ids

    def test_no_fp_literal_url(self):
        code = "import requests\nrequests.get('https://api.example.com/data')"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-SSRF-001" not in rule_ids
        assert "AST-SSRF-002" not in rule_ids


class TestPythonASTOpenRedirect:
    def test_detects_redirect_user_input(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-REDIR-001" in rule_ids

    def test_detects_redirect_dynamic(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-REDIR-002" in rule_ids

    def test_no_fp_literal_redirect(self):
        code = "from flask import redirect\nreturn redirect('/home')"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-REDIR-001" not in rule_ids
        assert "AST-REDIR-002" not in rule_ids


class TestPythonASTSSTI:
    def test_detects_render_template_string_user_input(self):
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SSTI-001" in rule_ids

    def test_no_fp_literal_template(self):
        code = "from flask import render_template_string\nrender_template_string('<h1>ok</h1>')"
        rule_ids = {f.rule_id for f in AST.analyze("t.py", code)}
        assert "AST-SSTI-001" not in rule_ids


# ── multi-hop taint tracking ──────────────────────────────────────────────────

class TestTaintTracking:
    """Variable assignment chains should propagate taint through 1–2 hops."""

    def test_ssrf_indirect_variable(self):
        code = (
            "import requests\n"
            "def view(request):\n"
            "    url = request.args.get('url')\n"
            "    return requests.get(url)\n"
        )
        findings = AST.analyze("t.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-SSRF-001" in rule_ids
        assert all(f.severity == Severity.HIGH for f in findings if f.rule_id == "AST-SSRF-001")

    def test_redirect_indirect_variable(self):
        code = (
            "from flask import redirect\n"
            "def view(request):\n"
            "    dest = request.args.get('next')\n"
            "    return redirect(dest)\n"
        )
        findings = AST.analyze("t.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-REDIR-001" in rule_ids

    def test_path_indirect_variable(self):
        code = (
            "def view(request):\n"
            "    filename = request.args.get('file')\n"
            "    open(filename)\n"
        )
        findings = AST.analyze("t.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-PATH-001" in rule_ids

    def test_taint_does_not_cross_function_boundary(self):
        """Taint in function A must not infect lookups in function B."""
        code = (
            "import requests\n"
            "def setup(request):\n"
            "    url = request.args.get('url')\n"
            "\n"
            "def safe_view():\n"
            "    url = 'https://safe.example.com'\n"
            "    return requests.get(url)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(
            f.rule_id == "AST-SSRF-001" and f.line_number >= 6
            for f in findings
        )

    def test_fixture_indirect_cases(self):
        """The updated fixture's indirect patterns are all detected."""
        rule_ids = {f.rule_id for f in AST.analyze("t.py", FIXTURE_AST)}
        assert "AST-SSRF-001" in rule_ids
        assert "AST-REDIR-001" in rule_ids
        assert "AST-PATH-001" in rule_ids

    def test_no_false_positive_generic_data_param(self):
        """A function param named 'data' must not auto-taint its subscript keys."""
        code = (
            "import json\n"
            "def save_plugin(self, data):\n"
            "    config_file = data['config_file']\n"
            "    with open(config_file, 'w') as f:\n"
            "        json.dump(data, f)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(f.rule_id == "AST-PATH-001" for f in findings)

    def test_data_from_request_still_tainted(self):
        """When 'data' is explicitly assigned from request, subscripts remain tainted."""
        code = (
            "def view(request):\n"
            "    data = request.get_json()\n"
            "    path = data['filename']\n"
            "    open(path)\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(f.rule_id == "AST-PATH-001" for f in findings)

    def test_subprocess_constant_variable_no_flag(self):
        """cmd = 'literal'; Popen(cmd, shell=True) must not be flagged — constant propagation."""
        code = (
            "import subprocess\n"
            "def run_restart():\n"
            "    cmd = 'schtasks /End /TN \"MyTask\" && schtasks /Run /TN \"MyTask\"'\n"
            "    subprocess.Popen(cmd, shell=True)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(f.rule_id == "AST-CMD-002" for f in findings)

    def test_subprocess_variable_command_still_flagged(self):
        """cmd derived from user input with shell=True must still be flagged HIGH."""
        code = (
            "import subprocess\n"
            "def view(request):\n"
            "    cmd = request.args.get('cmd')\n"
            "    subprocess.Popen(cmd, shell=True)\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(f.rule_id == "AST-CMD-002" for f in findings)

    # ── interprocedural Phase 1 ───────────────────────────────────────────────

    def test_interprocedural_3stmt_wrapper_detected(self):
        """3-statement wrapper (prev only ≤2 were handled) should propagate taint."""
        code = (
            "import sqlite3\n"
            "import logging\n"
            "def get_user_id():\n"
            "    raw = request.args.get('id')\n"
            "    logging.debug('got id: %s', raw)\n"
            "    return raw\n"
            "\n"
            "def view():\n"
            "    uid = get_user_id()\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM users WHERE id = ' + uid)\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(f.rule_id.startswith("AST-SQL-") for f in findings)

    def test_interprocedural_if_branch_tainted_detected(self):
        """Wrapper with if/else: tainted branch makes the whole call tainted."""
        code = (
            "import sqlite3\n"
            "def get_param(flag):\n"
            "    if flag:\n"
            "        return 'default'\n"
            "    return request.args.get('q')\n"
            "\n"
            "def view():\n"
            "    q = get_param(False)\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM t WHERE x = ' + q)\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(f.rule_id.startswith("AST-SQL-") for f in findings)

    # ── Phase 2: argument→parameter taint injection ───────────────────────────

    def test_interprocedural_tainted_arg_to_sink_inside_callee(self):
        """Tainted arg passed to a local function that uses it in a sink."""
        code = (
            "import sqlite3\n"
            "def run_query(sql):\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute(sql)\n"
            "\n"
            "def view():\n"
            "    run_query('SELECT * FROM t WHERE x = ' + request.args.get('q'))\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(f.rule_id.startswith("AST-SQL-") for f in findings)

    def test_interprocedural_tainted_arg_severity_upgrades_to_high(self):
        """When tainted arg reaches a sink inside callee, severity is HIGH not MEDIUM."""
        code = (
            "import sqlite3\n"
            "def run_query(sql):\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute(sql)\n"
            "\n"
            "def view():\n"
            "    run_query('SELECT * FROM t WHERE x = ' + request.args.get('q'))\n"
        )
        findings = AST.analyze("t.py", code)
        sql_findings = [f for f in findings if f.rule_id.startswith("AST-SQL-")]
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in sql_findings)

    def test_interprocedural_clean_arg_no_upgrade(self):
        """Literal (CLEAN) arg passed to a local function must not produce HIGH SQL finding."""
        code = (
            "import sqlite3\n"
            "def run_query(sql):\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute(sql)\n"
            "\n"
            "def view():\n"
            "    run_query('SELECT * FROM t WHERE x = 1')\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(
            f.rule_id.startswith("AST-SQL-") and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )

    # ── Phase 3: tainted arg → return → caller propagation ────────────────────

    def test_phase3_passthrough_return_tainted(self):
        """val = f(tainted_arg) where f returns its param → val must be TAINTED in caller."""
        code = (
            "import sqlite3\n"
            "def passthrough(x):\n"
            "    return x\n"
            "\n"
            "def view():\n"
            "    val = passthrough(request.args.get('q'))\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM t WHERE x = ' + val)\n"
        )
        findings = AST.analyze("t.py", code)
        sql = [f for f in findings if f.rule_id.startswith("AST-SQL-")]
        assert sql, "expected SQL finding"
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in sql)

    def test_phase3_transform_return_tainted(self):
        """f(tainted) that strips and returns tainted param must propagate TAINTED."""
        code = (
            "import sqlite3\n"
            "def clean_input(x):\n"
            "    return x.strip()\n"
            "\n"
            "def view():\n"
            "    val = clean_input(request.args.get('q'))\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM t WHERE x = ' + val)\n"
        )
        findings = AST.analyze("t.py", code)
        sql = [f for f in findings if f.rule_id.startswith("AST-SQL-")]
        assert sql, "expected SQL finding"
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in sql)

    def test_phase3_clean_arg_not_propagated(self):
        """Literal arg through passthrough must not upgrade to HIGH in caller."""
        code = (
            "import sqlite3\n"
            "def passthrough(x):\n"
            "    return x\n"
            "\n"
            "def view():\n"
            "    val = passthrough('safe_literal')\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM t WHERE x = ' + val)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(
            f.rule_id.startswith("AST-SQL-") and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )

    # ── #8 条件分岐ガード ─────────────────────────────────────────────────────────

    def test_guard_re_match_if_body(self):
        """re.match() in if condition suppresses HIGH inside the guarded body."""
        code = (
            "import sqlite3, re\n"
            "def view():\n"
            "    uid = request.args.get('id')\n"
            "    if re.match(r'^\\d+$', uid):\n"
            "        conn = sqlite3.connect('db')\n"
            "        conn.execute('SELECT * FROM users WHERE id = ' + uid)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(
            f.rule_id.startswith("AST-SQL-") and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )

    def test_guard_re_match_early_return(self):
        """not re.match() followed by return suppresses HIGH in subsequent stmts."""
        code = (
            "import sqlite3, re\n"
            "def view():\n"
            "    uid = request.args.get('id')\n"
            "    if not re.match(r'^\\d+$', uid):\n"
            "        return\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM users WHERE id = ' + uid)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(
            f.rule_id.startswith("AST-SQL-") and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )

    def test_guard_allowlist_not_in_early_return(self):
        """var not in ALLOWED followed by return suppresses HIGH in subsequent stmts."""
        code = (
            "import sqlite3\n"
            "ALLOWED = ['asc', 'desc']\n"
            "def view():\n"
            "    order = request.args.get('order')\n"
            "    if order not in ALLOWED:\n"
            "        return\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM t ORDER BY col ' + order)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(
            f.rule_id.startswith("AST-SQL-") and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )

    def test_guard_allowlist_in_if_body(self):
        """var in [literal_list] inside if body suppresses HIGH."""
        code = (
            "import sqlite3\n"
            "def view():\n"
            "    order = request.args.get('order')\n"
            "    if order in ['asc', 'desc']:\n"
            "        conn = sqlite3.connect('db')\n"
            "        conn.execute('SELECT * FROM t ORDER BY col ' + order)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(
            f.rule_id.startswith("AST-SQL-") and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )

    def test_guard_absent_still_fires(self):
        """Without any guard, unvalidated tainted input must still produce HIGH."""
        code = (
            "import sqlite3\n"
            "def view():\n"
            "    uid = request.args.get('id')\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM users WHERE id = ' + uid)\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(
            f.rule_id.startswith("AST-SQL-") and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )

    def test_interprocedural_nested_func_no_outer_contamination(self):
        """Tainted return inside a nested function must not mark the outer function."""
        code = (
            "import sqlite3\n"
            "def get_safe():\n"
            "    def _inner():\n"
            "        return request.args.get('x')\n"
            "    return 'safe_value'\n"
            "\n"
            "def view():\n"
            "    val = get_safe()\n"
            "    conn = sqlite3.connect('db')\n"
            "    conn.execute('SELECT * FROM t WHERE x = ' + val)\n"
        )
        findings = AST.analyze("t.py", code)
        # get_safe() is CLEAN — its only return is a literal.
        # val is therefore UNKNOWN → any SQL finding would be MEDIUM, not HIGH/CRITICAL.
        assert not any(
            f.rule_id == "AST-SQL-001" and f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in findings
        )


# ── suppression comments ──────────────────────────────────────────────────────

def _make_finding(rule_id: str, lineno: int) -> Finding:
    return Finding(
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.HIGH,
        file_path="test.py",
        line_number=lineno,
        line_content="",
        description="test",
        rule_id=rule_id,
    )


class TestSuppressionComments:
    def test_suppress_all_same_line(self):
        lines = ["cursor.execute(query)  # vulnscanner: ignore"]
        assert _is_suppressed(_make_finding("SQL-001", 1), lines)

    def test_suppress_all_previous_line(self):
        lines = ["# vulnscanner: ignore", "cursor.execute(query)"]
        assert _is_suppressed(_make_finding("SQL-001", 2), lines)

    def test_suppress_specific_rule_match(self):
        lines = ["cursor.execute(query)  # vulnscanner: ignore[SQL-001]"]
        assert _is_suppressed(_make_finding("SQL-001", 1), lines)

    def test_suppress_specific_rule_no_match(self):
        lines = ["cursor.execute(query)  # vulnscanner: ignore[XSS-001]"]
        assert not _is_suppressed(_make_finding("SQL-001", 1), lines)

    def test_suppress_multi_rule(self):
        lines = ["cursor.execute(query)  # vulnscanner: ignore[SQL-001, XSS-001]"]
        assert _is_suppressed(_make_finding("SQL-001", 1), lines)
        assert _is_suppressed(_make_finding("XSS-001", 1), lines)

    def test_no_suppress_without_comment(self):
        lines = ["cursor.execute(query)"]
        assert not _is_suppressed(_make_finding("SQL-001", 1), lines)

    def test_suppress_js_double_slash(self):
        lines = ["res.redirect(req.query.url)  // vulnscanner: ignore"]
        assert _is_suppressed(_make_finding("REDIR-001", 1), lines)

    def test_case_insensitive(self):
        lines = ["cursor.execute(query)  # VulnScanner: IGNORE"]
        assert _is_suppressed(_make_finding("SQL-001", 1), lines)


# ── SARIF output ──────────────────────────────────────────────────────────────

class TestSARIFReporter:
    def _make_result(self) -> ScanResult:
        result = ScanResult(repo_url="https://github.com/test/repo")
        result.findings = [
            Finding(
                vuln_type=VulnType.XSS,
                severity=Severity.HIGH,
                file_path="src/app.js",
                line_number=42,
                line_content='el.innerHTML = user',
                description="Direct innerHTML assignment",
                rule_id="XSS-001",
            ),
            Finding(
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                file_path="api/db.py",
                line_number=10,
                line_content='cursor.execute(query)',
                description="SQL injection via f-string",
                rule_id="AST-SQL-001",
            ),
        ]
        return result

    def test_sarif_valid_json(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        write_sarif(result, path)
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"

    def test_sarif_has_results(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        write_sarif(result, path)
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        sarif_results = doc["runs"][0]["results"]
        assert len(sarif_results) == 2

    def test_sarif_severity_mapping(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        write_sarif(result, path)
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
        assert levels["XSS-001"] == "error"
        assert levels["AST-SQL-001"] == "error"

    def test_sarif_rule_registry(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        write_sarif(result, path)
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert "XSS-001" in rule_ids
        assert "AST-SQL-001" in rule_ids

    def test_sarif_file_uri(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        write_sarif(result, path)
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        uris = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]
        }
        assert "src/app.js" in uris

    def test_sarif_rank_default(self):
        # Findings with default confidence=1.0 get rank=100.0
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        write_sarif(result, path)
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        for r in doc["runs"][0]["results"]:
            assert r["rank"] == 100.0, f"{r['ruleId']} should have rank=100 for confidence=1.0"

    def test_sarif_rank_taint_confidence(self):
        # Taint-based finding with confidence<1.0 must emit rank=confidence*100
        from vulnscanner.taint import TaintInfo, TaintStatus
        result = ScanResult(repo_url="test")
        result.findings = [
            Finding(
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.MEDIUM,
                file_path="app.py",
                line_number=5,
                line_content="cursor.execute(q)",
                description="[low_reach] execute() receives a variable",
                rule_id="AST-SQL-005",
                taint_status="unknown",
                confidence=0.3,
            ),
            Finding(
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.HIGH,
                file_path="app.py",
                line_number=6,
                line_content="cursor.execute(q)",
                description="execute() receives tainted input",
                rule_id="AST-SQL-001",
                taint_status="tainted",
                confidence=0.9,
            ),
        ]
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        write_sarif(result, path)
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        by_rule = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
        assert by_rule["AST-SQL-005"]["rank"] == 30.0
        assert by_rule["AST-SQL-001"]["rank"] == 90.0
        # low_reach finding must carry confidence in properties
        assert by_rule["AST-SQL-005"]["properties"]["confidence"] == 0.3
        assert by_rule["AST-SQL-005"]["properties"]["taint_status"] == "unknown"
        # high-confidence finding has no 'properties' key (confidence omitted when 1.0)
        assert "properties" not in by_rule["AST-SQL-001"] or \
               by_rule["AST-SQL-001"].get("properties", {}).get("confidence") == 0.9


# ── dependency parser unit tests ──────────────────────────────────────────────

class TestDependencyParsers:
    def test_parse_requirements_exact(self):
        content = "flask==2.3.2\nrequests==2.28.0\n# comment\n-r base.txt\n"
        pkgs = _parse_requirements(content)
        names = {p[0] for p in pkgs}
        assert "flask" in names
        assert "requests" in names

    def test_parse_requirements_skips_range(self):
        content = "flask>=2.0\nrequests==2.28.0\n"
        pkgs = _parse_requirements(content)
        # Only exact pin is captured
        assert len(pkgs) == 1
        assert pkgs[0][0] == "requests"

    def test_parse_package_json(self):
        data = json.dumps({
            "dependencies": {"express": "4.18.2"},
            "devDependencies": {"jest": "29.0.0"},
        })
        pkgs = _parse_package_json(data)
        names = {p[0] for p in pkgs}
        assert "express" in names
        assert "jest" in names

    def test_parse_package_json_strips_caret(self):
        data = json.dumps({"dependencies": {"lodash": "^4.17.21"}})
        pkgs = _parse_package_json(data)
        assert pkgs[0][1] == "4.17.21"

    def test_parse_gemfile_lock(self):
        content = (
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    rails (7.0.4)\n"
            "    activerecord (7.0.4)\n"
        )
        pkgs = _parse_gemfile_lock(content)
        names = {p[0] for p in pkgs}
        assert "rails" in names
        assert "activerecord" in names

    def test_parse_go_mod(self):
        content = (
            "module example.com/myapp\n\n"
            "require (\n"
            "    github.com/gin-gonic/gin v1.9.1\n"
            "    golang.org/x/crypto v0.12.0\n"
            ")\n"
        )
        pkgs = _parse_go_mod(content)
        names = {p[0] for p in pkgs}
        assert "github.com/gin-gonic/gin" in names

    def test_dependency_analyzer_supports(self):
        da = DependencyAnalyzer()
        assert da.supports("requirements.txt")
        assert da.supports("path/to/package.json")
        assert da.supports("Gemfile.lock")
        assert da.supports("go.mod")
        assert not da.supports("main.py")
        assert not da.supports("app.js")


# ── --exclude glob patterns ───────────────────────────────────────────────────

class TestExcludePatterns:
    def test_exclude_by_filename(self):
        assert _is_excluded("src/jquery.js", ["jquery.js"])
        assert not _is_excluded("src/app.js", ["jquery.js"])

    def test_exclude_by_glob_wildcard(self):
        assert _is_excluded("tests/test_foo.py", ["tests/**"])
        assert not _is_excluded("src/foo.py", ["tests/**"])

    def test_exclude_by_extension_glob(self):
        assert _is_excluded("src/bundle.min.js", ["*.min.js"])
        assert not _is_excluded("src/app.js", ["*.min.js"])

    def test_exclude_directory_pattern(self):
        # "tests/" should match any path with "tests" as a component
        assert _is_excluded("tests/unit/test_foo.py", ["tests/"])
        assert not _is_excluded("src/main.py", ["tests/"])

    def test_exclude_multiple_patterns(self):
        patterns = ["tests/**", "vendor/**", "*.min.js"]
        assert _is_excluded("tests/test_foo.py", patterns)
        assert _is_excluded("vendor/lib.py", patterns)
        assert _is_excluded("app.min.js", patterns)
        assert not _is_excluded("src/app.py", patterns)

    def test_no_patterns_excludes_nothing(self):
        assert not _is_excluded("src/app.py", [])
        assert not _is_excluded("tests/foo.py", [])


# ── .vulnscannerignore parsing ────────────────────────────────────────────────

class TestIgnoreFileParsing:
    def test_parses_patterns(self):
        content = "tests/**\nvendor/**\n# comment\n\n*.min.js\n"
        patterns = _parse_ignore_file(content)
        assert patterns == ["tests/**", "vendor/**", "*.min.js"]

    def test_ignores_blank_lines_and_comments(self):
        content = "\n# This is a comment\n\nfoo/**\n"
        patterns = _parse_ignore_file(content)
        assert patterns == ["foo/**"]

    def test_empty_file(self):
        assert _parse_ignore_file("") == []
        assert _parse_ignore_file("# only comments\n") == []


# ── scan result metadata ──────────────────────────────────────────────────────

class TestScanResultMetadata:
    def test_elapsed_defaults_to_zero(self):
        r = ScanResult(repo_url="x")
        assert r.elapsed_seconds == 0.0

    def test_suppressed_count_defaults_to_zero(self):
        r = ScanResult(repo_url="x")
        assert r.suppressed_count == 0

    def test_json_includes_metadata(self):
        from vulnscanner.reporters.json_reporter import to_dict
        r = ScanResult(repo_url="test", elapsed_seconds=1.23, suppressed_count=3)
        d = to_dict(r)
        assert d["summary"]["elapsed_seconds"] == 1.23
        assert d["summary"]["suppressed_count"] == 3


# ── client-side security analyzer ────────────────────────────────────────────

CS = ClientSideAnalyzer()


class TestClientSideAnalyzer:
    # CLIENT-CRED-001

    def test_cred_api_key_in_localstorage(self):
        code = "localStorage.setItem('fugu_api_key', key);"
        findings = CS.analyze("t.html", code)
        assert any(f.rule_id == "CLIENT-CRED-001" for f in findings)

    def test_cred_password_in_sessionstorage(self):
        code = "sessionStorage.setItem('user_password', pwd);"
        findings = CS.analyze("t.js", code)
        assert any(f.rule_id == "CLIENT-CRED-001" for f in findings)

    def test_cred_non_sensitive_key_no_flag(self):
        code = "localStorage.setItem('theme', 'dark');"
        findings = CS.analyze("t.html", code)
        assert not any(f.rule_id == "CLIENT-CRED-001" for f in findings)

    # CLIENT-SRI-001

    def test_sri_cdn_script_no_integrity(self):
        code = '<script src="https://cdn.example.com/lib.js"></script>'
        findings = CS.analyze("t.html", code)
        assert any(f.rule_id == "CLIENT-SRI-001" for f in findings)

    def test_sri_cdn_script_with_integrity_no_flag(self):
        code = '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
        findings = CS.analyze("t.html", code)
        assert not any(f.rule_id == "CLIENT-SRI-001" for f in findings)

    # CLIENT-SRI-002

    def test_sri2_esm_import_from_cdn(self):
        code = "import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';"
        findings = CS.analyze("t.html", code)
        assert any(f.rule_id == "CLIENT-SRI-002" for f in findings)

    def test_sri2_local_import_no_flag(self):
        code = "import { helper } from './utils.js';"
        findings = CS.analyze("t.js", code)
        assert not any(f.rule_id == "CLIENT-SRI-002" for f in findings)

    # CLIENT-FETCH-001

    def test_fetch_direct_localstorage_url(self):
        code = "fetch(localStorage.getItem('endpoint'));"
        findings = CS.analyze("t.js", code)
        assert any(f.rule_id == "CLIENT-FETCH-001" for f in findings)

    def test_fetch_variable_from_localstorage(self):
        code = (
            "const baseUrl = localStorage.getItem('fugu_base_url') || 'https://default.com';\n"
            "const res = await fetch(`${baseUrl}/chat/completions`, { method: 'POST' });\n"
        )
        findings = CS.analyze("t.html", code)
        assert any(f.rule_id == "CLIENT-FETCH-001" for f in findings)

    def test_fetch_static_url_no_flag(self):
        code = "const res = await fetch('https://api.example.com/v1/data');"
        findings = CS.analyze("t.js", code)
        assert not any(f.rule_id == "CLIENT-FETCH-001" for f in findings)

    # CLIENT-MSG-001

    def test_postmessage_no_origin_check(self):
        code = (
            "window.addEventListener('message', function(event) {\n"
            "    const data = event.data;\n"
            "    processData(data);\n"
            "});\n"
        )
        findings = CS.analyze("t.js", code)
        assert any(f.rule_id == "CLIENT-MSG-001" for f in findings)

    def test_postmessage_with_origin_check_no_flag(self):
        code = (
            "window.addEventListener('message', function(event) {\n"
            "    if (event.origin !== 'https://trusted.com') return;\n"
            "    const data = event.data;\n"
            "    processData(data);\n"
            "});\n"
        )
        findings = CS.analyze("t.js", code)
        assert not any(f.rule_id == "CLIENT-MSG-001" for f in findings)


class TestLogInjection:
    def test_stdlib_logging_tainted_flagged(self):
        code = "import logging\nfrom flask import request\nlogging.info(request.args.get('u'))"
        findings = AST.analyze("t.py", code, "")
        assert any(f.rule_id == "AST-LOG-001" for f in findings)

    def test_logger_instance_tainted_flagged(self):
        code = "import logging\nfrom flask import request\nlogger=logging.getLogger(__name__)\nlogger.warning(request.form.get('x'))"
        findings = AST.analyze("t.py", code, "")
        assert any(f.rule_id == "AST-LOG-001" for f in findings)

    def test_logging_literal_not_flagged(self):
        code = "import logging\nlogging.info('server started')"
        findings = AST.analyze("t.py", code, "")
        assert not any(f.rule_id == "AST-LOG-001" for f in findings)

    def test_logging_unknown_not_flagged(self):
        code = "import logging\ndef f(user_name): logging.info(user_name)"
        findings = AST.analyze("t.py", code, "")
        # UNKNOWN param → should NOT fire (only TAINTED fires)
        crits = [f for f in findings if f.rule_id == "AST-LOG-001" and f.taint_status == "tainted"]
        assert not crits


class TestFlaskMarkupXSS:
    """Flask Markup() with user input should fire AST-XSS-001; literals must not."""

    def test_markup_tainted_arg_flagged(self):
        code = (
            "from flask import request\n"
            "from markupsafe import Markup\n"
            "def view():\n"
            "    name = request.args.get('name')\n"
            "    return Markup(name)\n"
        )
        findings = AST.analyze("views.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-XSS-001" in rule_ids, "Markup(tainted) must be flagged"

    def test_markup_tainted_fires_high(self):
        code = (
            "from flask import request\n"
            "from markupsafe import Markup\n"
            "def view():\n"
            "    name = request.args.get('name')\n"
            "    return Markup(name)\n"
        )
        findings = AST.analyze("views.py", code)
        highs = [f for f in findings if f.rule_id == "AST-XSS-001" and f.severity == "HIGH"]
        assert highs, "Markup(tainted) must fire HIGH"

    def test_markup_literal_not_flagged(self):
        code = "from markupsafe import Markup\nresult = Markup('<b>safe</b>')\n"
        findings = AST.analyze("views.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-XSS-001" not in rule_ids, "Markup(literal) must NOT be flagged"

    def test_mark_safe_tainted_flagged(self):
        code = (
            "from django.utils.safestring import mark_safe\n"
            "from django.http import HttpRequest\n"
            "def view(request):\n"
            "    name = request.GET['name']\n"
            "    return mark_safe(name)\n"
        )
        findings = AST.analyze("views.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-XSS-001" in rule_ids, "mark_safe(tainted) must be flagged"


class TestInterproceduralTaint:
    """Fixed-point iteration in _find_taint_source_funcs resolves transitive chains."""

    def test_single_hop_inherent_source(self):
        code = """
from flask import request
import os

def get_user():
    return request.args.get('user')

def handler():
    u = get_user()
    os.system(u)
"""
        findings = AST.analyze("t.py", code, "")
        cmds = [f for f in findings if f.rule_id == "AST-CMD-001"]
        assert cmds, "single-hop taint source not detected"
        assert cmds[0].severity.value == "HIGH"

    def test_two_hop_transitive_chain(self):
        code = """
from flask import request
import os

def get_raw():
    return request.args.get('q')

def wrap():
    v = get_raw()
    return v

def handler():
    u = wrap()
    os.system(u)
"""
        findings = AST.analyze("t.py", code, "")
        cmds = [f for f in findings if f.rule_id == "AST-CMD-001"]
        assert cmds, "2-hop transitive taint chain not detected"
        assert cmds[0].severity.value == "HIGH"

    def test_self_method_inherent_taint_source(self):
        # Phase 3a: self.method() where method is in _interprocedural_taint_sources
        code = """
import os
from flask import request

class View:
    def _get_param(self):
        return request.args.get('p')

    def handle(self):
        p = self._get_param()
        os.system(p)
"""
        findings = AST.analyze("t.py", code, "")
        cmds = [f for f in findings if f.rule_id == "AST-CMD-001"]
        assert cmds, "Phase 3a: self.method() taint source not detected"
        assert cmds[0].severity.value == "HIGH"

    def test_self_method_arg_passthrough(self):
        # Phase 3b: self.method(tainted_arg) where method passes arg to return
        code = """
import os
from flask import request

class Proc:
    def _wrap(self, x):
        return x

    def run(self):
        val = request.form.get('cmd')
        result = self._wrap(val)
        os.system(result)
"""
        findings = AST.analyze("t.py", code, "")
        cmds = [f for f in findings if f.rule_id == "AST-CMD-001"]
        assert cmds, "Phase 3b: self.method(tainted_arg) passthrough not detected"
        assert cmds[0].severity.value == "HIGH"

    def test_clean_return_not_promoted_to_tainted(self):
        # get_const() returns a literal — must NOT be promoted to a taint source.
        # os.system(UNKNOWN) still fires HIGH by design, but taint_status must be 'unknown',
        # not 'tainted'. This verifies the fixed-point does not incorrectly expand sources.
        code = """
import os

def get_const():
    return "safe_value"

def handler():
    v = get_const()
    os.system(v)
"""
        findings = AST.analyze("t.py", code, "")
        tainted_cmds = [f for f in findings if f.rule_id == "AST-CMD-001" and f.taint_status == "tainted"]
        assert not tainted_cmds, "constant-return function must not be promoted to TAINTED taint source"
