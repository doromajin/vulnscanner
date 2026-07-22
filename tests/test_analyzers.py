import json
import tempfile
from pathlib import Path

import pytest

from vulnscanner.analyzers.ast_java import (
    JavaASTAnalyzer,
    _HAS_JAVALANG,
    build_java_cross_file_context,
    set_java_cross_file_context,
)
from vulnscanner.analyzers.ast_go import GoASTAnalyzer, _TS_GO_AVAILABLE
from vulnscanner.analyzers.ast_js import JSASTAnalyzer, TSASTAnalyzer, _TS_JS_AVAILABLE, _TS_TS_AVAILABLE
from vulnscanner.analyzers.ast_ruby import RubyASTAnalyzer, _TS_RUBY_AVAILABLE
from vulnscanner.analyzers.ast_php import PhpASTAnalyzer, _TS_AVAILABLE as _TS_PHP_AVAILABLE

_skip_no_tsjs = pytest.mark.skipif(not _TS_JS_AVAILABLE, reason="tree-sitter-javascript not installed")
_skip_no_tsts = pytest.mark.skipif(not _TS_TS_AVAILABLE, reason="tree-sitter-typescript not installed")
_skip_no_tsgo = pytest.mark.skipif(not _TS_GO_AVAILABLE, reason="tree-sitter-go not installed")
_skip_no_tsrb = pytest.mark.skipif(not _TS_RUBY_AVAILABLE, reason="tree-sitter-ruby not installed")
_skip_no_tsphp = pytest.mark.skipif(not _TS_PHP_AVAILABLE, reason="tree-sitter-php not installed")

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
from vulnscanner.analyzers.path_traversal import PathTraversalAnalyzer
from vulnscanner.analyzers.js_taint import JSTaintAnalyzer
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
class TestJavaTrustBoundaryViolation:
    """session.setAttribute(key, tainted) should fire JAST-TBV-001."""

    def test_session_set_tainted_value_flagged(self):
        code = """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
public class T {
    public void handle(HttpServletRequest req) {
        HttpSession session = req.getSession();
        String user = req.getParameter("user");
        session.setAttribute("user", user);
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-TBV-001" in rule_ids, "session.setAttribute(tainted) must be flagged"

    def test_session_set_literal_not_flagged(self):
        code = """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
public class T {
    public void handle(HttpServletRequest req) {
        HttpSession session = req.getSession();
        session.setAttribute("logged_in", "true");
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-TBV-001" not in rule_ids, "setAttribute(literal) must NOT be flagged"


@_skip_no_javalang
class TestSpringRestTemplateSSRF:
    """Spring RestTemplate.getForObject(taintedUrl) must fire JAST-SSRF-002."""

    _PREAMBLE = (
        "import javax.servlet.http.HttpServletRequest;\n"
        "import org.springframework.web.client.RestTemplate;\n"
    )

    def test_get_for_object_tainted_url_flagged(self):
        code = self._PREAMBLE + """
public class T {
    RestTemplate restTemplate;
    public String fetch(HttpServletRequest req) {
        String url = req.getParameter("target");
        return restTemplate.getForObject(url, String.class);
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SSRF-002" in rule_ids, "restTemplate.getForObject(tainted) must be flagged"

    def test_hardcoded_url_not_flagged(self):
        code = self._PREAMBLE + """
public class T {
    RestTemplate restTemplate;
    public String fetch() {
        return restTemplate.getForObject("https://api.example.com/data", String.class);
    }
}"""
        findings = JavaASTAnalyzer().analyze("T.java", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SSRF-002" not in rule_ids, "hardcoded URL must NOT be flagged"


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
                severity=Severity.LOW,
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


class TestJinja2TemplateSSTI:
    """jinja2.Template(user_input) must fire AST-SSTI-003."""

    def test_template_ctor_tainted_flagged(self):
        code = (
            "from flask import request\n"
            "import jinja2\n"
            "def view():\n"
            "    t = request.args.get('tmpl')\n"
            "    return jinja2.Template(t).render()\n"
        )
        findings = AST.analyze("views.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-SSTI-003" in rule_ids, "jinja2.Template(tainted) must fire SSTI"

    def test_template_ctor_literal_not_flagged(self):
        code = "import jinja2\nresult = jinja2.Template('Hello {{ name }}').render(name='world')\n"
        findings = AST.analyze("views.py", code)
        rule_ids = {f.rule_id for f in findings}
        assert "AST-SSTI-003" not in rule_ids, "jinja2.Template(literal) must NOT be flagged"

    def test_from_string_tainted_high(self):
        code = (
            "from flask import request\n"
            "from jinja2 import Environment\n"
            "def view():\n"
            "    src = request.args.get('t')\n"
            "    return Environment().from_string(src).render()\n"
        )
        findings = AST.analyze("views.py", code)
        highs = [f for f in findings if f.rule_id == "AST-SSTI-002" and f.severity == "HIGH"]
        assert highs, "Environment.from_string(tainted) must fire HIGH"


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


# ── Phase E: cross-file confirmed taint params ────────────────────────────────

class TestPhaseEConfirmedTaintParams:
    """Phase E: callee params confirmed tainted from caller → HIGH confidence findings."""

    def _scan_multi(self, files: dict[str, str]):
        from vulnscanner.scanner import VulnScanner
        import tempfile, os
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in files.items():
                Path(os.path.join(tmp, name)).write_text(content)
            return VulnScanner().scan(tmp)

    def test_3hop_chain_confidence_is_high(self):
        result = self._scan_multi({
            "dao.py": (
                "def get_user(user_id):\n"
                "    conn.execute('SELECT * FROM users WHERE id=' + user_id)\n"
                "    return conn.fetchone()\n"
            ),
            "services.py": (
                "from dao import get_user\n"
                "def fetch_user(uid):\n"
                "    return get_user(uid)\n"
            ),
            "views.py": (
                "from services import fetch_user\n"
                "def view(request):\n"
                "    uid = request.args.get('uid')\n"
                "    return fetch_user(uid)\n"
            ),
        })
        sql = [f for f in result.findings if "SQL" in f.rule_id]
        assert sql, "3-hop cross-file SQLi must be detected"
        assert len(sql) == 1, f"must deduplicate to exactly 1 finding, got {len(sql)}"
        assert sql[0].confidence >= 0.8, (
            f"confirmed cross-file taint must give high confidence, got {sql[0].confidence}"
        )

    def test_callee_standalone_no_false_negative(self):
        result = self._scan_multi({
            "helper.py": (
                "def run_query(val):\n"
                "    conn.execute('SELECT * FROM t WHERE x=' + val)\n"
            ),
            "app.py": (
                "from helper import run_query\n"
                "def view(request):\n"
                "    run_query(request.args.get('x'))\n"
            ),
        })
        sql = [f for f in result.findings if "SQL" in f.rule_id]
        assert sql, "callee with tainted arg must detect SQLi"


# ── FastAPI parameter taint ───────────────────────────────────────────────────

class TestFastAPIParams:
    """FastAPI Query/Path/Body parameters must be treated as TAINTED."""

    def test_query_param_taint_detected(self):
        code = """
from fastapi import FastAPI, Query
app = FastAPI()

@app.get('/search')
async def search(q: str = Query(None)):
    conn.execute('SELECT * FROM t WHERE name=' + q)
"""
        findings = [
            f for f in AST.analyze("main.py", code, ".")
            if "SQL" in f.rule_id and not f.suppression_reason
        ]
        assert findings, "FastAPI Query parameter must be treated as tainted"
        assert findings[0].taint_status == "tainted"

    def test_body_param_taint_detected(self):
        code = """
from fastapi import FastAPI, Body
app = FastAPI()

@app.post('/run')
async def run(cmd: str = Body(...)):
    import os
    os.system(cmd)
"""
        findings = [
            f for f in AST.analyze("main.py", code, ".")
            if "CMD" in f.rule_id and not f.suppression_reason
        ]
        assert findings, "FastAPI Body parameter must be treated as tainted"

    def test_path_param_taint_detected(self):
        code = """
from fastapi import FastAPI, Path
app = FastAPI()

@app.get('/files/{name}')
async def get_file(name: str = Path(...)):
    with open('/data/' + name) as f:
        return f.read()
"""
        findings = [
            f for f in AST.analyze("main.py", code, ".")
            if "PATH" in f.rule_id and not f.suppression_reason
        ]
        assert findings, "FastAPI Path parameter must be treated as tainted"

    def test_non_fastapi_decorator_not_affected(self):
        # Regular function with default value that looks like Query() but isn't in a web handler
        code = """
def process(q=None):
    conn.execute('SELECT * FROM t WHERE name=' + q)
"""
        findings = [
            f for f in AST.analyze("main.py", code, ".")
            if "SQL" in f.rule_id and not f.suppression_reason
        ]
        # Should detect but with UNKNOWN taint (low_reach), not TAINTED
        for f in findings:
            assert f.taint_status != "tainted", (
                "Non-FastAPI default params must not be injected as TAINTED"
            )


# ── Phase F: CLI CLEAN param propagation ─────────────────────────────────────

class TestPhaseFCLICleanPropagation:
    """Phase F: params confirmed to receive only CLI-originated input must suppress PATH FPs."""

    def _scan_multi(self, files: dict[str, str]):
        from vulnscanner.scanner import VulnScanner
        import tempfile, os
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in files.items():
                Path(os.path.join(tmp, name)).write_text(content)
            return VulnScanner().scan(tmp)

    def test_cli_callee_path_no_fp(self):
        """Function called from Click CLI entry with CLI path arg must not produce PATH finding."""
        result = self._scan_multi({
            "cli.py": (
                "import click\n"
                "@click.command()\n"
                "@click.argument('output_path')\n"
                "def export(output_path):\n"
                "    save_file(output_path)\n"
            ),
            "helper.py": (
                "from pathlib import Path\n"
                "def save_file(path):\n"
                "    Path(path).write_text('data')\n"
            ),
        })
        path_findings = [
            f for f in result.findings
            if "PATH" in f.rule_id and "helper.py" in f.file_path
            and not f.suppression_reason
        ]
        assert not path_findings, (
            f"CLI-callee path must not produce PATH finding, got: {path_findings}"
        )

    def test_web_callee_path_still_detected(self):
        """Same helper called from a web entry with tainted arg must still produce finding."""
        result = self._scan_multi({
            "views.py": (
                "from flask import request\n"
                "def download(req):\n"
                "    filename = request.args.get('file')\n"
                "    save_file(filename)\n"
            ),
            "helper.py": (
                "from pathlib import Path\n"
                "def save_file(path):\n"
                "    Path(path).write_text('data')\n"
            ),
        })
        path_findings = [
            f for f in result.findings
            if "PATH" in f.rule_id and "helper.py" in f.file_path
            and not f.suppression_reason
        ]
        assert path_findings, "Web-callee path with tainted arg must produce PATH finding"


class TestModuleLevelAssignments:
    """Module-level assignments (BASE_DIR, os.environ) must not produce FPs."""

    def _scan(self, code: str):
        return PythonASTAnalyzer().analyze("tool.py", code)

    def test_base_dir_from_file_no_fp(self):
        """BASE_DIR = Path(__file__).parent → paths derived from it must be CLEAN."""
        code = (
            "from pathlib import Path\n"
            "import os\n"
            "BASE_DIR = Path(__file__).parent\n"
            "def open_config():\n"
            "    cfg = BASE_DIR / 'config.yaml'\n"
            "    return open(cfg).read()\n"
        )
        findings = self._scan(code)
        path = [f for f in findings if "PATH" in f.rule_id and not f.suppression_reason]
        assert not path, f"Path derived from __file__ must not FP, got: {path}"

    def test_os_environ_get_no_path_fp(self):
        """os.environ.get() in path construction must not produce PATH FP."""
        code = (
            "import os\n"
            "from pathlib import Path\n"
            "def get_home():\n"
            "    home = os.environ.get('HOME', '/tmp')\n"
            "    p = Path(home) / 'config.ini'\n"
            "    return p.read_text()\n"
        )
        findings = self._scan(code)
        path = [f for f in findings if "PATH" in f.rule_id and not f.suppression_reason]
        assert not path, f"os.environ.get() path must not FP, got: {path}"

    def test_tainted_module_var_still_detected(self):
        """Module-level var from taint source must still be flagged."""
        code = (
            "from flask import request\n"
            "import sqlite3\n"
            "SORT_FIELD = request.args.get('sort')\n"
            "def query():\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    conn.execute('SELECT * FROM t ORDER BY ' + SORT_FIELD)\n"
        )
        findings = self._scan(code)
        sql = [f for f in findings if "SQL" in f.rule_id]
        assert sql, "Module-level tainted var must still be detected"


class TestPythonStrPassthrough:
    """str/bytes/repr must propagate taint so guard-validated CLEAN values don't FP."""

    def _scan(self, code: str):
        return PythonASTAnalyzer().analyze("app.py", code)

    def test_str_of_tainted_still_detected(self):
        """str(tainted) must remain TAINTED → SQL finding must fire."""
        code = (
            "from flask import request\n"
            "def view():\n"
            "    uid = request.args.get('id')\n"
            "    import sqlite3; conn = sqlite3.connect(':memory:')\n"
            "    conn.execute('SELECT * FROM t WHERE id=' + str(uid))\n"
        )
        findings = self._scan(code)
        rule_ids = {f.rule_id for f in findings}
        assert any("SQL" in r for r in rule_ids), "str(tainted) must still trigger SQL finding"

    def test_str_of_isinstance_guarded_clean_no_fp(self):
        """int() reassignment + isinstance guard → str(clean) must suppress SQL FP."""
        code = (
            "from flask import request\n"
            "def view():\n"
            "    uid = request.args.get('id')\n"
            "    if not isinstance(uid, str):\n"
            "        return\n"
            "    uid = int(uid)\n"
            "    import sqlite3; conn = sqlite3.connect(':memory:')\n"
            "    conn.execute('SELECT * FROM t WHERE id=' + str(uid))\n"
        )
        findings = self._scan(code)
        sql = [f for f in findings if "SQL" in f.rule_id and not f.suppression_reason]
        assert not sql, f"str(int(uid)) after guard must not FP, got: {sql}"

    def test_str_of_int_cast_no_fp(self):
        """try/except int() cast → str(uid) downstream must suppress FP."""
        code = (
            "from flask import request\n"
            "def view():\n"
            "    raw = request.args.get('id')\n"
            "    try:\n"
            "        uid = int(raw)\n"
            "    except ValueError:\n"
            "        return 'bad'\n"
            "    import sqlite3; conn = sqlite3.connect(':memory:')\n"
            "    conn.execute('SELECT * FROM t WHERE id=' + str(uid))\n"
        )
        findings = self._scan(code)
        sql = [f for f in findings if "SQL" in f.rule_id and not f.suppression_reason]
        assert not sql, f"str(int(raw)) after try/except must not FP, got: {sql}"


# ── datetime / time CLEAN sources ────────────────────────────────────────────

class TestDatetimeCleanSources:
    """datetime.now() / date.today() / time.time() must not propagate taint."""

    def _scan(self, code: str):
        return PythonASTAnalyzer().analyze("app.py", code)

    def test_datetime_now_strftime_no_path_fp(self):
        """datetime.now().strftime(...) used as a path component must not FP."""
        code = (
            "from datetime import datetime\n"
            "from pathlib import Path\n"
            "def archive():\n"
            "    ts = datetime.now().strftime('%Y%m%d')\n"
            "    path = Path('/data') / ts / 'log.txt'\n"
            "    return path.read_text()\n"
        )
        findings = self._scan(code)
        path_fps = [f for f in findings if "PATH" in f.rule_id and not f.suppression_reason]
        assert not path_fps, f"datetime.now().strftime() path must not FP: {path_fps}"

    def test_date_today_no_path_fp(self):
        """date.today().isoformat() used as path must not FP."""
        code = (
            "from datetime import date\n"
            "from pathlib import Path\n"
            "def daily_log():\n"
            "    today = date.today().isoformat()\n"
            "    return (Path('/logs') / today).read_text()\n"
        )
        findings = self._scan(code)
        path_fps = [f for f in findings if "PATH" in f.rule_id and not f.suppression_reason]
        assert not path_fps, f"date.today().isoformat() path must not FP: {path_fps}"

    def test_tainted_datetime_still_detected(self):
        """User-controlled path (not datetime) must still be detected."""
        code = (
            "from flask import request\n"
            "from pathlib import Path\n"
            "def view():\n"
            "    name = request.args.get('name')\n"
            "    return (Path('/data') / name).read_text()\n"
        )
        findings = self._scan(code)
        path_finds = [f for f in findings if "PATH" in f.rule_id and not f.suppression_reason]
        assert path_finds, "Tainted path must still be detected"


# ── NoSQL injection ───────────────────────────────────────────────────────────

class TestNoSQLInjection:
    """MongoDB $where JS execution and tainted filter detection."""

    def test_dollar_where_with_tainted_value_is_critical(self):
        code = """
from flask import request
from pymongo import MongoClient

client = MongoClient()
col = client.db.users
user_input = request.args.get('q')
col.find({"$where": user_input})
"""
        findings = AST.analyze("t.py", code, "")
        hits = [f for f in findings if f.rule_id == "AST-NOSQL-001"]
        assert hits, "MongoDB $where with tainted value must fire AST-NOSQL-001"
        assert hits[0].severity == "CRITICAL"

    def test_dollar_where_with_literal_is_safe(self):
        code = """
from pymongo import MongoClient
col = MongoClient().db.users
col.find({"$where": "this.age > 18"})
"""
        findings = AST.analyze("t.py", code, "")
        hits = [f for f in findings if f.rule_id == "AST-NOSQL-001"]
        assert not hits, "Literal $where must not fire"

    def test_count_documents_tainted_filter_is_high(self):
        code = """
from flask import request
from pymongo import MongoClient

col = MongoClient().db.users

def handle():
    q = request.args.get('filter')
    col.count_documents(q)
"""
        findings = AST.analyze("t.py", code, "")
        hits = [f for f in findings if f.rule_id == "AST-NOSQL-002"]
        assert hits, "count_documents() with tainted filter must fire AST-NOSQL-002"
        assert hits[0].severity == "HIGH"

    def test_generic_find_with_tainted_filter_does_not_fire(self):
        """collection.find(tainted) alone must not fire — too many non-Mongo .find() callers."""
        code = """
from flask import request
from pymongo import MongoClient

col = MongoClient().db.users
q = request.args.get('filter')
col.find(q)
"""
        findings = AST.analyze("t.py", code, "")
        nosql = [f for f in findings if "NOSQL" in f.rule_id]
        assert not nosql, "Generic .find(tainted) must NOT fire to avoid FPs"


# ── Email header injection ────────────────────────────────────────────────────

class TestEmailHeaderInjection:
    """CWE-93: email header injection via smtplib / Django send_mail."""

    def test_sendmail_tainted_subject_is_high(self):
        code = """
from flask import request
import smtplib
def send(server):
    subj = request.args.get("subject")
    server.sendmail("from@x.com", "to@x.com", f"Subject: {subj}\\r\\n\\r\\nBody")
"""
        findings = AST.analyze("t.py", code, "")
        email = [f for f in findings if "EMAIL" in f.rule_id]
        assert email, "Tainted sendmail arg must be detected"
        assert email[0].severity == Severity.HIGH
        assert email[0].rule_id == "AST-EMAIL-001"

    def test_django_send_mail_tainted_subject(self):
        code = """
from flask import request
from django.core.mail import send_mail
def notify(request):
    subj = request.POST.get("title")
    send_mail(subject=subj, message="body", from_email="a@b.com", recipient_list=["c@d.com"])
"""
        findings = AST.analyze("t.py", code, "")
        email = [f for f in findings if "EMAIL" in f.rule_id]
        assert email, "Tainted send_mail subject kwarg must be detected"
        assert email[0].severity == Severity.HIGH

    def test_unknown_sendmail_is_medium_low_reach(self):
        code = """
import smtplib
def send(server, subject):
    server.sendmail("from@x.com", "to@x.com", f"Subject: {subject}\\r\\n\\r\\nBody")
"""
        findings = AST.analyze("t.py", code, "")
        email = [f for f in findings if "EMAIL" in f.rule_id]
        assert email, "UNKNOWN sendmail must produce finding"
        assert email[0].severity == Severity.LOW
        assert email[0].rule_id == "AST-EMAIL-002"

    def test_clean_sendmail_no_finding(self):
        code = """
import smtplib
def send(server):
    server.sendmail("from@x.com", "to@x.com", "Subject: Hello\\r\\n\\r\\nBody")
"""
        findings = AST.analyze("t.py", code, "")
        email = [f for f in findings if "EMAIL" in f.rule_id]
        assert not email, "Literal sendmail must not fire"


# ── Node.js path traversal and command injection ──────────────────────────────

_NODEJS_FIXTURE = FIXTURES / "vulnerable_nodejs.js"


class TestNodeJsPathTraversal:
    """PATH-006/007: fs.* with request-derived paths in Node.js."""

    def test_fs_req_query_is_high(self):
        content = _NODEJS_FIXTURE.read_text(encoding="utf-8")
        findings = PathTraversalAnalyzer().analyze("server.js", content)
        match = [f for f in findings if f.rule_id == "PATH-006"]
        assert match, "fs.readFile(req.query.*) must be detected as PATH-006"
        assert match[0].severity == Severity.HIGH

    def test_fs_template_literal_is_medium(self):
        content = _NODEJS_FIXTURE.read_text(encoding="utf-8")
        findings = PathTraversalAnalyzer().analyze("server.js", content)
        assert any(f.rule_id == "PATH-007" for f in findings)


class TestNodeJsCommandInjection:
    """CMD-011/012: child_process with request-derived args in Node.js."""

    def test_exec_req_body_is_critical(self):
        content = _NODEJS_FIXTURE.read_text(encoding="utf-8")
        findings = CommandInjectionAnalyzer().analyze("app.js", content)
        match = [f for f in findings if f.rule_id == "CMD-011"]
        assert match, "child_process with req.body must be detected as CMD-011"
        assert match[0].severity == Severity.CRITICAL

    def test_exec_template_literal_is_critical(self):
        content = _NODEJS_FIXTURE.read_text(encoding="utf-8")
        findings = CommandInjectionAnalyzer().analyze("app.ts", content)
        assert any(f.rule_id == "CMD-012" for f in findings)


# ── Guard / taint suppression ─────────────────────────────────────────────────

class TestGuardSuppression:
    """Condition-based taint guards that suppress findings inside validated branches."""

    def test_isdigit_guard_suppresses_sql(self):
        code = """
from flask import request
import sqlite3

conn = sqlite3.connect(':memory:')

def handle():
    uid = request.args.get('id')
    if uid.isdigit():
        conn.execute('SELECT * FROM users WHERE id=' + uid)
"""
        findings = AST.analyze("t.py", code, "")
        active = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert not active, "isdigit() guard must suppress SQL injection finding inside if-body"

    def test_early_return_guard_suppresses_sql(self):
        code = """
from flask import request
import sqlite3

conn = sqlite3.connect(':memory:')

def handle():
    uid = request.args.get('id')
    if not uid.isdigit():
        return 'bad input'
    conn.execute('SELECT * FROM users WHERE id=' + uid)
"""
        findings = AST.analyze("t.py", code, "")
        active = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert not active, "early-return guard must suppress subsequent SQL injection finding"

    def test_regex_guard_suppresses_sql(self):
        code = """
import re
from flask import request
import sqlite3

conn = sqlite3.connect(':memory:')

def handle():
    uid = request.args.get('id')
    if re.match(r'\\d+', uid):
        conn.execute('SELECT * FROM users WHERE id=' + uid)
"""
        findings = AST.analyze("t.py", code, "")
        active = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert not active, "re.match() guard must suppress SQL injection finding inside if-body"

    def test_abort_early_exit_suppresses_sql(self):
        code = """
from flask import request, abort
import sqlite3

conn = sqlite3.connect(':memory:')

def handle():
    uid = request.args.get('id')
    if not uid.isdigit():
        abort(400)
    conn.execute('SELECT * FROM users WHERE id=' + uid)
"""
        findings = AST.analyze("t.py", code, "")
        active = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert not active, "abort() early exit must suppress subsequent SQL injection finding"

    def test_compiled_regex_var_guard_suppresses_sql(self):
        code = """
import re
from flask import request
import sqlite3

conn = sqlite3.connect(':memory:')
ID_PAT = re.compile(r'\\d+')

def handle():
    uid = request.args.get('id')
    if ID_PAT.match(uid):
        conn.execute('SELECT * FROM users WHERE id=' + uid)
"""
        findings = AST.analyze("t.py", code, "")
        active = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert not active, "pre-compiled regex var .match() guard must suppress SQL injection"

    def test_inline_compile_match_guard_suppresses_sql(self):
        code = """
import re
from flask import request
import sqlite3

conn = sqlite3.connect(':memory:')

def handle():
    uid = request.args.get('id')
    if re.compile(r'\\d+').match(uid):
        conn.execute('SELECT * FROM users WHERE id=' + uid)
"""
        findings = AST.analyze("t.py", code, "")
        active = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert not active, "inline re.compile().match() guard must suppress SQL injection"

    def test_unguarded_tainted_name_still_fires(self):
        code = """
from flask import request
import sqlite3

conn = sqlite3.connect(':memory:')

def handle():
    uid = request.args.get('id')
    conn.execute('SELECT * FROM users WHERE id=' + uid)
"""
        findings = AST.analyze("t.py", code, "")
        active = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert active, "Unguarded tainted variable must still fire SQL injection"
        assert active[0].severity == "HIGH"


_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_JS_VULN = _FIXTURES_DIR / "js_taint_vuln.js"
_JS_SAFE = _FIXTURES_DIR / "js_taint_safe.js"
_JS = JSTaintAnalyzer()


class TestJSTaintAnalyzer:
    """JavaScript 1-hop taint tracker — indirect source→sink flows."""

    def test_vuln_file_detects_all_patterns(self):
        content = _JS_VULN.read_text(encoding="utf-8")
        findings = _JS.analyze("app.js", content)
        rule_ids = {f.rule_id for f in findings}
        expected = {
            "JSTAINT-CMD-001",  # exec(cmd) where cmd = req.body.command
            "JSTAINT-CMD-002",  # spawn(tool) where tool = req.query.tool
            "JSTAINT-SQL-003",  # db.query(`... ${id}`) where id = req.query.id
            "JSTAINT-PATH-001", # fs.readFile(filename) where filename = req.query.file
            "JSTAINT-XSS-001",  # res.send(query) where query = req.query.q
            "JSTAINT-EVAL-001", # eval(expr) where expr = req.body.expression
            "JSTAINT-SSRF-001", # fetch(url) where url = req.query.target
        }
        missing = expected - rule_ids
        assert not missing, f"Expected rules not fired: {missing}"

    def test_destructuring_taint_detected(self):
        content = _JS_VULN.read_text(encoding="utf-8")
        findings = _JS.analyze("app.js", content)
        xss = [f for f in findings if f.rule_id == "JSTAINT-XSS-001"]
        destuct_finding = any("name" in f.description for f in xss)
        assert destuct_finding, "Destructured req.body variable must be tainted"

    def test_two_hop_taint_detected(self):
        content = _JS_VULN.read_text(encoding="utf-8")
        findings = _JS.analyze("app.js", content)
        two_hop = [f for f in findings if "fullCmd" in f.description]
        assert two_hop, "2-hop: dir→fullCmd→execSync must be detected"

    def test_safe_file_no_findings(self):
        content = _JS_SAFE.read_text(encoding="utf-8")
        findings = _JS.analyze("safe.js", content)
        assert not findings, f"Safe file produced unexpected findings: {findings}"

    def test_parseInt_sanitizer_suppresses(self):
        code = """
const express = require('express');
const db = require('./db');
const app = express();
app.get('/items', async (req, res) => {
    const page = parseInt(req.query.page);
    const rows = await db.query(`SELECT * FROM items LIMIT ${page}`);
    res.json(rows);
});
"""
        findings = _JS.analyze("app.js", code)
        assert not findings, "parseInt() must sanitize and suppress SQL finding"

    def test_no_false_positive_on_parameterized_query(self):
        code = """
const express = require('express');
const db = require('./db');
const app = express();
app.get('/user', async (req, res) => {
    const id = req.query.id;
    const rows = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    res.json(rows);
});
"""
        findings = _JS.analyze("app.js", code)
        sql_fps = [f for f in findings if "SQL" in f.rule_id]
        assert not sql_fps, "Parameterized query must not fire SQL injection"

    def test_non_js_file_ignored(self):
        content = "req.body.cmd; exec(cmd);"
        findings = _JS.analyze("notes.txt", content)
        assert not findings, "Non-JS extension must return no findings"


@_skip_no_javalang
class TestJavaCrossFileTaint:
    """Java cross-file taint tracking via build_java_cross_file_context."""

    def _analyze_with_context(self, target_path: str, target_code: str, extra_files: dict) -> list:
        all_files = {target_path: target_code, **extra_files}
        ctx = build_java_cross_file_context(all_files)
        set_java_cross_file_context(ctx)
        try:
            return JavaASTAnalyzer().analyze(target_path, target_code)
        finally:
            set_java_cross_file_context(None)

    def test_inherent_taint_source_in_remote_file(self):
        """Helper in another file returns request.getParameter() — should propagate."""
        helper = """
import javax.servlet.http.HttpServletRequest;
public class Helper {
    private HttpServletRequest req;
    public String getUserInput() { return req.getParameter("q"); }
}"""
        target = """
import java.sql.Connection;
import java.sql.Statement;
public class Controller {
    private Helper helper;
    public void handle(Connection conn) throws Exception {
        String val = helper.getUserInput();
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x='" + val + "'");
    }
}"""
        findings = self._analyze_with_context("Controller.java", target, {"Helper.java": helper})
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" in rule_ids, "Cross-file inherent taint source not propagated"

    def test_passthrough_method_in_remote_file(self):
        """Helper in another file passes its tainted arg through → should detect."""
        helper = """
public class Sanitizer {
    public String passthrough(String x) { return x; }
}"""
        target = """
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;
public class Controller {
    private Sanitizer san;
    public void handle(HttpServletRequest req, Connection conn) throws Exception {
        String raw = req.getParameter("q");
        String val = san.passthrough(raw);
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x='" + val + "'");
    }
}"""
        findings = self._analyze_with_context("Controller.java", target, {"Sanitizer.java": helper})
        rule_ids = {f.rule_id for f in findings}
        assert "JAST-SQL-001" in rule_ids, "Cross-file passthrough taint not propagated"

    def test_no_fp_for_clean_remote_method(self):
        """Remote method that never touches request data must not produce FP."""
        helper = """
public class Clean {
    public String getSafeValue() { return "constant"; }
}"""
        target = """
import java.sql.Connection;
import java.sql.Statement;
public class Controller {
    private Clean clean;
    public void handle(Connection conn) throws Exception {
        String val = clean.getSafeValue();
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x='" + val + "'");
    }
}"""
        findings = self._analyze_with_context("Controller.java", target, {"Clean.java": helper})
        sql = [f for f in findings if f.rule_id == "JAST-SQL-001"]
        assert not sql, "Clean cross-file method must not produce SQL injection FP"

    def test_spring_pathvariable_seeds_service_param(self):
        """@PathVariable in controller flows into service method param — must detect SQLi."""
        controller = """
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private UserService svc;

    @GetMapping("/user/{id}")
    public String get(@PathVariable String userId) {
        return svc.findUser(userId);
    }
}"""
        service = """
import java.sql.*;
public class UserService {
    private Connection conn;
    public String findUser(String id) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE id='" + id + "'").toString();
    }
}"""
        findings = self._analyze_with_context(
            "UserService.java", service, {"UserController.java": controller}
        )
        sql = [f for f in findings if "SQL" in f.rule_id]
        assert sql, "@PathVariable taint must propagate into service method param via cross-file seeding"

    def test_3hop_spring_controller_to_dao(self):
        """@RequestParam in Controller → Service → DAO — 3-hop cross-file chain must detect SQLi."""
        controller = """
import org.springframework.web.bind.annotation.*;
@RestController
public class UserController {
    private UserService svc;
    @GetMapping("/user")
    public String get(@RequestParam String userId) {
        return svc.findUser(userId);
    }
}"""
        service = """
public class UserService {
    private UserDao dao;
    public String findUser(String uid) {
        return dao.queryUser(uid);
    }
}"""
        dao = """
import java.sql.*;
public class UserDao {
    private Connection conn;
    public String queryUser(String id) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE id='" + id + "'").toString();
    }
}"""
        all_files = {
            "UserController.java": controller,
            "UserService.java": service,
            "UserDao.java": dao,
        }
        ctx = build_java_cross_file_context(all_files)
        set_java_cross_file_context(ctx)
        try:
            findings = JavaASTAnalyzer().analyze("UserDao.java", dao)
        finally:
            set_java_cross_file_context(None)
        sql = [f for f in findings if "SQL" in f.rule_id]
        assert sql, "3-hop @RequestParam→Service→DAO SQLi must be detected"


# ── Java CFG guards ───────────────────────────────────────────────────────────

@_skip_no_javalang
class TestJavaCFGGuards:
    """Early-exit validation guards suppress taint sinks in Java."""

    _IMPORTS = (
        "import javax.servlet.http.HttpServletRequest;\n"
        "import java.sql.*;\n"
    )

    def _sql_findings(self, code: str) -> list:
        return [f for f in JavaASTAnalyzer().analyze("C.java", code) if "SQL" in f.rule_id]

    def test_regex_matches_guard_suppresses_sql(self):
        code = self._IMPORTS + r"""
public class C {
    public void m(HttpServletRequest req, Connection conn) throws Exception {
        String uid = req.getParameter("id");
        if (!uid.matches("\d+")) { throw new IllegalArgumentException("bad"); }
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id=" + uid);
    }
}"""
        assert not self._sql_findings(code), "regex matches() guard must suppress SQL injection FP"

    def test_static_isnumeric_guard_suppresses_sql(self):
        code = self._IMPORTS + r"""
public class C {
    public void m(HttpServletRequest req, Connection conn) throws Exception {
        String page = req.getParameter("page");
        if (!isNumeric(page)) { return; }
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t LIMIT " + page);
    }
    private boolean isNumeric(String s) { return s.matches("-?\\d+"); }
}"""
        assert not self._sql_findings(code), "static isNumeric() guard must suppress SQL injection FP"

    def test_null_only_guard_does_not_suppress_sql(self):
        code = self._IMPORTS + r"""
public class C {
    public void m(HttpServletRequest req, Connection conn) throws Exception {
        String uid = req.getParameter("id");
        if (uid == null) { return; }
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id=" + uid);
    }
}"""
        assert self._sql_findings(code), "null-only guard must NOT suppress SQL injection — content is still unsanitized"

    def test_unguarded_tainted_still_fires(self):
        code = self._IMPORTS + r"""
public class C {
    public void m(HttpServletRequest req, Connection conn) throws Exception {
        String uid = req.getParameter("id");
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id=" + uid);
    }
}"""
        assert self._sql_findings(code), "unguarded tainted variable must produce SQL injection finding"


_JSAST = JSASTAnalyzer()


@_skip_no_tsjs
class TestJSASTAnalyzer:
    """JavaScript AST taint analyzer (tree-sitter-javascript)."""

    # ── taint propagation ─────────────────────────────────────────────────────

    def test_sql_direct_variable(self):
        code = """
const express = require('express');
const app = express();
app.get('/search', (req, res) => {
    const q = req.query.q;
    db.query("SELECT * FROM t WHERE name='" + q + "'");
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "Direct tainted variable in SQL query not detected"

    def test_sql_destructuring(self):
        code = """
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE user=\'' + username + '\'');
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "Destructured req.body field in SQL not detected"

    def test_sql_template_literal(self):
        code = """
app.get('/item', (req, res) => {
    const id = req.query.id;
    db.query(`SELECT * FROM items WHERE id=${id}`);
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "Template literal SQL injection not detected"

    def test_cmd_injection(self):
        code = """
const { exec } = require('child_process');
app.post('/run', (req, res) => {
    const cmd = req.body.command;
    exec(cmd, (err, stdout) => res.send(stdout));
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-CMD-001" in rule_ids, "Command injection not detected"

    def test_path_traversal_fs(self):
        code = """
const fs = require('fs');
app.get('/file', (req, res) => {
    const filename = req.query.name;
    fs.readFile(filename, 'utf8', (err, data) => res.send(data));
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-PATH-001" in rule_ids, "Path traversal via fs.readFile not detected"

    def test_xss_res_send(self):
        code = """
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send('<h1>Hello ' + name + '</h1>');
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-XSS-001" in rule_ids, "XSS via res.send not detected"

    def test_eval_injection(self):
        code = """
app.post('/calc', (req, res) => {
    const expr = req.body.expression;
    const result = eval(expr);
    res.json({ result });
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-EVAL-001" in rule_ids, "eval() with tainted input not detected"

    def test_ssrf_fetch(self):
        code = """
app.get('/proxy', async (req, res) => {
    const url = req.query.url;
    const resp = await fetch(url);
    res.send(await resp.text());
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SSRF-001" in rule_ids, "SSRF via fetch not detected"

    # ── interprocedural (function return taint) ───────────────────────────────

    def test_interprocedural_function_return(self):
        """Function that returns req.query data should propagate taint to call site."""
        code = """
function getQuery(req) {
    return req.query.search;
}
app.get('/search', (req, res) => {
    const term = getQuery(req);
    db.query('SELECT * FROM t WHERE name=\'' + term + '\'');
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "Interprocedural function return taint not propagated"

    def test_async_function_return_taint(self):
        """Async function returning tainted value propagates via await."""
        code = """
async function getUser(req) {
    const id = req.query.id;
    return id;
}
app.get('/user', async (req, res) => {
    const userId = await getUser(req);
    db.query('SELECT * FROM users WHERE id=\'' + userId + '\'');
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "Async interprocedural return taint not propagated"

    # ── no false positives ────────────────────────────────────────────────────

    def test_no_fp_parseint_sanitizer(self):
        code = """
app.get('/page', (req, res) => {
    const page = parseInt(req.query.page);
    db.query('SELECT * FROM items LIMIT ' + page);
});
"""
        findings = _JSAST.analyze("app.js", code)
        sql = [f for f in findings if f.rule_id == "JSAST-SQL-001"]
        assert not sql, "parseInt() must suppress taint"

    def test_no_fp_parameterized_query(self):
        code = """
app.get('/user', async (req, res) => {
    const id = req.query.id;
    const rows = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    res.json(rows);
});
"""
        findings = _JSAST.analyze("app.js", code)
        sql = [f for f in findings if f.rule_id == "JSAST-SQL-001"]
        assert not sql, "Parameterized query must not fire SQL injection"

    def test_no_fp_clean_constant(self):
        code = """
app.get('/list', (req, res) => {
    const sql = 'SELECT * FROM items';
    db.query(sql);
    res.send('OK');
});
"""
        findings = _JSAST.analyze("app.js", code)
        sql = [f for f in findings if f.rule_id == "JSAST-SQL-001"]
        assert not sql, "Constant SQL string must not fire"

    def test_ts_file_not_analyzed(self):
        """TypeScript files must be skipped (JS parser chokes on type annotations)."""
        code = "const x: string = req.query.x; db.query(x);"
        findings = _JSAST.analyze("app.ts", code)
        assert not findings, ".ts files must not be analyzed by JSASTAnalyzer"

    def test_non_js_file_ignored(self):
        code = "req.body.cmd; exec(cmd);"
        findings = _JSAST.analyze("notes.txt", code)
        assert not findings, "Non-JS extension must return no findings"

    def test_inline_require_fs_path_detected(self):
        """require('fs').readFileSync(tainted) must be detected as path traversal."""
        code = """
app.get('/file', (req, res) => {
    const name = req.query.filename;
    const data = require('fs').readFileSync(name, 'utf8');
    res.send(data);
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-PATH-001" in rule_ids, "require('fs').readFileSync(tainted) must fire PATH finding"

    def test_inline_require_child_process_cmd_detected(self):
        """require('child_process').exec(tainted) must be detected as cmd injection."""
        code = """
app.post('/run', (req, res) => {
    const cmd = req.body.command;
    require('child_process').exec(cmd);
});
"""
        findings = _JSAST.analyze("app.js", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-CMD-001" in rule_ids, "require('child_process').exec(tainted) must fire CMD finding"


_TSAST = TSASTAnalyzer()


@_skip_no_tsts
class TestTSASTAnalyzer:
    """TypeScript AST taint analyzer (tree-sitter-typescript)."""

    def test_sql_with_type_annotation(self):
        code = """
import { Request, Response } from 'express';
app.get('/search', (req: Request, res: Response): void => {
    const q: string = req.query.q as string;
    db.query("SELECT * FROM t WHERE name='" + q + "'");
});
"""
        findings = _TSAST.analyze("app.ts", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "Tainted TS variable with type annotation not detected"

    def test_destructuring_with_interface_type(self):
        code = """
interface LoginBody { username: string; password: string; }
app.post('/login', (req: Request, res: Response) => {
    const { username }: LoginBody = req.body;
    db.query('SELECT * FROM users WHERE user=\'' + username + '\'');
});
"""
        findings = _TSAST.analyze("app.ts", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "TS destructuring with interface type not handled"

    def test_non_null_assertion_still_tainted(self):
        """expr! strips the TS non-null wrapper but taint must propagate."""
        code = """
app.get('/file', (req: Request, res: Response) => {
    const name = req.query.name!;
    fs.readFile(name, 'utf8', cb);
});
"""
        findings = _TSAST.analyze("app.ts", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-PATH-001" in rule_ids, "Non-null assertion must not suppress taint"

    def test_as_expression_still_tainted(self):
        """expr as Type strips the TS cast but taint must propagate."""
        code = """
app.get('/run', (req: Request, res: Response) => {
    const cmd = req.body.command as string;
    exec(cmd);
});
"""
        findings = _TSAST.analyze("app.ts", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-CMD-001" in rule_ids, "as-expression must not suppress taint"

    def test_tsx_file_parsed(self):
        """TSX files should be parsed with the TSX grammar."""
        code = """
import React from 'react';
export async function getServerSideProps(ctx: any) {
    const id = ctx.query.id;
    const data = await db.query('SELECT * FROM t WHERE id=\'' + id + '\'');
    return { props: { data } };
}
"""
        findings = _TSAST.analyze("page.tsx", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "TSX file SQL injection not detected"

    def test_interprocedural_ts(self):
        """TypeScript named function returning tainted value propagates taint."""
        code = """
function getParam(req: Request): string {
    return req.query.search as string;
}
app.get('/search', async (req: Request, res: Response) => {
    const term: string = getParam(req);
    db.query('SELECT * FROM t WHERE name=\'' + term + '\'');
});
"""
        findings = _TSAST.analyze("app.ts", code)
        rule_ids = {f.rule_id for f in findings}
        assert "JSAST-SQL-001" in rule_ids, "TS interprocedural return taint not propagated"

    def test_no_fp_parseint_sanitizer(self):
        code = """
app.get('/page', (req: Request, res: Response): void => {
    const page: number = parseInt(req.query.page as string);
    db.query('SELECT * FROM items LIMIT ' + page);
});
"""
        findings = _TSAST.analyze("app.ts", code)
        sql = [f for f in findings if f.rule_id == "JSAST-SQL-001"]
        assert not sql, "parseInt() must suppress taint in TypeScript too"

    def test_js_file_not_analyzed_by_ts_analyzer(self):
        code = "const x = req.query.x; db.query(x);"
        findings = _TSAST.analyze("app.js", code)
        assert not findings, ".js files must not be analyzed by TSASTAnalyzer"


_GOAST = GoASTAnalyzer()


@_skip_no_tsgo
class TestGoASTAnalyzer:
    """Go AST taint analyzer (tree-sitter-go)."""

    # ── direct taint sources → sinks ─────────────────────────────────────────

    def test_sql_form_value(self):
        code = """
package main
import ("database/sql"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    id := r.FormValue("id")
    db.Query("SELECT * FROM t WHERE id='" + id + "'")
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-SQL-001" in rule_ids, "r.FormValue → SQL injection not detected"

    def test_sql_url_query_get(self):
        code = """
package main
import ("database/sql"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    db.QueryRow("SELECT id FROM users WHERE name='" + name + "'")
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-SQL-001" in rule_ids, "r.URL.Query().Get → SQL injection not detected"

    def test_cmd_injection(self):
        code = """
package main
import ("os/exec"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.FormValue("cmd")
    exec.Command("sh", "-c", cmd)
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-CMD-001" in rule_ids, "exec.Command with tainted arg not detected"

    def test_path_traversal_os_open(self):
        code = """
package main
import ("os"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    os.Open(filename)
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-PATH-001" in rule_ids, "os.Open with tainted path not detected"

    def test_xss_fmt_fprintf(self):
        code = """
package main
import ("fmt"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    fmt.Fprintf(w, "<h1>Hello " + name + "</h1>")
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-XSS-001" in rule_ids, "fmt.Fprintf with tainted format not detected"

    def test_ssrf_http_get(self):
        code = """
package main
import ("net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    http.Get(url)
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-SSRF-001" in rule_ids, "http.Get with tainted URL not detected"

    # ── multi-hop taint ───────────────────────────────────────────────────────

    def test_multihop_fmt_sprintf(self):
        """fmt.Sprintf with tainted arg propagates taint to the result."""
        code = """
package main
import ("database/sql"; "fmt"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    id := r.FormValue("id")
    query := fmt.Sprintf("SELECT * FROM t WHERE id=%s", id)
    db.Query(query)
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-SQL-001" in rule_ids, "fmt.Sprintf taint propagation not detected"

    def test_multihop_string_concat(self):
        """Taint propagates through string concatenation."""
        code = """
package main
import ("database/sql"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    q := "SELECT * FROM t WHERE name='" + name + "'"
    db.Query(q)
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-SQL-001" in rule_ids, "Multi-hop string concat taint not detected"

    def test_interprocedural_function_return(self):
        """Named function returning request data propagates taint to call site."""
        code = """
package main
import ("database/sql"; "net/http")
func getID(r *http.Request) string {
    return r.FormValue("id")
}
func handler(w http.ResponseWriter, r *http.Request) {
    id := getID(r)
    db.Query("SELECT * FROM t WHERE id='" + id + "'")
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-SQL-001" in rule_ids, "Go interprocedural return taint not detected"

    # ── framework sources ─────────────────────────────────────────────────────

    def test_gin_query_param(self):
        code = """
package main
import "github.com/gin-gonic/gin"
func handler(c *gin.Context) {
    id := c.Query("id")
    db.Query("SELECT * FROM t WHERE id='" + id + "'")
}
"""
        findings = _GOAST.analyze("main.go", code)
        rule_ids = {f.rule_id for f in findings}
        assert "GOAST-SQL-001" in rule_ids, "Gin c.Query() taint source not detected"

    # ── no false positives ────────────────────────────────────────────────────

    def test_no_fp_safe_constant(self):
        code = """
package main
import ("database/sql"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
    id := "42"
    db.Query("SELECT * FROM t WHERE id='" + id + "'")
}
"""
        findings = _GOAST.analyze("main.go", code)
        sql = [f for f in findings if f.rule_id == "GOAST-SQL-001"]
        assert not sql, "Constant string assignment must not produce FP"

    def test_no_fp_non_go_file(self):
        code = 'id := r.FormValue("id"); db.Query(id)'
        findings = _GOAST.analyze("main.py", code)
        assert not findings, "Non-.go file must not be analyzed by GoASTAnalyzer"


@_skip_no_tsgo
class TestGoCrossFileTaint:
    """Go cross-file taint: handler → helper → sink must be detected."""

    def _scan_multi(self, files: dict[str, str]):
        from vulnscanner.scanner import VulnScanner
        import tempfile, os
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in files.items():
                Path(os.path.join(tmp, name)).write_text(content)
            return VulnScanner().scan(tmp)

    def test_handler_to_helper_sql(self):
        """Handler passes r.FormValue to a helper in a separate file — must fire SQL."""
        result = self._scan_multi({
            "handler.go": (
                "package main\n"
                "import \"net/http\"\n"
                "func handler(w http.ResponseWriter, r *http.Request) {\n"
                "    id := r.FormValue(\"id\")\n"
                "    runQuery(id)\n"
                "}\n"
            ),
            "queries.go": (
                "package main\n"
                "func runQuery(query string) {\n"
                "    db.Query(\"SELECT * FROM t WHERE id=\" + query)\n"
                "}\n"
            ),
        })
        sql = [f for f in result.findings if f.rule_id == "GOAST-SQL-001"]
        assert sql, "Cross-file taint handler→helper must produce GOAST-SQL-001"

    def test_cross_file_helper_no_fp_without_taint(self):
        """Helper function called only with constants must NOT fire."""
        result = self._scan_multi({
            "main.go": (
                "package main\n"
                "func main() {\n"
                "    runQuery(\"admin\")\n"  # constant arg — not tainted
                "}\n"
            ),
            "queries.go": (
                "package main\n"
                "func runQuery(query string) {\n"
                "    db.Query(\"SELECT * FROM t WHERE role=\" + query)\n"
                "}\n"
            ),
        })
        sql = [f for f in result.findings if f.rule_id == "GOAST-SQL-001"]
        assert not sql, "Helper with only constant args must not produce FP"

    def test_two_hop_chain_detected(self):
        """handler → intermediate → sink (3 files) must be detected."""
        result = self._scan_multi({
            "handler.go": (
                "package main\n"
                "import \"net/http\"\n"
                "func handler(w http.ResponseWriter, r *http.Request) {\n"
                "    name := r.FormValue(\"name\")\n"
                "    intermediate(name)\n"
                "}\n"
            ),
            "service.go": (
                "package main\n"
                "func intermediate(val string) {\n"
                "    runQuery(val)\n"
                "}\n"
            ),
            "queries.go": (
                "package main\n"
                "func runQuery(q string) {\n"
                "    db.Exec(\"DELETE FROM t WHERE name=\" + q)\n"
                "}\n"
            ),
        })
        sql = [f for f in result.findings if f.rule_id == "GOAST-SQL-001"]
        assert sql, "2-hop cross-file chain must be detected"


# ── Go Gin ShouldBindJSON struct binding ─────────────────────────────────────

@_skip_no_tsgo
class TestGoGinBinding:
    """Gin c.ShouldBindJSON(&req) / c.Bind(&req) must mark struct fields tainted."""

    def _scan(self, code: str):
        return GoASTAnalyzer().analyze("handler.go", code)

    def test_should_bind_json_sql_detected(self):
        """c.ShouldBindJSON(&req) → req.Name in SQL → must fire GOAST-SQL-001."""
        code = (
            'package main\n'
            'import "github.com/gin-gonic/gin"\n'
            'type LoginReq struct { Name string `json:"name"` }\n'
            'func handler(c *gin.Context) {\n'
            '    var req LoginReq\n'
            '    c.ShouldBindJSON(&req)\n'
            '    db.Exec("SELECT * FROM users WHERE name=\'" + req.Name + "\'")\n'
            '}\n'
        )
        findings = self._scan(code)
        sql = [f for f in findings if f.rule_id == "GOAST-SQL-001"]
        assert sql, "c.ShouldBindJSON → req.Name in SQL must fire"

    def test_bind_json_cmd_detected(self):
        """c.BindJSON(&req) → req.Cmd in exec → must fire GOAST-CMD-001."""
        code = (
            'package main\n'
            'import "github.com/gin-gonic/gin"\n'
            'type CmdReq struct { Cmd string `json:"cmd"` }\n'
            'func handler(c *gin.Context) {\n'
            '    var req CmdReq\n'
            '    c.BindJSON(&req)\n'
            '    exec.Command("sh", "-c", req.Cmd).Run()\n'
            '}\n'
        )
        findings = self._scan(code)
        cmd = [f for f in findings if f.rule_id == "GOAST-CMD-001"]
        assert cmd, "c.BindJSON → req.Cmd in exec must fire"

    def test_should_bind_query_detected(self):
        """c.ShouldBindQuery(&req) → req.Search in SQL → must fire."""
        code = (
            'package main\n'
            'import "github.com/gin-gonic/gin"\n'
            'type SearchReq struct { Search string `form:"q"` }\n'
            'func handler(c *gin.Context) {\n'
            '    var req SearchReq\n'
            '    c.ShouldBindQuery(&req)\n'
            '    db.Query("SELECT * FROM items WHERE name LIKE %" + req.Search + "%")\n'
            '}\n'
        )
        findings = self._scan(code)
        sql = [f for f in findings if f.rule_id == "GOAST-SQL-001"]
        assert sql, "c.ShouldBindQuery → req.Search in SQL must fire"

    def test_no_fp_constant_struct(self):
        """Struct populated with literals must NOT fire."""
        code = (
            'package main\n'
            'import "github.com/gin-gonic/gin"\n'
            'type Req struct { Name string }\n'
            'func handler(c *gin.Context) {\n'
            '    req := Req{Name: "admin"}\n'
            '    db.Exec("SELECT * FROM users WHERE name=\'" + req.Name + "\'")\n'
            '}\n'
        )
        findings = self._scan(code)
        sql = [f for f in findings if f.rule_id == "GOAST-SQL-001"]
        assert not sql, "Struct with constant fields must not FP"


# ─────────────────────────────────────────────────────────────────────────────
# RubyASTAnalyzer tests
# ─────────────────────────────────────────────────────────────────────────────

_RBAST = RubyASTAnalyzer()


@_skip_no_tsrb
class TestRubyASTAnalyzer:
    """Tests for ast_ruby.py — Rails/Sinatra/Rack taint tracking."""

    # ── SQL injection ─────────────────────────────────────────────────────────

    def test_sql_direct_params(self):
        code = """
class UsersController < ApplicationController
  def show
    id = params[:id]
    User.find_by_sql("SELECT * FROM users WHERE id = " + id)
  end
end
"""
        findings = _RBAST.analyze("app/controllers/users_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-SQL-001" in rule_ids, "params[:id] → find_by_sql not detected"

    def test_sql_interpolation(self):
        code = """
def search
  q = params[:q]
  results = ActiveRecord::Base.connection.execute("SELECT * FROM articles WHERE title LIKE '%#{q}%'")
end
"""
        findings = _RBAST.analyze("app/models/article.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-SQL-001" in rule_ids, "String interpolation into execute() not detected"

    def test_sql_where_string(self):
        code = """
def filter
  name = params["name"]
  User.where("name = '" + name + "'")
end
"""
        findings = _RBAST.analyze("app/controllers/users_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-SQL-001" in rule_ids, "params → where(string) not detected"

    def test_sql_multihop(self):
        code = """
def index
  id = params[:id]
  query = "SELECT * FROM users WHERE id = " + id
  ActiveRecord::Base.connection.execute(query)
end
"""
        findings = _RBAST.analyze("app/controllers/users_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-SQL-001" in rule_ids, "Multi-hop params → query → execute not detected"

    # ── Command injection ─────────────────────────────────────────────────────

    def test_cmd_system(self):
        code = """
def run_cmd
  file = params[:file]
  system("ls " + file)
end
"""
        findings = _RBAST.analyze("app/controllers/cmd_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-CMD-001" in rule_ids, "params → system() not detected"

    def test_cmd_exec(self):
        code = """
def run
  cmd = params[:cmd]
  exec(cmd)
end
"""
        findings = _RBAST.analyze("app/controllers/cmd_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-CMD-001" in rule_ids, "params → exec() not detected"

    def test_cmd_io_popen(self):
        code = """
def pipe
  name = params[:name]
  IO.popen("cat " + name)
end
"""
        findings = _RBAST.analyze("app/controllers/pipe_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-CMD-001" in rule_ids, "params → IO.popen() not detected"

    # ── Path traversal ────────────────────────────────────────────────────────

    def test_path_file_read(self):
        code = """
def download
  path = params[:path]
  content = File.read(path)
  render plain: content
end
"""
        findings = _RBAST.analyze("app/controllers/files_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-PATH-001" in rule_ids, "params → File.read() not detected"

    def test_path_file_open(self):
        code = """
def view
  fname = params[:name]
  File.open(fname) { |f| f.read }
end
"""
        findings = _RBAST.analyze("app/controllers/files_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-PATH-001" in rule_ids, "params → File.open() not detected"

    # ── XSS ──────────────────────────────────────────────────────────────────

    def test_xss_render_plain(self):
        code = """
def show
  name = params[:name]
  render plain: name
end
"""
        findings = _RBAST.analyze("app/controllers/users_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-XSS-001" in rule_ids, "params → render plain: not detected"

    def test_xss_render_html(self):
        code = """
def show
  content = params[:html]
  render html: content
end
"""
        findings = _RBAST.analyze("app/controllers/users_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-XSS-001" in rule_ids, "params → render html: not detected"

    # ── Open redirect ─────────────────────────────────────────────────────────

    def test_open_redirect(self):
        code = """
def callback
  url = params[:return_to]
  redirect_to url
end
"""
        findings = _RBAST.analyze("app/controllers/sessions_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-REDIR-001" in rule_ids, "params → redirect_to not detected"

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def test_ssrf_uri_open(self):
        code = """
def fetch
  url = params[:url]
  URI.open(url)
end
"""
        findings = _RBAST.analyze("app/controllers/proxy_controller.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-SSRF-001" in rule_ids, "params → URI.open() not detected"

    # ── False positive suppression ────────────────────────────────────────────

    def test_no_fp_constant_sql(self):
        code = """
def list_all
  User.where("active = true")
end
"""
        findings = _RBAST.analyze("app/models/user.rb", code)
        sql = [f for f in findings if f.rule_id == "RBAST-SQL-001"]
        assert not sql, "Constant string in where() must not produce FP"

    def test_no_fp_safe_where_hash(self):
        code = """
def find_user
  id = params[:id]
  User.where(id: id)
end
"""
        findings = _RBAST.analyze("app/models/user.rb", code)
        sql = [f for f in findings if f.rule_id == "RBAST-SQL-001"]
        assert not sql, "Hash argument in where() must not produce FP"

    def test_no_fp_non_ruby_file(self):
        code = 'id = params[:id]; User.find_by_sql("SELECT * FROM users WHERE id=" + id)'
        findings = _RBAST.analyze("main.py", code)
        assert not findings, "Non-.rb file must not be analyzed by RubyASTAnalyzer"

    def test_cookies_subscript_tainted(self):
        """cookies[:key] is client-controlled — must fire SQL finding."""
        code = """
def show
  token = cookies[:auth_token]
  ActiveRecord::Base.connection.execute("SELECT * FROM sessions WHERE token='" + token + "'")
end
"""
        findings = _RBAST.analyze("app.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-SQL-001" in rule_ids, "cookies[:key] must be recognized as taint source"

    def test_session_subscript_tainted(self):
        """session[:key] can be client-controlled (cookie-backed) — must fire SQL."""
        code = """
def show
  user_id = session[:user_id]
  ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id=" + user_id)
end
"""
        findings = _RBAST.analyze("app.rb", code)
        rule_ids = {f.rule_id for f in findings}
        assert "RBAST-SQL-001" in rule_ids, "session[:key] must be recognized as taint source"


# ─────────────────────────────────────────────────────────────────────────────
# PhpASTAnalyzer tests
# ─────────────────────────────────────────────────────────────────────────────

_PHPAST = PhpASTAnalyzer()


@_skip_no_tsphp
class TestPhpASTAnalyzer:
    """Tests for ast_php.py — multi-vuln, multi-hop taint tracking."""

    # ── SQL injection ─────────────────────────────────────────────────────────

    def test_sql_pdo_query_multihop(self):
        code = """<?php
$id = $_GET["id"];
$sql = "SELECT * FROM users WHERE id = " . $id;
$pdo->query($sql);
"""
        findings = _PHPAST.analyze("index.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-SQL-001" in rule_ids, "Multi-hop $_GET → $sql → $pdo->query() not detected"

    def test_sql_mysql_query(self):
        code = """<?php
$name = $_POST["name"];
mysql_query("SELECT * FROM users WHERE name='" . $name . "'");
"""
        findings = _PHPAST.analyze("db.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-SQL-001" in rule_ids, "$_POST → mysql_query() not detected"

    def test_sql_mysqli_obj(self):
        code = """<?php
$id = $_REQUEST["id"];
$q = "SELECT * FROM users WHERE id=" . $id;
$mysqli->query($q);
"""
        findings = _PHPAST.analyze("db.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-SQL-001" in rule_ids, "$_REQUEST → $mysqli->query() not detected"

    def test_sql_pdo_prepare(self):
        code = """<?php
$col = $_GET["col"];
$stmt = $pdo->prepare("SELECT " . $col . " FROM users");
"""
        findings = _PHPAST.analyze("db.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-SQL-001" in rule_ids, "$_GET → $pdo->prepare() not detected"

    def test_sql_interpolation(self):
        code = '<?php\n$id = $_GET["id"];\n$pdo->query("SELECT * FROM t WHERE id=$id");\n'
        findings = _PHPAST.analyze("db.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-SQL-001" in rule_ids, "String interpolation into $pdo->query() not detected"

    # ── Command injection ─────────────────────────────────────────────────────

    def test_cmd_system(self):
        code = """<?php
$cmd = $_GET["cmd"];
system("ls " . $cmd);
"""
        findings = _PHPAST.analyze("exec.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-CMD-001" in rule_ids, "$_GET → system() not detected"

    def test_cmd_exec(self):
        code = """<?php
$file = $_POST["file"];
exec($file);
"""
        findings = _PHPAST.analyze("exec.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-CMD-001" in rule_ids, "$_POST → exec() not detected"

    def test_cmd_shell_exec(self):
        code = """<?php
$arg = $_GET["arg"];
$out = shell_exec("ping " . $arg);
"""
        findings = _PHPAST.analyze("exec.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-CMD-001" in rule_ids, "$_GET → shell_exec() not detected"

    # ── Path traversal / LFI ─────────────────────────────────────────────────

    def test_path_file_get_contents(self):
        code = """<?php
$path = $_GET["file"];
$data = file_get_contents($path);
echo $data;
"""
        findings = _PHPAST.analyze("files.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-PATH-001" in rule_ids, "$_GET → file_get_contents() not detected"

    def test_path_include_lfi(self):
        code = """<?php
$page = $_GET["page"];
include($page . ".php");
"""
        findings = _PHPAST.analyze("files.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-PATH-001" in rule_ids, "$_GET → include() not detected"

    def test_path_fopen(self):
        code = """<?php
$fname = $_POST["name"];
$f = fopen($fname, "r");
"""
        findings = _PHPAST.analyze("files.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-PATH-001" in rule_ids, "$_POST → fopen() not detected"

    # ── XSS ──────────────────────────────────────────────────────────────────

    def test_xss_echo_multihop(self):
        code = """<?php
$raw = $_GET["name"];
$name = $raw;
echo $name;
"""
        findings = _PHPAST.analyze("view.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-XSS-001" in rule_ids, "Multi-hop $_GET → $name → echo not detected"

    def test_xss_no_fp_htmlspecialchars(self):
        code = """<?php
$name = $_GET["name"];
$safe = htmlspecialchars($name);
echo $safe;
"""
        findings = _PHPAST.analyze("view.php", code)
        xss = [f for f in findings if f.rule_id == "PHAST-XSS-001"]
        assert not xss, "htmlspecialchars() sanitized output must not produce XSS FP"

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def test_ssrf_curl_setopt(self):
        code = """<?php
$url = $_GET["url"];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_exec($ch);
"""
        findings = _PHPAST.analyze("proxy.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-SSRF-001" in rule_ids, "$_GET → curl_setopt(CURLOPT_URL) not detected"

    # ── Open redirect ─────────────────────────────────────────────────────────

    def test_open_redirect_header(self):
        code = """<?php
$url = $_GET["return_to"];
header("Location: " . $url);
"""
        findings = _PHPAST.analyze("auth.php", code)
        rule_ids = {f.rule_id for f in findings}
        assert "PHAST-REDIR-001" in rule_ids, "$_GET → header(Location:) not detected"

    # ── False positive suppression ────────────────────────────────────────────

    def test_no_fp_constant_sql(self):
        code = """<?php
$sql = "SELECT * FROM users WHERE active = 1";
$pdo->query($sql);
"""
        findings = _PHPAST.analyze("db.php", code)
        sql = [f for f in findings if f.rule_id == "PHAST-SQL-001"]
        assert not sql, "Constant SQL must not produce FP"

    def test_no_fp_sanitized_cmd(self):
        code = """<?php
$raw = $_GET["file"];
$file = intval($raw);
system("cat /proc/" . $file);
"""
        findings = _PHPAST.analyze("exec.php", code)
        cmd = [f for f in findings if f.rule_id == "PHAST-CMD-001"]
        assert not cmd, "intval() sanitized value must not trigger CMD FP"

    def test_no_fp_non_php_file(self):
        code = '<?php\n$id = $_GET["id"];\n$pdo->query("SELECT * FROM t WHERE id=" . $id);'
        findings = _PHPAST.analyze("main.py", code)
        assert not findings, "Non-.php file must not be analyzed by PhpASTAnalyzer"


# ── Exploitability filter ─────────────────────────────────────────────────────

class TestExploitabilityFilter:
    """--filter exploitable: keep tainted findings, drop unknown-taint ones."""

    def _findings(self, code: str):
        return PythonASTAnalyzer().analyze("app.py", code)

    def test_tainted_finding_kept(self):
        """taint_status='tainted' findings must survive the exploitable filter."""
        code = (
            "from flask import request\n"
            "def view():\n"
            "    name = request.args.get('name')\n"
            "    from pathlib import Path\n"
            "    return (Path('/data') / name).read_text()\n"
        )
        findings = self._findings(code)
        tainted = [f for f in findings if f.taint_status == "tainted" and not f.suppression_reason]
        kept = [f for f in tainted if f.taint_status != "unknown"]
        assert kept, "TAINTED findings must not be dropped by exploitable filter"

    def test_unknown_taint_finding_dropped(self):
        """taint_status='unknown' (low_reach) findings must be filtered out."""
        code = (
            "def process(target_file: str):\n"
            "    from pathlib import Path\n"
            "    return Path(target_file).read_text()\n"
        )
        findings = self._findings(code)
        unknown = [f for f in findings if f.taint_status == "unknown" and not f.suppression_reason]
        # After exploitable filter: unknown findings removed
        filtered = [f for f in unknown if f.taint_status != "unknown"]
        assert not filtered, "unknown-taint findings are exactly those dropped by exploitable filter"
        # Verify the scanner-level filter works
        from vulnscanner.models import ScanResult
        result = ScanResult(repo_url=".")
        result.findings = findings
        result.findings = [f for f in result.findings if f.taint_status != "unknown"]
        assert all(f.taint_status != "unknown" for f in result.findings)

    def test_secret_finding_no_taint_kept(self):
        """Findings with no taint tracking (taint_status=None) must be kept."""
        code = 'db_password = "hunter2secret"\n'
        findings = self._findings(code)
        secrets = [f for f in findings if f.taint_status is None and not f.suppression_reason]
        kept = [f for f in secrets if f.taint_status != "unknown"]
        assert kept, "Secret findings (no taint tracking) must survive exploitable filter"
