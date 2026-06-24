import json
import tempfile
from pathlib import Path

import pytest

from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
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
