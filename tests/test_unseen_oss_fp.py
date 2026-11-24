"""False-positive types found by scanning five unseen OSS repos (redmine, halo, memos, gotify, node-red).

Each FP type has a twin that must still be reported, so the fix cannot become a blanket suppression.
"""
import pytest

from vulnscanner.analyzers.ast_go import GoASTAnalyzer
from vulnscanner.analyzers.csrf import CSRFAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.sql_injection import SQLInjectionAnalyzer
from pathlib import Path

from vulnscanner.rules.loader import load_rules

_BUILTIN = Path(__file__).parent.parent / "vulnscanner" / "rules" / "builtin"


def _ids(findings, rule):
    return [f for f in findings if f.rule_id == rule]


# ── Go: .Parse(x) is a template sink only on a template ──────────────────────────────────────

_GO = "package main\nimport (\n{imports}\n)\nfunc h(w http.ResponseWriter, r *http.Request) {{\n    {body}\n}}\n"


def _go(imports, body):
    return GoASTAnalyzer().analyze("srv/h.go", _GO.format(imports=imports, body=body))


@pytest.mark.parametrize("call", [
    "u, _ := url.Parse(o)", "t, _ := time.Parse(time.RFC3339, o)", "id, _ := uuid.Parse(o)",
])
def test_go_package_level_parse_is_not_a_template(call):
    f = _go('"html/template"\n"net/http"\n"net/url"\n"time"\n"github.com/google/uuid"',
            'o := r.Header.Get("Origin")\n    ' + call + '\n    _ = template.New("x")')
    assert not _ids(f, "GOAST-SSTI-001")


def test_go_parse_in_a_file_without_a_template_import_is_not_ssti():
    f = _go('"net/http"', 'o := r.FormValue("p")\n    p := parser.New()\n    p.Parse(o)')
    assert not _ids(f, "GOAST-SSTI-001")


def test_go_template_parse_of_request_data_is_still_ssti():
    f = _go('"html/template"\n"net/http"', 'src := r.FormValue("t")\n    t, _ := template.New("p").Parse(src)\n    _ = t')
    assert _ids(f, "GOAST-SSTI-001")


# ── AKIA inside base64 is not an AWS key ─────────────────────────────────────────────────────

def test_aws_key_pattern_inside_a_base64_blob_is_not_a_key():
    blob = "fileDesc(\"ChxhcGkvYXR0YWNobWVudF9zZXJ2aWNlLnByb3RvEgltZW1vcy5hcGkiAKIAQWERTYUIOPLKJHGFDSAZXCVBNMQWERTYUIOPLKJHGFDSA\")"
    assert not _ids(HardcodedSecretsAnalyzer().analyze("web/x_pb.ts", blob), "SEC-004")
    blob2 = 'x = "abcAKIAIOSFODNN7ABCD123def"'
    assert not _ids(HardcodedSecretsAnalyzer().analyze("a.py", blob2), "SEC-004")


def test_standalone_aws_key_is_still_reported():
    assert _ids(HardcodedSecretsAnalyzer().analyze("a.py", 'key = "AKIAIOSFODNN7ABCD123"'), "SEC-004")


# ── Thymeleaf th:action forms carry a CSRF token ─────────────────────────────────────────────

def test_thymeleaf_action_form_is_not_missing_a_token():
    html = '<form th:action="@{/logout}" method="post">\n<button>out</button>\n</form>'
    assert not _ids(CSRFAnalyzer().analyze("templates/logout.html", html), "CSRF-002")


def test_plain_post_form_is_still_flagged():
    html = '<form action="/logout" method="post">\n<button>out</button>\n</form>'
    assert _ids(CSRFAnalyzer().analyze("templates/logout.html", html), "CSRF-002")


# ── Ruby: interpolating a table name is not interpolating input ──────────────────────────────

def _rb(code, path="app/models/m.rb"):
    return SQLInjectionAnalyzer().analyze(path, code)


@pytest.mark.parametrize("code", [
    'scope.where("LOWER(#{WikiPage.table_name}.title) LIKE LOWER(?)", "%#{q}%")',
    'Issue.where("#{Project.table_name}.lft >= ? AND #{self.class.table_name}.rgt <= ?", a, b)',
    'User.where("mail_notification = #{connection.quoted_true}")',
    'scope.where("#{Journal.table_name}.id > #{journal_id.to_i}")',
    'scope.where("kind = #{KIND_PUBLIC}")',
    "scope.where('#{name} = 1')",
])
def test_ruby_where_with_a_harmless_interpolation_is_not_flagged(code):
    assert not _ids(_rb(code), "SQL-007")


def test_ruby_interpolated_local_that_holds_a_table_name_is_not_flagged():
    code = 't = Foo.table_name\nscope = Bar.where("#{t}.project_id = ?", id)\n'
    assert not _ids(_rb(code), "SQL-007")


@pytest.mark.parametrize("code", [
    'User.where("name = \'#{params[:name]}\'")',
    'User.where("id = #{params[:id]} AND #{Project.table_name}.x = ?", 1)',
    'User.find_by_sql("select * from t where a = #{q}")',
])
def test_ruby_where_with_request_data_is_still_flagged(code):
    assert _ids(_rb(code), "SQL-007")


def test_ruby_raw_connection_with_request_data_is_still_critical():
    assert _ids(_rb('connection.execute("DELETE FROM t WHERE id=#{params[:id]}")'), "SQL-008")


def test_ruby_schema_migration_is_not_reported():
    code = 'connection.execute("DELETE FROM t WHERE id=#{x}")'
    assert not _ids(_rb(code, "db/migrate/20130207_x.rb"), "SQL-008")


# ── Java: raw() is a builder method unless the file talks to a database ──────────────────────

def test_java_raw_accessor_and_builder_are_not_sql():
    code = "class C { Object f(Content c) { return Wrapper.builder().raw(c.getRaw()).build(); } }\n"
    assert not _ids(SQLInjectionAnalyzer().analyze("app/C.java", code), "SQL-005")


def test_java_zero_argument_raw_is_an_accessor_even_next_to_jdbc():
    code = "import java.sql.Connection;\nclass C { Object f(Content c) { return c.raw(); } }\n"
    assert not _ids(SQLInjectionAnalyzer().analyze("app/C.java", code), "SQL-005")


def test_java_raw_with_an_argument_in_a_database_file_is_still_checked():
    code = "import java.sql.Connection;\nclass C { void f() { var x = repo.raw(q); } }\n"
    assert _ids(SQLInjectionAnalyzer().analyze("app/R.java", code), "SQL-005")


# ── Java log injection needs request data, not a variable called "request" ───────────────────

def _java_log_hits(line):
    rules = [r for r in load_rules([str(_BUILTIN)]) if r.id == "JAVA-LOG-001"]
    return [r.id for r in rules if r.matches(line)]


@pytest.mark.parametrize("line", [
    'log.debug("Adding request {} immediately", request);',
    'log.error("Invalid MenuItem {}", request.name());',
    'log.info("param {}", paramName);',
])
def test_java_log_of_an_internal_request_object_is_not_log_injection(line):
    assert not _java_log_hits(line)


@pytest.mark.parametrize("line", [
    'log.info("user " + request.getParameter("u"));',
    'logger.warn("ua={}", request.getHeader("User-Agent"));',
])
def test_java_log_of_a_request_parameter_is_still_flagged(line):
    assert _java_log_hits(line) == ["JAVA-LOG-001"]
