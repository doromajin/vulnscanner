"""Tests for the three-state taint tracking engine in ast_python.py."""
import ast

import pytest

from vulnscanner.taint import TaintStatus
from vulnscanner.analyzers.ast_python import (
    PythonASTAnalyzer,
    _taint_of,
    _taint_merge,
    _collect_class_attrs,
    _collect_scope_assignments,
    set_cross_file_context,
)
from vulnscanner.models import Severity

AST = PythonASTAnalyzer()


# ── helpers ────────────────────────────────────────────────────────────────────

def _expr(src: str) -> ast.expr:
    """Parse a single expression and return its AST node."""
    return ast.parse(src, mode="eval").body


def _stmt_assignments(src: str) -> dict:
    """Extract assignments from a function body snippet."""
    code = f"def f():\n" + "\n".join(f"    {line}" for line in src.splitlines())
    tree = ast.parse(code)
    func = tree.body[0]
    return _collect_scope_assignments(func)


def _class_attrs(src: str) -> dict:
    """Extract class-level and __init__ self.xxx attrs from a class snippet."""
    tree = ast.parse(src)
    return _collect_class_attrs(tree.body[0])


# ── _taint_of: CLEAN cases ─────────────────────────────────────────────────────

class TestTaintClean:
    def test_string_literal(self):
        node = _expr('"hello"')
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_integer_literal(self):
        node = _expr("42")
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_none_literal(self):
        node = _expr("None")
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_true_false(self):
        assert _taint_of(_expr("True")).status == TaintStatus.CLEAN
        assert _taint_of(_expr("False")).status == TaintStatus.CLEAN

    def test_fstring_no_interpolation(self):
        # f"static" — JoinedStr with no FormattedValues
        node = _expr('f"static string"')
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_concat_of_two_literals(self):
        node = _expr('"hello" + "world"')
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_percent_format_both_literals(self):
        node = _expr('"SELECT %s" % "literal"')
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_constant_propagation_through_assignment(self):
        assignments = _stmt_assignments('x = "safe_value"\ny = x')
        node = _expr("y")
        # y → x → "safe_value" → CLEAN
        result = _taint_of(node, assignments)
        assert result.status == TaintStatus.CLEAN

    def test_self_attr_literal_in_init(self):
        cls_src = (
            "class DB:\n"
            "    def __init__(self):\n"
            '        self.placeholder = "?"\n'
        )
        attrs = _class_attrs(cls_src)
        # self.placeholder → Constant("?") → CLEAN
        node = _expr("self.placeholder")
        result = _taint_of(node, class_attrs=attrs)
        assert result.status == TaintStatus.CLEAN

    def test_percent_format_with_clean_attr(self):
        cls_src = (
            "class DB:\n"
            "    def __init__(self):\n"
            '        self.placeholder = "%s"\n'
        )
        attrs = _class_attrs(cls_src)
        # "SELECT %s" % self.placeholder  → BinOp(CLEAN, Mod, CLEAN) → CLEAN
        left = _expr('"SELECT * FROM t WHERE id = %s"')
        right = _expr("self.placeholder")
        node = ast.BinOp(left=left, op=ast.Mod(), right=right)
        result = _taint_of(node, class_attrs=attrs)
        assert result.status == TaintStatus.CLEAN

    def test_sanitizer_method_no_args_is_unknown(self):
        # .escape() with no args: no argument to inspect → UNKNOWN
        node = _expr("value.escape()")
        assert _taint_of(node).status == TaintStatus.UNKNOWN

    def test_html_escape_on_unknown_arg_is_unknown(self):
        # html.escape(val) where val is unresolvable (not a known taint source) → UNKNOWN.
        # "user_input" is in _TAINTED_NAME_SOURCES, so use a generic name here.
        node = _expr("html.escape(some_val)")
        assert _taint_of(node).status == TaintStatus.UNKNOWN

    def test_html_escape_on_literal_is_clean(self):
        # html.escape("safe_string"): argument is CLEAN → result is CLEAN
        node = _expr('html.escape("safe_string")')
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_html_escape_on_tainted_preserves_tainted(self):
        # html.escape wrapping a request value: taint status MUST stay TAINTED.
        # html.escape is ineffective against SQL/CMD/SSRF — downgrading to UNKNOWN
        # would hide HIGH findings at those sinks.
        assignments = _stmt_assignments("x = request.args.get('q')")
        node = _expr("html.escape(x)")
        result = _taint_of(node, assignments)
        assert result.status == TaintStatus.TAINTED
        assert "html.escape" in result.sanitizers
        assert "HTML/URL context only" in result.reason

    def test_int_coercion_returns_clean(self):
        # int() is a universal sanitizer: non-string output can't carry injection
        node = _expr("int(user_id)")
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_float_coercion_returns_clean(self):
        node = _expr("float(user_val)")
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_url_sanitizer_on_tainted_preserves_tainted(self):
        # urllib.parse.quote on a tainted value: taint must propagate as TAINTED.
        # URL encoding is ineffective against SQL/CMD injection.
        assignments = _stmt_assignments("v = request.form.get('path')")
        node = _expr("urllib.parse.quote(v)")
        result = _taint_of(node, assignments)
        assert result.status == TaintStatus.TAINTED
        assert any("quote" in s for s in result.sanitizers)

    def test_empty_list_is_clean(self):
        node = _expr("[]")
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_literal_list_is_clean(self):
        node = _expr('["a", "b", "c"]')
        assert _taint_of(node).status == TaintStatus.CLEAN

    def test_class_level_constant(self):
        cls_src = "class Config:\n    TABLE = 'users'\n"
        attrs = _class_attrs(cls_src)
        node = _expr("self.TABLE")
        result = _taint_of(node, class_attrs=attrs)
        assert result.status == TaintStatus.CLEAN


# ── _taint_of: TAINTED cases ───────────────────────────────────────────────────

class TestTaintTainted:
    def test_request_name_source(self):
        node = _expr("request")
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_user_input_name_source(self):
        node = _expr("user_input")
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_request_args_attribute(self):
        node = _expr("request.args")
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_request_form_attribute(self):
        node = _expr("request.form")
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_request_json_attribute(self):
        node = _expr("request.json")
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_django_get_attribute(self):
        node = _expr("request.GET")
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_getter_on_tainted_object(self):
        # request.args.get("key")
        node = _expr('request.args.get("key")')
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_subscript_of_tainted(self):
        # request.args["file"]
        node = _expr('request.args["file"]')
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_assignment_chain_tainted(self):
        assignments = _stmt_assignments('url = request.args.get("url")')
        node = _expr("url")
        result = _taint_of(node, assignments)
        assert result.status == TaintStatus.TAINTED

    def test_python_input_call(self):
        node = _expr('input("Enter: ")')
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_fstring_with_tainted_part(self):
        assignments = _stmt_assignments('user = request.args.get("user")')
        node = _expr('f"SELECT * FROM t WHERE name = \'{user}\'"')
        result = _taint_of(node, assignments)
        assert result.status == TaintStatus.TAINTED

    def test_concat_with_tainted(self):
        node = _expr('"prefix " + request.args["x"]')
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_percent_format_with_tainted(self):
        node = _expr('"SELECT %s" % request.args["id"]')
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_format_method_with_tainted_arg(self):
        # "SELECT {}".format(request.args["id"])
        node = _expr('"SELECT {}" .format(request.args["id"])')
        result = _taint_of(node)
        assert result.status == TaintStatus.TAINTED

    def test_get_json_on_request_is_tainted(self):
        node = _expr("request.get_json()")
        assert _taint_of(node).status == TaintStatus.TAINTED

    def test_subscript_two_hops_from_request(self):
        assignments = _stmt_assignments(
            'data = request.get_json()\n'
            'filename = data["filename"]'
        )
        node = _expr("filename")
        result = _taint_of(node, assignments)
        assert result.status == TaintStatus.TAINTED


# ── _taint_of: UNKNOWN cases ───────────────────────────────────────────────────

class TestTaintUnknown:
    def test_function_param_not_in_sources(self):
        # "username" is a function param — not in _TAINTED_NAME_SOURCES
        # and not in assignments (no assignment in function body)
        node = _expr("username")
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN

    def test_generic_variable_data(self):
        # "data" as a standalone name (not from request)
        node = _expr("data")
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN

    def test_generic_config_subscript(self):
        # config["key"] where config is UNKNOWN
        node = _expr('config["key"]')
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN

    def test_function_call_result(self):
        # load_config() → function call result is UNKNOWN
        node = _expr("load_config()")
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN

    def test_fstring_with_unknown_part(self):
        node = _expr('f"uploads/{filename}"')
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN

    def test_concat_with_unknown(self):
        node = _expr('"prefix/" + filename')
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN

    def test_untracked_self_attr(self):
        # self.some_unknown_attr not in any class we parsed
        node = _expr("self.some_unknown_attr")
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN

    def test_os_environ_attr(self):
        # os.environ is not a tainted attr (it's an Attribute with obj=Name("os"))
        node = _expr("os.environ")
        result = _taint_of(node)
        # os is UNKNOWN (not a tainted name source), .environ is not in _TAINTED_ATTR_NAMES
        assert result.status == TaintStatus.UNKNOWN

    def test_data_param_subscript_is_unknown(self):
        # data['config_file'] where data is a function param → UNKNOWN
        node = _expr("data['config_file']")
        result = _taint_of(node)
        assert result.status == TaintStatus.UNKNOWN


# ── _taint_merge helper ────────────────────────────────────────────────────────

class TestTaintMerge:
    def test_tainted_beats_unknown(self):
        from vulnscanner.taint import TaintInfo, TaintStatus
        t = TaintInfo(TaintStatus.TAINTED, "t")
        u = TaintInfo(TaintStatus.UNKNOWN, "u")
        assert _taint_merge(t, u).status == TaintStatus.TAINTED
        assert _taint_merge(u, t).status == TaintStatus.TAINTED

    def test_unknown_beats_clean(self):
        from vulnscanner.taint import TaintInfo, TaintStatus
        u = TaintInfo(TaintStatus.UNKNOWN, "u")
        c = TaintInfo(TaintStatus.CLEAN, "c")
        assert _taint_merge(u, c).status == TaintStatus.UNKNOWN
        assert _taint_merge(c, u).status == TaintStatus.UNKNOWN

    def test_tainted_beats_clean(self):
        from vulnscanner.taint import TaintInfo, TaintStatus
        t = TaintInfo(TaintStatus.TAINTED, "t")
        c = TaintInfo(TaintStatus.CLEAN, "c")
        assert _taint_merge(t, c).status == TaintStatus.TAINTED


# ── _collect_class_attrs ───────────────────────────────────────────────────────

class TestCollectClassAttrs:
    def test_collects_init_self_assignments(self):
        src = (
            "class DB:\n"
            "    def __init__(self):\n"
            '        self.placeholder = "?"\n'
            '        self.table = "users"\n'
        )
        attrs = _class_attrs(src)
        assert "placeholder" in attrs
        assert "table" in attrs

    def test_collects_class_level_assignments(self):
        src = "class Config:\n    TABLE = 'items'\n    LIMIT = 100\n"
        attrs = _class_attrs(src)
        assert "TABLE" in attrs
        assert "LIMIT" in attrs

    def test_ignores_other_method_self_assignments(self):
        src = (
            "class Service:\n"
            "    def __init__(self):\n"
            '        self.name = "service"\n'
            "    def update(self):\n"
            '        self.runtime = "now"  # NOT collected\n'
        )
        attrs = _class_attrs(src)
        assert "name" in attrs
        assert "runtime" not in attrs  # only __init__ is scanned


# ── Integration: AST analyzer using 3-state taint ─────────────────────────────

class TestASTAnalyzerTaintIntegration:
    def test_clean_sql_suppressed(self):
        # "SELECT %s" % "literal" → CLEAN → suppressed, no AST-SQL-003 in reported findings
        code = (
            'import sqlite3\n'
            'def q():\n'
            '    conn = sqlite3.connect(":memory:")\n'
            '    conn.cursor().execute("SELECT %s" % "42")\n'
        )
        findings = AST.analyze("t.py", code)
        # Active findings (not suppressed) should not include SQL-003
        active = [f for f in findings if f.suppression_reason is None]
        assert not any(f.rule_id == "AST-SQL-003" for f in active)
        # The suppressed one IS in findings list (scanner will remove it)
        suppressed = [f for f in findings if f.suppression_reason == "clean_taint_source"]
        assert any(f.rule_id == "AST-SQL-003" for f in suppressed)

    def test_unknown_sql_emits_medium(self):
        # username is a function parameter → UNKNOWN → MEDIUM
        code = (
            'def q(username):\n'
            '    conn.cursor().execute("SELECT * FROM t WHERE name = %s" % username)\n'
        )
        findings = AST.analyze("t.py", code)
        sql_findings = [f for f in findings if f.rule_id == "AST-SQL-003"
                        and f.suppression_reason is None]
        assert sql_findings, "Should detect SQL-003"
        assert sql_findings[0].severity == Severity.MEDIUM

    def test_tainted_sql_emits_high(self):
        # request.args[...] → TAINTED → HIGH
        code = (
            'def view(request):\n'
            '    conn.cursor().execute(f"SELECT * FROM t WHERE id = {request.args[\'id\']}")\n'
        )
        findings = AST.analyze("t.py", code)
        sql_findings = [f for f in findings if f.rule_id == "AST-SQL-001"
                        and f.suppression_reason is None]
        assert sql_findings
        assert sql_findings[0].severity == Severity.HIGH

    def test_self_placeholder_suppressed(self):
        # pyspider pattern: self.placeholder = "?" set in __init__
        code = (
            'class ProjectDB:\n'
            '    def __init__(self):\n'
            '        self.placeholder = "?"\n'
            '    def execute(self, query, values):\n'
            '        self.cursor.execute(\n'
            '            "SELECT * FROM t WHERE id = %s" % self.placeholder,\n'
            '            values,\n'
            '        )\n'
        )
        findings = AST.analyze("t.py", code)
        active = [f for f in findings if f.suppression_reason is None]
        assert not any(f.rule_id == "AST-SQL-003" for f in active), (
            "self.placeholder='?' is CLEAN; SQL-003 should be suppressed"
        )

    def test_data_param_open_not_path001(self):
        # data parameter (not from user input) should not trigger AST-PATH-001
        code = (
            "def save_plugin(self, data):\n"
            "    config_file = data['config_file']\n"
            "    open(config_file, 'w')\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(f.rule_id == "AST-PATH-001" for f in findings)

    def test_request_data_open_is_path001(self):
        # data from request.get_json() is TAINTED → should trigger AST-PATH-001
        code = (
            "def view(request):\n"
            "    data = request.get_json()\n"
            "    path = data['filename']\n"
            "    open(path)\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(f.rule_id == "AST-PATH-001" for f in findings)

    def test_constant_subprocess_not_flagged(self):
        # cmd = 'literal'; Popen(cmd, shell=True) → CLEAN → no flag
        code = (
            "import subprocess\n"
            "def run():\n"
            "    cmd = 'git status'\n"
            "    subprocess.Popen(cmd, shell=True)\n"
        )
        findings = AST.analyze("t.py", code)
        assert not any(f.rule_id == "AST-CMD-002" and f.suppression_reason is None
                       for f in findings)

    def test_tainted_subprocess_flagged(self):
        # cmd = request.args.get('cmd') → TAINTED → flag
        code = (
            "import subprocess\n"
            "def view(request):\n"
            "    cmd = request.args.get('cmd')\n"
            "    subprocess.Popen(cmd, shell=True)\n"
        )
        findings = AST.analyze("t.py", code)
        assert any(f.rule_id == "AST-CMD-002" and f.severity == Severity.HIGH
                   for f in findings)

    def test_unknown_ssrf_emits_medium(self):
        # endpoint is function param → UNKNOWN → MEDIUM, AST-SSRF-002
        code = (
            "import requests\n"
            "def call(endpoint):\n"
            "    return requests.get(endpoint)\n"
        )
        findings = AST.analyze("t.py", code)
        ssrf = [f for f in findings if f.rule_id == "AST-SSRF-002"]
        assert ssrf
        assert ssrf[0].severity == Severity.MEDIUM

    def test_tainted_ssrf_emits_high(self):
        code = (
            "import requests\n"
            "def view(request):\n"
            "    url = request.args.get('url')\n"
            "    return requests.get(url)\n"
        )
        findings = AST.analyze("t.py", code)
        ssrf = [f for f in findings if f.rule_id == "AST-SSRF-001"]
        assert ssrf
        assert ssrf[0].severity == Severity.HIGH

    def test_taint_info_attached_to_finding(self):
        code = (
            "def view(request):\n"
            "    open(request.args.get('file'))\n"
        )
        findings = [f for f in AST.analyze("t.py", code) if f.rule_id == "AST-PATH-001"]
        assert findings
        f = findings[0]
        assert f.taint_status == "tainted"
        assert f.taint_reason is not None
        assert f.confidence > 0.5

    def test_suppressed_finding_has_clean_taint_status(self):
        code = (
            'def q():\n'
            '    conn.cursor().execute("SELECT %s" % "42")\n'
        )
        findings = AST.analyze("t.py", code)
        suppressed = [f for f in findings if f.suppression_reason == "clean_taint_source"]
        assert suppressed
        assert suppressed[0].taint_status == "clean"

    def test_scanner_counts_clean_taint_in_breakdown(self):
        # End-to-end: scanner must count clean_taint_source in suppression_breakdown
        import tempfile, os
        from vulnscanner.scanner import VulnScanner

        code = (
            "import sqlite3\n"
            "class DB:\n"
            "    def __init__(self):\n"
            '        self.ph = "?"\n'
            "    def q(self):\n"
            '        conn = sqlite3.connect(":memory:")\n'
            '        conn.cursor().execute("SELECT %s" % self.ph)\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            py_file = os.path.join(tmp, "db.py")
            with open(py_file, "w", encoding="utf-8") as fh:
                fh.write(code)
            result = VulnScanner().scan(tmp)

        assert result.suppression_breakdown.get("clean_taint_source", 0) >= 1


# ── Sink-aware sanitizer propagation (FuguAI validation scenarios) ─────────────

class TestSanitizerSinkAwareness:
    """Verify that context-specific sanitizers preserve taint for non-HTML sinks."""

    def test_sql_html_escape_emits_high(self):
        # html.escape() does NOT protect against SQL injection → HIGH finding
        code = (
            "def view(request, cursor):\n"
            "    x = html.escape(request.args.get('id'))\n"
            "    cursor.execute('SELECT * FROM users WHERE id=' + x)\n"
        )
        findings = AST.analyze("t.py", code)
        sql = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert sql, "html.escape() in SQL context must not suppress the finding"
        assert sql[0].severity == Severity.HIGH

    def test_cmd_html_escape_emits_high(self):
        # html.escape() does NOT protect against command injection → HIGH finding
        code = (
            "import os\n"
            "def view(request):\n"
            "    cmd = html.escape(request.args.get('cmd'))\n"
            "    os.system(cmd)\n"
        )
        findings = AST.analyze("t.py", code)
        cmd = [f for f in findings if "CMD" in f.rule_id and f.suppression_reason is None]
        assert cmd, "html.escape() in CMD context must not suppress the finding"
        assert cmd[0].severity == Severity.HIGH

    def test_ssrf_url_quote_active_finding(self):
        # urllib.parse.quote() does NOT protect against SSRF → active finding
        code = (
            "import requests, urllib.parse\n"
            "def view(request):\n"
            "    url = urllib.parse.quote(request.args.get('url'))\n"
            "    requests.get(url)\n"
        )
        findings = AST.analyze("t.py", code)
        ssrf = [f for f in findings if "SSRF" in f.rule_id and f.suppression_reason is None]
        assert ssrf, "urllib.parse.quote() in SSRF context must not suppress the finding"

    def test_sql_int_coercion_suppressed(self):
        # int() is a universal sanitizer → CLEAN → finding suppressed.
        # Use user_id directly in f-string (str() is not a tracked sanitizer and
        # would lose the CLEAN status through the generic call handler).
        code = (
            "def view(request, cursor):\n"
            "    user_id = int(request.args.get('id'))\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n"
        )
        findings = AST.analyze("t.py", code)
        sql_active = [f for f in findings
                      if "SQL" in f.rule_id and f.suppression_reason is None]
        assert not sql_active, "int() coercion makes the value universally safe; SQL finding should be suppressed"

    def test_sanitizer_name_recorded_in_taint_metadata(self):
        # The sanitizer name must be stored in TaintInfo.sanitizers for audit trails
        assignments = _stmt_assignments("x = request.args.get('q')")
        node = _expr("html.escape(x)")
        result = _taint_of(node, assignments)
        assert result.status == TaintStatus.TAINTED
        assert "html.escape" in result.sanitizers, (
            "sanitizer name must be recorded in metadata even when taint is preserved"
        )


# ── cross-file taint tracking ──────────────────────────────────────────────────

class TestCrossFileTaint:
    """Phase 4: taint propagation across imported project-local files."""

    def _scan_with_context(self, files: dict[str, str], target_file: str) -> list:
        """Analyze target_file with cross-file context from files dict."""
        set_cross_file_context(files)
        return AST.analyze(target_file, files[target_file])

    def test_tainted_arg_passthrough_via_import(self):
        # utils.py: process(s) returns s unchanged (passthrough)
        # app.py: from utils import process; db.execute(... + process(request.args['q']))
        files = {
            "utils.py": (
                "def process(s):\n"
                "    return s\n"
            ),
            "app.py": (
                "from utils import process\n"
                "def view(request, cursor):\n"
                "    q = request.args.get('q')\n"
                "    cursor.execute('SELECT * FROM t WHERE id=' + process(q))\n"
            ),
        }
        findings = self._scan_with_context(files, "app.py")
        sql = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert sql, "tainted arg passthrough via imported function must be detected"

    def test_remote_taint_source_function(self):
        # utils.py: get_input() reads request.args directly, so it is a taint source
        # app.py: from utils import get_input; db.execute(... + get_input())
        files = {
            "utils.py": (
                "def get_input(request):\n"
                "    return request.args.get('q')\n"
            ),
            "app.py": (
                "from utils import get_input\n"
                "def view(request, cursor):\n"
                "    val = get_input(request)\n"
                "    cursor.execute('SELECT * FROM t WHERE id=' + val)\n"
            ),
        }
        findings = self._scan_with_context(files, "app.py")
        sql = [f for f in findings if "SQL" in f.rule_id and f.suppression_reason is None]
        assert sql, "remote taint-source function must propagate taint to callers"

    def test_no_cross_file_fp_for_clean_passthrough(self):
        # utils.py: sanitize(s) returns int(s), which is universally safe.
        # Phase 4 must not report a confirmed-TAINTED (HIGH) SQL finding;
        # an UNKNOWN/MEDIUM finding is acceptable since we cannot prove the
        # remote function always returns a safe value without full analysis.
        files = {
            "utils.py": (
                "def sanitize(s):\n"
                "    return int(s)\n"
            ),
            "app.py": (
                "from utils import sanitize\n"
                "def view(request, cursor):\n"
                "    q = request.args.get('q')\n"
                "    cursor.execute('SELECT * FROM t WHERE id=' + str(sanitize(q)))\n"
            ),
        }
        findings = self._scan_with_context(files, "app.py")
        confirmed_tainted_sql = [
            f for f in findings
            if "SQL" in f.rule_id
            and f.suppression_reason is None
            and f.taint_status == "tainted"
        ]
        assert not confirmed_tainted_sql, (
            "int() sanitizer in remote function must prevent confirmed-TAINTED SQL finding"
        )

    def test_no_cross_file_detection_without_context(self):
        # Without cross-file context the call to process(q) is UNKNOWN, not confirmed-tainted.
        set_cross_file_context({})
        code = (
            "from utils import process\n"
            "def view(request, cursor):\n"
            "    q = request.args.get('q')\n"
            "    cursor.execute('SELECT * FROM t WHERE id=' + process(q))\n"
        )
        findings = AST.analyze("app.py", code)
        high_sql = [
            f for f in findings
            if "SQL" in f.rule_id
            and f.suppression_reason is None
            and f.taint_status == "tainted"
        ]
        assert not high_sql, "without cross-file context, confirmed-taint SQL should not fire"
