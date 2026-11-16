"""Findings reached through a cross-file method call must be attributed to the callee's file."""
from vulnscanner.analyzers.ast_python import (
    PythonASTAnalyzer,
    build_cross_file_summary,
    set_cross_file_context,
)

AST = PythonASTAnalyzer()

_MODELS = (
    "class Repo:\n"
    "    def __init__(self, conn):\n"
    "        self.conn = conn\n"
    "\n"
    "    def run(self, q):\n"
    "        # a few lines of padding so that the sink sits well below line 4\n"
    "        # padding\n"
    "        return self.conn.execute('select * from t where a=' + q)\n"
)

_VIEWS = (
    "from models import Repo\n"
    "def view(request, conn):\n"
    "    r = Repo(conn)\n"
    "    return r.run(request.args.get('q'))\n"
)

_SINK_LINE = 8


def _analyze(files, target, prescan=False):
    summary = build_cross_file_summary(files) if prescan else None
    set_cross_file_context(files, summary)
    try:
        return AST.analyze(target, files[target])
    finally:
        set_cross_file_context({})


def _sql(findings):
    return [f for f in findings if f.rule_id.startswith("AST-SQL") and not f.suppression_reason]


def test_method_call_into_another_file_reports_the_callee_location():
    findings = _sql(_analyze({"models.py": _MODELS, "views.py": _VIEWS}, "views.py"))
    assert findings, "the tainted argument reaches execute() in models.py"
    for f in findings:
        assert f.file_path == "models.py", f"attributed to {f.file_path}:{f.line_number}"
        assert f.line_number == _SINK_LINE
        assert "execute" in f.line_content


def test_no_finding_is_placed_past_the_end_of_the_calling_file():
    files = {"models.py": _MODELS, "views.py": _VIEWS}
    n_lines = {fp: len(c.splitlines()) for fp, c in files.items()}
    for prescan in (False, True):
        for f in _analyze(files, "views.py", prescan):
            assert f.line_number <= n_lines[f.file_path], (
                f"{f.rule_id} at {f.file_path}:{f.line_number}, but the file has {n_lines[f.file_path]} lines")


def test_same_file_method_call_still_reports_in_that_file():
    code = (
        "class Repo:\n"
        "    def run(self, conn, q):\n"
        "        return conn.execute('select * from t where a=' + q)\n"
        "def view(request, conn):\n"
        "    return Repo().run(conn, request.args.get('q'))\n"
    )
    findings = _sql(_analyze({"app.py": code}, "app.py"))
    assert findings
    assert {f.file_path for f in findings} == {"app.py"}
    assert 3 in {f.line_number for f in findings}


def test_untainted_argument_into_another_file_reports_nothing_confirmed():
    views = _VIEWS.replace("request.args.get('q')", "'fixed'")
    findings = _sql(_analyze({"models.py": _MODELS, "views.py": views}, "views.py"))
    assert not [f for f in findings if f.taint_status == "tainted"]
