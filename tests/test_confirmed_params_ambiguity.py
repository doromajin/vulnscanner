from vulnscanner.analyzers.ast_python import PythonASTAnalyzer, build_cross_file_summary, set_cross_file_context

_VIEW = ("from django.http import HttpResponse\n"
         "def v(request):\n    return HttpResponse(widget.render(request))\n")


def _xss_severities(columns_src: str, extra: dict[str, str] | None = None):
    files = {"app/views.py": _VIEW, "app/columns.py": columns_src, **(extra or {})}
    set_cross_file_context(files, build_cross_file_summary(files))
    try:
        return [f.severity.name for f in PythonASTAnalyzer().analyze("app/columns.py", columns_src)
                if f.rule_id == "AST-XSS-001"]
    finally:
        set_cross_file_context({}, None)


_COLUMN = ("from django.utils.safestring import mark_safe\n"
           "class Badge:\n    def render(self, value):\n        return mark_safe(f'<b>{value}</b>')\n")
_OTHER = "class Widget:\n    def render(self, request):\n        return ''\n"


def test_same_name_method_elsewhere_does_not_taint_this_one():
    assert "HIGH" not in _xss_severities(_COLUMN, {"app/widgets.py": _OTHER})


def test_unique_method_name_still_receives_the_tainted_argument():
    assert "HIGH" in _xss_severities(_COLUMN)


# A callee that merely receives one tainted argument is not a web entry for its other values.

_CALLER = "def v(request):\n    return lookup(request.GET['q'], settings)\n"


def _sql(lib_src: str):
    files = {"app/views.py": _CALLER, "app/lib.py": lib_src}
    set_cross_file_context(files, build_cross_file_summary(files))
    try:
        return [f.severity.name for f in PythonASTAnalyzer().analyze("app/lib.py", lib_src)
                if f.rule_id.startswith("AST-SQL")]
    finally:
        set_cross_file_context({}, None)


def test_untraced_query_unrelated_to_the_tainted_argument_is_low():
    src = "def lookup(term, cfg):\n    q = build_query(cfg)\n    return db.execute(q)\n"
    sev = _sql(src)
    assert sev and set(sev) == {"LOW"}


def test_query_built_from_the_tainted_argument_is_high():
    src = "def lookup(term, cfg):\n    return db.execute('select * from t where a=' + term)\n"
    assert "HIGH" in _sql(src)


def test_untraced_query_in_a_request_handler_stays_medium():
    src = "def lookup(request, cfg):\n    q = build_query(cfg)\n    return db.execute(q)\n"
    assert "MEDIUM" in _sql(src)
