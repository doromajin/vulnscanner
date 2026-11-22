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
