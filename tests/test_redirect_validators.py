from vulnscanner.analyzers.ast_python import PythonASTAnalyzer, set_cross_file_context

_HELPERS = '''
from django.utils.http import url_has_allowed_host_and_scheme

def safe_for_redirect(url):
    return url_has_allowed_host_and_scheme(url, allowed_hosts=None)

class ObjectView:
    def get_return_url(self, request, obj=None):
        url = request.GET.get("return_url")
        if url and safe_for_redirect(url):
            return url
        return "/"
'''


def _redirects(view_src: str, helpers: str = _HELPERS):
    set_cross_file_context({"utils/views.py": helpers, "app/views.py": view_src})
    try:
        return [(f.rule_id, f.severity.name) for f in PythonASTAnalyzer().analyze("app/views.py", view_src)
                if f.rule_id.startswith("AST-REDIR")]
    finally:
        set_cross_file_context({})


_VIEW_HEAD = "from django.shortcuts import redirect\n\n"


def test_redirect_through_a_validating_helper_is_not_reported():
    src = _VIEW_HEAD + "class V(ObjectView):\n    def post(self, request):\n        return redirect(self.get_return_url(request))\n"
    assert _redirects(src) == []


def test_redirect_through_a_variable_set_from_the_helper():
    src = _VIEW_HEAD + ("class V(ObjectView):\n    def post(self, request):\n"
                        "        return_url = self.get_return_url(request)\n        return redirect(return_url)\n")
    assert _redirects(src) == []


def test_unvalidated_helper_is_still_reported():
    helpers = "class ObjectView:\n    def get_return_url(self, request):\n        return request.GET.get('return_url')\n"
    src = _VIEW_HEAD + "class V(ObjectView):\n    def post(self, request):\n        return redirect(self.get_return_url(request))\n"
    assert _redirects(src, helpers) != []


def test_request_param_is_still_reported():
    src = _VIEW_HEAD + "def go(request):\n    return redirect(request.GET['next'])\n"
    assert any(r.startswith("AST-REDIR") for r, _ in _redirects(src))


def test_own_url_forms_are_not_reported():
    for expr in ("obj.get_absolute_url()", "request.get_full_path()", "request.path_info",
                 "resolve_url(settings.LOGOUT_REDIRECT_URL)"):
        src = _VIEW_HEAD + f"def go(request, obj):\n    return redirect({expr})\n"
        assert _redirects(src) == [], expr


def test_redirect_inside_a_validating_if_is_not_reported():
    src = _VIEW_HEAD + ("def go(request):\n    url = request.GET['next']\n"
                        "    if safe_for_redirect(url):\n        return redirect(url)\n    return redirect('/')\n")
    assert _redirects(src) == []


def test_redirect_inside_a_negated_check_is_still_reported():
    src = _VIEW_HEAD + ("def go(request):\n    url = request.GET['next']\n"
                        "    if not safe_for_redirect(url):\n        return redirect(url)\n    return redirect('/')\n")
    assert _redirects(src) != []
