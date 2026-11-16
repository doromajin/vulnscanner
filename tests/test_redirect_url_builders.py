"""AST-REDIR: application URL builders are safe redirect targets; request values are not."""
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer

AST = PythonASTAnalyzer()


def _redir(code):
    return [f for f in AST.analyze("views.py", code)
            if f.rule_id.startswith("AST-REDIR") and not f.suppression_reason]


def _view(body):
    return "def view(self, request, datasette):\n" + "".join(f"    {line}\n" for line in body.splitlines())


# ── false positives: the application builds its own URL ───────────────────────

def test_urls_helper_namespace_is_not_flagged():
    assert not _redir(_view("return Response.redirect(self.ds.urls.instance())"))


def test_urls_helper_with_internal_arguments_is_not_flagged():
    assert not _redir(_view("return Response.redirect(self.ds.urls.table(db.name, 'items'))"))


def test_nested_urls_helpers_are_not_flagged():
    assert not _redir(_view("return Response.redirect(self.ds.urls.path(self.ds.urls.database(db.name)))"))


def test_request_url_for_and_url_path_for_are_not_flagged():
    assert not _redir(_view("return RedirectResponse(request.url_for('home'))"))
    assert not _redir(_view("return RedirectResponse(request.app.url_path_for('home'))"))


def test_builder_prefix_with_appended_query_string_is_not_flagged():
    code = _view(
        "target = datasette.urls.database('main') + '/-/query'\n"
        "target += '?' + request.query_string\n"
        "return Response.redirect(target)"
    )
    assert not _redir(code)


# ── true positives must stay ──────────────────────────────────────────────────

def test_urls_helper_given_a_request_value_is_still_flagged():
    assert _redir(_view("return Response.redirect(self.ds.urls.path(request.args.get('next')))"))


def test_container_named_urls_is_not_a_builder():
    # `data.urls.get('next')` reads a value; it does not build an application URL.
    assert _redir(_view("data = request.args\nreturn Response.redirect(data.urls.get('next'))"))


def test_plain_request_value_is_still_flagged_high():
    findings = _redir(_view("return Response.redirect(request.args.get('next'))"))
    assert findings and findings[0].severity.value == "HIGH"


def test_builder_prefix_overwritten_by_request_value_is_still_flagged():
    code = _view(
        "target = datasette.urls.database('main')\n"
        "target = request.args.get('next')\n"
        "return Response.redirect(target)"
    )
    assert _redir(code)


# ── boolean operands (`a or b`) ───────────────────────────────────────────────

def test_or_with_a_request_value_is_a_confirmed_redirect():
    findings = _redir(_view("return Response.redirect(request.args.get('next') or '/')"))
    assert findings and findings[0].rule_id == "AST-REDIR-001" and findings[0].severity.value == "HIGH"


def test_or_of_a_config_value_and_a_path_stays_needs_review():
    findings = _redir(_view("return Response.redirect(cfg.on_error_redirect or request.path)"))
    assert findings and findings[0].rule_id == "AST-REDIR-002"


def test_or_of_only_safe_values_is_not_flagged():
    assert not _redir(_view("return Response.redirect(request.path or '/home')"))
