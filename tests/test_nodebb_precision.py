from vulnscanner.analyzers.ast_js import JSASTAnalyzer
from vulnscanner.analyzers.open_redirect import OpenRedirectAnalyzer


def _ids(src: str):
    return {f.rule_id for f in JSASTAnalyzer().analyze("src/controllers/x.js", src)}


def _redir(src: str):
    return {f.rule_id for f in OpenRedirectAnalyzer().analyze("src/routes/x.js", src)}


def test_render_data_is_escaped_by_the_template_engine():
    assert "JSAST-XSS-001" not in _ids("function h(req, res) {\n  res.render('chats', { q: req.query.q });\n}\n")


def test_render_with_a_request_chosen_view_stays_flagged():
    assert "JSAST-XSS-001" in _ids("function h(req, res) {\n  res.render(req.query.view, {});\n}\n")


def test_res_send_with_request_data_stays_flagged():
    assert "JSAST-XSS-001" in _ids("function h(req, res) {\n  res.send(req.query.q);\n}\n")


def test_app_layer_call_taking_req_first_is_not_a_nosql_sink():
    assert "JSAST-NOSQL-001" not in _ids("async function h(req, res) {\n  await api.users.deleteMany(req, req.body);\n}\n")
    assert "JSAST-NOSQL-001" in _ids("async function h(req, res) {\n  await db.users.deleteMany(req.body);\n}\n")


def test_redirect_under_a_fixed_prefix_is_not_open_redirect():
    assert "REDIR-006" not in _redir("res.redirect(`${relativePath}/assets/uploads${req.path}`);\n")
    assert "REDIR-006" in _redir("res.redirect(`${req.query.next}/home`);\n")
    assert "REDIR-006" in _redir("res.redirect(`${req.query.next}`);\n")
