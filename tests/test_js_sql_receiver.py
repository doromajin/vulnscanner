from vulnscanner.analyzers.ast_js import JSASTAnalyzer


def _sql(src: str):
    return [f for f in JSASTAnalyzer().analyze("src/controllers/x.js", src) if f.rule_id == "JSAST-SQL-001"]


def test_generic_query_helper_is_not_sql():
    src = "async function h(req, res) {\n  const w = await activitypub.helpers.query(req.query.handle);\n}\n"
    assert _sql(src) == []


def test_database_named_receiver_is_sql():
    src = "async function h(req, res) {\n  const r = await db.query('select * from t where a=' + req.query.a);\n}\n"
    assert len(_sql(src)) == 1


def test_file_loading_a_database_library_makes_any_receiver_sql():
    src = ("const mysql = require('mysql2');\nasync function h(req, res) {\n"
           "  const r = await store.query('select * from t where a=' + req.query.a);\n}\n")
    assert len(_sql(src)) == 1


def test_prepared_statement_style_receivers_stay_sql():
    src = "function h(req, res) {\n  const rows = stmt.all(req.query.id);\n}\n"
    assert len(_sql(src)) == 1


def _taint_sql(src: str):
    from vulnscanner.analyzers.js_taint import JSTaintAnalyzer
    return [f for f in JSTaintAnalyzer().analyze("src/controllers/x.js", src) if f.rule_id.startswith("JSTAINT-SQL")]


_GENERIC = "async function h(req, res) {\n  const handle = req.query.handle;\n  const w = await activitypub.helpers.query(handle);\n}\n"
_DB = "async function h(req, res) {\n  const id = req.query.id;\n  const r = await db.query(id);\n}\n"


def test_regex_taint_tracker_skips_a_generic_query_helper():
    assert _taint_sql(_GENERIC) == []


def test_regex_taint_tracker_keeps_database_receivers():
    assert len(_taint_sql(_DB)) >= 1
