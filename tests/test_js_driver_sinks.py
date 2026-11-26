"""Node DB-driver SQL, code-injection (mathjs / vm / safe-eval) and libxmljs XXE sinks: TP / FP / FN trio."""
from vulnscanner.analyzers.ast_js import JSASTAnalyzer


def _f(src: str, prefix: str):
    return [f for f in JSASTAnalyzer().analyze("src/controllers/x.js", src) if f.rule_id.startswith(prefix)]


def _sql(src):
    return _f(src, "JSAST-SQL")


def _eval(src):
    return _f(src, "JSAST-EVAL")


def _xxe(src):
    return _f(src, "JSAST-XXE")


# ---- SQL: driver call with a built string -------------------------------------------------------

def test_pg_pool_query_concat_of_request_value_is_flagged():
    src = ("const { Pool } = require('pg');\nconst pool = new Pool();\n"
           "async function h(req, res) {\n  const r = await pool.query(\"SELECT * FROM u WHERE n = '\" + req.body.n + \"'\");\n}\n")
    assert len(_sql(src)) == 1


def test_pg_query_with_placeholders_and_values_is_clean():
    src = ("const { Pool } = require('pg');\nconst pool = new Pool();\n"
           "async function h(req, res) {\n  const r = await pool.query('SELECT * FROM u WHERE n = $1', [req.body.n]);\n}\n")
    assert _sql(src) == []


def test_sqlite3_exec_template_is_flagged_with_driver_import():
    src = ("const Database = require('better-sqlite3');\nconst conn = new Database('x.db');\n"
           "function h(req, res) {\n  conn.exec(`DELETE FROM t WHERE id = ${req.query.id}`);\n}\n")
    assert len(_sql(src)) == 1


def test_sqlite3_get_each_flagged_only_with_sqlite_import():
    with_lib = ("const sqlite3 = require('sqlite3');\nconst db = new sqlite3.Database(':memory:');\n"
                "function h(req, res) {\n  db.get('SELECT * FROM t WHERE a = ' + req.query.a, cb);\n}\n")
    without = ("function h(req, res) {\n  cache.get('k' + req.query.a);\n}\n")
    assert len(_sql(with_lib)) == 1
    assert _sql(without) == []


def test_child_process_exec_in_a_file_that_also_loads_pg_is_not_sql():
    src = ("const { Pool } = require('pg');\nconst cp = require('child_process');\n"
           "function h(req, res) {\n  cp.exec('ls ' + req.query.d);\n}\n")
    assert _sql(src) == []


def test_prisma_query_raw_unsafe_is_flagged_but_tagged_template_is_clean():
    bad = "async function h(req, res) {\n  await prisma.$queryRawUnsafe('SELECT * FROM t WHERE a = ' + req.query.a);\n}\n"
    ok = "async function h(req, res) {\n  await prisma.$queryRaw`SELECT * FROM t WHERE a = ${req.query.a}`;\n}\n"
    assert len(_sql(bad)) == 1
    assert _sql(ok) == []


def test_unrelated_query_property_without_driver_is_clean():
    src = "function h(req, res) {\n  const q = window.location.query;\n  foo.run(req.query.a);\n}\n"
    assert _sql(src) == []


# ---- SQL: data-access layer, the request value arrives as a parameter of the helper -------------

_DAL_HEAD = "const { Pool } = require('pg');\nconst pool = new Pool();\nconst COLS = 'id, name';\n"


def test_dal_helper_param_concatenated_into_query_variable_is_flagged():
    src = (_DAL_HEAD + "function login(username, password) {\n"
           "  const q = \"SELECT * FROM users WHERE username = '\" + username + \"' AND p = '\" + password + \"'\";\n"
           "  return pool.query(q);\n}\n")
    assert len(_sql(src)) == 1


def test_dal_helper_param_in_template_literal_is_flagged():
    src = _DAL_HEAD + "function find(term) {\n  return pool.query(`SELECT * FROM p WHERE name ILIKE '%${term}%'`);\n}\n"
    assert len(_sql(src)) == 1


def test_dal_helper_parameterised_and_constant_queries_are_clean():
    src = (_DAL_HEAD + "function a(id) {\n  return pool.query('SELECT * FROM t WHERE id = $1', [id]);\n}\n"
           "function b() {\n  return pool.query('SELECT ' + COLS + ' FROM t');\n}\n"
           "function c(n) {\n  return pool.query('SELECT * FROM t WHERE id = ' + Number(n));\n}\n")
    assert _sql(src) == []


def test_dal_helper_without_driver_import_is_clean():
    src = "function find(term) {\n  return store.query(`SELECT * FROM p WHERE name = '${term}'`);\n}\n"
    assert _sql(src) == []


# ---- code injection -----------------------------------------------------------------------------

def test_mathjs_eval_and_evaluate_of_request_value_are_flagged():
    src = ("const mathjs = require('mathjs');\nfunction h(req, res) {\n  res.json(mathjs.eval(req.body.eqn));\n"
           "  res.json(mathjs.evaluate(req.query.e));\n}\n")
    assert len(_eval(src)) == 2


def test_mathjs_literal_expression_is_clean():
    src = "const math = require('mathjs');\nfunction h(req, res) {\n  res.json(math.evaluate('1 + 2'));\n}\n"
    assert _eval(src) == []


def test_eval_method_without_mathjs_import_is_clean():
    src = "async function h(req, res) {\n  await page.evaluate(req.body.script);\n  calc.eval(req.body.x);\n}\n"
    assert _eval(src) == []


def test_vm_run_in_context_and_script_are_flagged_literals_are_clean():
    bad = ("const vm = require('vm');\nfunction h(req, res) {\n  vm.runInNewContext(req.body.c, {});\n"
           "  const s = new vm.Script(req.body.d);\n  vm.runInThisContext(req.query.e);\n}\n")
    ok = "const vm = require('vm');\nfunction h(req, res) {\n  vm.runInNewContext('1 + 1', {});\n}\n"
    assert len(_eval(bad)) == 3
    assert _eval(ok) == []


def test_safe_eval_of_request_value_is_flagged():
    src = "const safeEval = require('safe-eval');\nfunction h(req, res) {\n  res.send(safeEval(req.body.x));\n}\n"
    assert len(_eval(src)) == 1


# ---- XXE ----------------------------------------------------------------------------------------

def test_libxmljs_noent_with_request_data_is_flagged():
    src = ("const libxmljs = require('libxmljs');\nfunction h(req, res) {\n"
           "  const d = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent: true, noblanks: true});\n}\n")
    assert len(_xxe(src)) == 1


def test_libxmljs_without_noent_or_with_literal_input_is_clean():
    src = ("const libxmljs = require('libxmljs');\nfunction h(req, res) {\n"
           "  libxmljs.parseXml(req.body.x);\n  libxmljs.parseXmlString(req.body.x, {noent: false});\n"
           "  libxmljs.parseXml('<a/>', {noent: true});\n}\n")
    assert _xxe(src) == []


def test_xml2js_and_domparser_are_not_xxe_sinks():
    src = ("const xml2js = require('xml2js');\nfunction h(req, res) {\n  xml2js.parseString(req.body.x, cb);\n"
           "  new DOMParser().parseFromString(req.body.x, 'text/xml');\n}\n")
    assert _xxe(src) == []
