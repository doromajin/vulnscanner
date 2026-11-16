"""SQL identifier-quoting helpers and comprehension taint (AST-SQL-00x)."""
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer


def _sql(code, path="views.py"):
    return [f for f in PythonASTAnalyzer().analyze(path, code)
            if f.rule_id.startswith("AST-SQL") and not f.suppression_reason]


# ── FP: quoted identifiers are safe in SQL text ────────────────────────────────

def test_escape_sqlite_in_fstring_is_clean():
    code = '''
async def view(request, db):
    table = request.args.get("table")
    sql = f"select * from {escape_sqlite(table)}"
    return await db.execute(sql)
'''
    assert _sql(code) == []


def test_join_of_quoted_genexp_is_clean():
    code = '''
def view(request, db, columns):
    cols = ", ".join(escape_sqlite(c) for c in columns)
    sql = f"select {cols} from t"
    return db.execute(sql)
'''
    assert _sql(code) == []


def test_django_quote_name_method_is_clean():
    code = '''
def view(request, connection, cursor):
    name = request.GET["col"]
    q = "select %s from t" % connection.ops.quote_name(name)
    cursor.execute(q)
'''
    assert _sql(code) == []


# ── TP: unquoted or mixed input still fires ────────────────────────────────────

def test_unquoted_user_input_still_tainted():
    code = '''
def view(request, db):
    table = request.args.get("table")
    sql = f"select * from {table}"
    return db.execute(sql)
'''
    assert any(f.severity.name == "HIGH" for f in _sql(code))


def test_quoted_table_but_tainted_where_still_tainted():
    code = '''
def view(request, db):
    where = request.args.get("where")
    sql = f"select * from {escape_sqlite('t')} where {where}"
    return db.execute(sql)
'''
    assert any(f.severity.name == "HIGH" for f in _sql(code))


def test_join_of_tainted_genexp_still_tainted():
    code = '''
def view(request, db):
    cols = request.args.getlist("c")
    sql = "select " + ", ".join(c for c in cols) + " from t"
    return db.execute(sql)
'''
    assert any(f.severity.name == "HIGH" for f in _sql(code))


# ── FN guard: genexp of unknown elements stays UNKNOWN, not CLEAN ──────────────

def test_join_of_untracked_genexp_not_clean():
    code = '''
def view(db, columns):
    sql = "select " + ", ".join(c for c in columns) + " from t"
    return db.execute(sql)
'''
    assert _sql(code) != []
