import html
from flask import request


def search(cursor, req):
    # html.escape() protects XSS sinks but NOT SQL injection.
    # Taint must propagate as TAINTED → AST-SQL-002: HIGH (not suppressed).
    name = html.escape(req.args.get("name"))
    cursor.execute("SELECT * FROM users WHERE name = " + name)
