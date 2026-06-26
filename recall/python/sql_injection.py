from flask import request


def search(cursor, req):
    name = req.args.get("name")
    order_id = req.args.get("id")

    # AST-SQL-001: HIGH — f-string interpolation
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

    # AST-SQL-002: HIGH — string concatenation
    cursor.execute("SELECT * FROM orders WHERE id = " + order_id)
