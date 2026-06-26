"""Negative: safe SQL patterns — parameterized queries and int()-coerced inputs.

Variable-based patterns are placed inside a function so AST scope tracking works
(module-level assignments are not propagated by the AST analyzer).
"""
import sqlite3
from flask import request

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()

# Parameterized queries — literal query string, no user-controlled interpolation
cursor.execute("SELECT * FROM users WHERE id = ?", (42,))
cursor.execute("SELECT * FROM items WHERE name = ? AND active = ?", ("widget", 1))
cursor.execute("SELECT COUNT(*) FROM config WHERE active = 1")


def safe_query_view():
    # int() is a universal sanitizer → CLEAN; f-string interpolation is safe
    uid = int(request.args.get("id", "0"))
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")

    # bool() coercion → CLEAN
    flag = bool(request.args.get("flag", "0"))
    cursor.execute(f"SELECT * FROM items WHERE visible = {flag}")
