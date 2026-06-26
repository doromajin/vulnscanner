"""Negative: SQL via f-string where all interpolated values are literals.

When a variable is assigned a string/int literal inside a function, the AST
taint tracker resolves it to CLEAN.  An f-string composed entirely of CLEAN
values produces a CLEAN query — AST-SQL-001/002 must not fire.
"""
import sqlite3
from flask import request

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()


def list_audit_log() -> list:
    # Literal table name assigned inside function — AST resolves to CLEAN
    table = "audit_log"
    cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 100")
    return cursor.fetchall()


def paginate_items() -> list:
    # Both variables are literal strings / ints
    table = "catalog_items"
    limit = 50
    offset = 0
    cursor.execute(f"SELECT id, name FROM {table} LIMIT {limit} OFFSET {offset}")
    return cursor.fetchall()


def safe_coercion_view() -> list:
    # int() is a universal sanitizer — result is always CLEAN regardless of input
    uid = int(request.args.get("id", "0"))
    page = int(request.args.get("page", "1"))
    per_page = 20
    cursor.execute(
        f"SELECT * FROM users WHERE id > {uid} LIMIT {per_page} OFFSET {(page - 1) * per_page}"
    )
    return cursor.fetchall()
