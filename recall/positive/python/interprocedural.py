"""Interprocedural taint: transitive function chains must be detected as CRITICAL."""
import os
import sqlite3
from flask import request


# ── single-hop (already worked before fix) ───────────────────────────────────

def get_user_direct():
    return request.args.get('u')


def handler_direct():
    u = get_user_direct()
    os.system(u)  # AST-CMD-001 CRITICAL


# ── two-hop transitive chain (fixed by fixed-point iteration) ─────────────────

def get_raw():
    return request.args.get('q')


def wrap_raw():
    v = get_raw()
    return v          # transitive: v is TAINTED


def handler_transitive():
    conn = sqlite3.connect(':memory:')
    p = wrap_raw()
    conn.execute("SELECT * FROM t WHERE x = '" + p + "'")  # AST-SQL-001 CRITICAL
