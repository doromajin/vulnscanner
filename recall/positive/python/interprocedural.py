"""Interprocedural taint: transitive function chains must be detected."""
import os
import sqlite3
from flask import request


# ── single-hop (already worked before fix) ───────────────────────────────────

def get_user_direct():
    return request.args.get('u')


def handler_direct():
    u = get_user_direct()
    os.system(u)  # AST-CMD-001 HIGH


# ── two-hop transitive chain (fixed by fixed-point iteration) ─────────────────

def get_raw():
    return request.args.get('q')


def wrap_raw():
    v = get_raw()
    return v          # transitive: v is TAINTED


def handler_transitive():
    conn = sqlite3.connect(':memory:')
    p = wrap_raw()
    conn.execute("SELECT * FROM t WHERE x = '" + p + "'")  # AST-SQL-002 HIGH


# ── self.method() inherent taint (Phase 3a) ──────────────────────────────────

class UserView:
    def _get_id(self):
        return request.args.get('id')

    def get(self):
        uid = self._get_id()  # Phase 3a: self._get_id in _interprocedural_taint_sources
        conn = sqlite3.connect(':memory:')
        conn.execute("SELECT * FROM users WHERE id=" + uid)  # AST-SQL-002 HIGH


# ── self.method(tainted_arg) passthrough (Phase 3b) ──────────────────────────

class Processor:
    def _wrap(self, x):
        return x  # passthrough

    def handle(self):
        name = request.form.get('name')
        result = self._wrap(name)   # Phase 3b: tainted arg flows through _wrap
        os.system(result)           # AST-CMD-001 HIGH
