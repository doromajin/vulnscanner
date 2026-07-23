"""Cross-file taint test — imports taint sources from utils and uses them in sinks."""
import sqlite3
import subprocess
from flask import request
from cross_file_utils import get_search_term, build_clause


def search(conn):
    # Pattern 1: inherent cross-file taint source (get_search_term always returns user input)
    term = get_search_term()
    conn.execute("SELECT * FROM items WHERE name LIKE '" + term + "'")  # AST-SQL-002


def run_cmd():
    # Pattern 2: tainted arg flows through imported passthrough function
    raw = request.args.get("cmd")
    clause = build_clause(raw)
    subprocess.call(clause, shell=True)  # AST-CMD-002
