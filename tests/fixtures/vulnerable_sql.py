# Intentionally vulnerable code for testing — do NOT deploy
import sqlite3


def get_user_bad(username):
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")  # SQL-001
    return cur.fetchone()


def get_user_format(username):
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)  # SQL-002
    return cur.fetchone()


def get_user_fstring(username):
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")  # SQL-001
    return cur.fetchone()


def get_user_safe(username):
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))  # safe — parameterized
    return cur.fetchone()
