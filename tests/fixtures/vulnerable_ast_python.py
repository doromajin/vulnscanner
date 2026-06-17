# Intentionally vulnerable Python code for AST analyzer tests — do NOT deploy
import os
import subprocess
import sqlite3

# ── SQL injection ──────────────────────────────────────────────────────────────

def sql_fstring(username):
    conn = sqlite3.connect("db.sqlite3")
    conn.cursor().execute(f"SELECT * FROM users WHERE name = '{username}'")  # AST-SQL-001

def sql_concat(username):
    conn = sqlite3.connect("db.sqlite3")
    conn.cursor().execute("SELECT * FROM users WHERE name = '" + username + "'")  # AST-SQL-002

def sql_percent(username):
    conn = sqlite3.connect("db.sqlite3")
    conn.cursor().execute("SELECT * FROM users WHERE name = '%s'" % username)  # AST-SQL-003

def sql_format(username):
    conn = sqlite3.connect("db.sqlite3")
    conn.cursor().execute("SELECT * FROM users WHERE name = '{}'".format(username))  # AST-SQL-004

def sql_safe(username):
    conn = sqlite3.connect("db.sqlite3")
    conn.cursor().execute("SELECT * FROM users WHERE name = ?", (username,))  # safe — parameterized

# ── command injection ──────────────────────────────────────────────────────────

def cmd_os_system(host):
    os.system("ping " + host)               # AST-CMD-001

def cmd_shell_true(cmd):
    subprocess.run(cmd, shell=True)         # AST-CMD-002

def cmd_eval(user_code):
    eval(user_code)                         # AST-CMD-003

def cmd_exec(user_code):
    exec(user_code)                         # AST-CMD-004

def cmd_safe(host):
    subprocess.run(["ping", host])          # safe — list form, no shell

def cmd_os_system_literal():
    os.system("ls -la")                    # safe — literal constant

# ── path traversal ─────────────────────────────────────────────────────────────

def path_user_input(request):
    open(request.args.get("file"))          # AST-PATH-001 (direct user input)

def path_fstring(filename):
    open(f"uploads/{filename}")             # AST-PATH-002 (f-string)

def path_concat(base, filename):
    open(base + "/" + filename)             # AST-PATH-002 (concat)

def path_safe():
    open("config/settings.json")           # safe — literal

# ── hardcoded secrets ──────────────────────────────────────────────────────────

SECRET_KEY = "s3cr3t-django-key-xyz"       # AST-SEC-001
api_token = "Bearer eyJhbGciOiJIUzI1NiJ9"  # AST-SEC-001
placeholder_password = "your-password-here" # safe — placeholder

# ── false positive checks: these should NOT be detected ───────────────────────

# Pattern appears only inside a string literal — not executable
documentation = """
  Avoid: cursor.execute("SELECT * FROM users WHERE id = " + user_id)
  Use:   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  Never: eval(untrusted_input)
  Also:  os.system(cmd) is dangerous
"""

# .exec() is a JS/Java method — should not trigger CMD-004
class MockRegex:
    def exec(self, text):  # method named exec — NOT standalone exec()
        return text
