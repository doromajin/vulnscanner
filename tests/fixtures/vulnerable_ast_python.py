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

def path_indirect(request):
    filename = request.args.get("file")
    open(filename)                          # AST-PATH-001 (via taint tracking)

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

# ── insecure deserialization ──────────────────────────────────────────────────

import pickle
import marshal
import yaml

def deser_pickle(data):
    return pickle.loads(data)            # AST-DESER-001

def deser_marshal(data):
    return marshal.loads(data)           # AST-DESER-002

def deser_yaml_unsafe(stream):
    return yaml.unsafe_load(stream)      # AST-DESER-003

def deser_yaml_no_loader(stream):
    return yaml.load(stream)             # AST-DESER-004

def deser_yaml_safe(stream):
    return yaml.safe_load(stream)        # safe

def deser_yaml_with_safe_loader(stream):
    return yaml.load(stream, Loader=yaml.SafeLoader)  # safe

# ── SSRF ──────────────────────────────────────────────────────────────────────

import requests

def ssrf_user_url(request):
    return requests.get(request.args.get("url"))  # AST-SSRF-001

def ssrf_indirect(request):
    url = request.args.get("url")
    return requests.get(url)             # AST-SSRF-001 (via taint tracking)

def ssrf_dynamic_url(endpoint):
    return requests.post(endpoint)       # AST-SSRF-002

def ssrf_safe():
    return requests.get("https://api.internal/health")  # safe — literal

# ── open redirect ─────────────────────────────────────────────────────────────

from flask import redirect, request as flask_req

def redir_user_input(request):
    return redirect(request.args.get("next"))  # AST-REDIR-001

def redir_indirect(request):
    dest = request.args.get("next")
    return redirect(dest)                # AST-REDIR-001 (via taint tracking)

def redir_dynamic(dest):
    return redirect(dest)                # AST-REDIR-002

def redir_safe():
    return redirect("/dashboard")        # safe — literal

# ── server-side template injection ────────────────────────────────────────────

from flask import render_template_string

def ssti_user_template(request):
    tmpl = request.args.get("template")
    return render_template_string(tmpl)  # AST-SSTI-001

def ssti_safe():
    return render_template_string("<h1>Hello</h1>")  # safe — literal

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
