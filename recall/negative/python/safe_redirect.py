"""Negative: Flask redirects to hard-coded literal URLs.

AST-REDIR rules fire when the redirect target is tainted (user-controlled).
Literal string arguments resolve to CLEAN — no finding expected.
"""
from flask import redirect


def go_home():
    return redirect("/dashboard")


def go_login():
    return redirect("/auth/login?next=%2F")


def go_external():
    # Full URL literal — still CLEAN (not from user input)
    return redirect("https://docs.example.com/getting-started")


def go_absolute():
    return redirect("https://status.example.com/maintenance")
