"""Negative: safe file-open patterns — literal paths only."""

# Direct literal path arguments — AST resolves these to CLEAN immediately
with open("/etc/hosts") as f:
    content = f.read()

with open("config/settings.json") as f:
    data = f.read()
