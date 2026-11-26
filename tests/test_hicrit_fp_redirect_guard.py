from vulnscanner.analyzers.ast_js import JSASTAnalyzer


def _redir(src: str) -> list[int]:
    return [f.line_number for f in JSASTAnalyzer().analyze("app/routes.js", src) if f.rule_id == "JSAST-REDIR-001"]


_HEAD = "const express = require('express');\nconst app = express();\n"

# TP: unvalidated request value into res.redirect
def test_unvalidated_redirect_fires():
    src = _HEAD + "app.get('/l', (req, res) => {\n  const next = req.query.to || '/';\n  res.redirect(next);\n});\n"
    assert _redir(src)


# FP: same-origin guard (leading '/', not '//') ahead of the redirect, negated early-return form
def test_same_origin_early_return_guard_is_safe():
    src = _HEAD + (
        "app.get('/l', (req, res) => {\n"
        "  const next = req.query.to || '/';\n"
        "  if (!next.startsWith('/') || next.startsWith('//')) {\n    return res.redirect('/');\n  }\n"
        "  res.redirect(next);\n});\n"
    )
    assert not _redir(src)


# FP: positive form, redirect inside the guarded branch
def test_same_origin_positive_guard_is_safe():
    src = _HEAD + (
        "app.get('/l', (req, res) => {\n  const next = req.query.to;\n"
        "  if (next.startsWith('/') && !next.startsWith('//')) {\n    res.redirect(next);\n  }\n});\n"
    )
    assert not _redir(src)


# FN guards: a half check ('/' only: '//evil.example' passes) or a guard on another variable stays reported
def test_half_checks_still_fire():
    only_slash = _HEAD + (
        "app.get('/l', (req, res) => {\n  const next = req.query.to;\n"
        "  if (!next.startsWith('/')) {\n    return res.redirect('/');\n  }\n  res.redirect(next);\n});\n"
    )
    assert _redir(only_slash)
    other_var = _HEAD + (
        "app.get('/l', (req, res) => {\n  const next = req.query.to;\n  const ok = '/home';\n"
        "  if (!ok.startsWith('/') || ok.startsWith('//')) {\n    return res.redirect('/');\n  }\n  res.redirect(next);\n});\n"
    )
    assert _redir(other_var)
