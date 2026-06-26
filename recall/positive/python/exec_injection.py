from flask import request


def run_code(req):
    code = req.args.get("code")
    exec(code)  # AST-CMD-004: CRITICAL — exec() with tainted input
