from flask import request


def calculate(req):
    expr = req.args.get("expr")
    return eval(expr)  # AST-CMD-003: CRITICAL — eval() with tainted input
