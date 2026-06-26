from jinja2 import Environment
from flask import request


def render_template(req):
    env = Environment()
    tmpl_src = req.args.get("template")

    # AST-SSTI-002: HIGH — Environment.from_string() with non-literal source
    return env.from_string(tmpl_src).render()
