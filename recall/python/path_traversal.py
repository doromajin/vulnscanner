from flask import request


def serve_file(req):
    filename = req.args.get("file")

    # AST-PATH-001: HIGH — open() with tainted variable path
    with open(filename) as f:
        return f.read()


def serve_file_concat(req):
    name = req.args.get("name")

    # AST-PATH-002: HIGH — open() with tainted concatenated path
    with open("/var/data/" + name) as f:
        return f.read()
