import requests
from flask import request


def proxy(req):
    url = req.args.get("url")

    # AST-SSRF-001: HIGH — requests.get() with URL from user input
    return requests.get(url)
