"""Cross-file taint test — utility module with taint source functions."""
from flask import request


def get_search_term():
    """Inherent taint source: returns user-controlled HTTP parameter."""
    return request.args.get("q", "")


def build_clause(term):
    """Passthrough: propagates taint when term is tainted."""
    return "%" + term + "%"
