"""build_cross_file_summary: parameter propagation through the Phase E/F fixed points."""
import ast

from vulnscanner.analyzers.ast_python import (
    _FuncFacts,
    _collect_scope_assignments,
    build_cross_file_summary,
)


def _summary(files):
    return build_cross_file_summary(files)


# ── Phase E: tainted parameters ───────────────────────────────────────────────

def test_tainted_param_propagates_through_a_call_chain():
    s = _summary({
        "views.py": "def view(request):\n    return fetch(request.args.get('q'))\n",
        "dao.py": "def fetch(term):\n    return lookup(term)\n\ndef lookup(key):\n    return key\n",
    })
    assert s.confirmed_tainted_params["fetch"] == frozenset({0})
    assert s.confirmed_tainted_params["lookup"] == frozenset({0})


def test_constant_argument_is_not_marked_tainted():
    s = _summary({"views.py": "def view(request):\n    return fetch('fixed')\n\ndef fetch(term):\n    return term\n"})
    assert "fetch" not in s.confirmed_tainted_params


def test_each_tainted_argument_position_is_recorded():
    s = _summary({"v.py": "def view(request):\n    return run('a', request.args.get('q'), 'c')\n"})
    assert s.confirmed_tainted_params["run"] == frozenset({1})


def test_qualified_call_uses_the_attribute_name():
    s = _summary({"v.py": "def view(request):\n    return svc.fetch(request.args.get('q'))\n"})
    assert s.confirmed_tainted_params["fetch"] == frozenset({0})


# ── Phase F: parameters that only ever receive CLI-controlled values ──────────

def test_cli_argument_propagates_as_clean():
    s = _summary({"tool.py": (
        "import argparse\n"
        "def main():\n"
        "    args = argparse.ArgumentParser().parse_args()\n"
        "    process(args.path)\n"
        "def process(path):\n"
        "    return helper(path)\n"
        "def helper(p):\n"
        "    return p\n"
    )})
    assert s.confirmed_clean_params["process"] == frozenset({0})
    assert s.confirmed_clean_params["helper"] == frozenset({0})


def test_clean_return_function_lets_clean_values_flow_on():
    s = _summary({"tool.py": (
        "import argparse\n"
        "def run_dir(base):\n"
        "    return base\n"
        "def main():\n"
        "    args = argparse.ArgumentParser().parse_args()\n"
        "    d = run_dir(args.out)\n"
        "    write(d)\n"
        "def write(target):\n"
        "    return target\n"
    )})
    assert s.confirmed_clean_params["write"] == frozenset({0})


def test_function_with_a_non_clean_return_does_not_count_as_clean():
    s = _summary({"tool.py": (
        "import argparse\n"
        "def pick(base, request):\n"
        "    if base:\n"
        "        return base\n"
        "    return request.args.get('x')\n"
        "def main():\n"
        "    args = argparse.ArgumentParser().parse_args()\n"
        "    d = pick(args.out, None)\n"
        "    write(d)\n"
        "def write(target):\n"
        "    return target\n"
    )})
    assert "write" not in s.confirmed_clean_params


# ── the per-function memo ─────────────────────────────────────────────────────

def _func(src):
    return next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef))


def test_func_facts_call_sites_skip_calls_without_arguments():
    f = _func("def f():\n    a()\n    b(1, 2)\n    x.c(3)\n    d.e.g()\n")
    assert [(c, len(a)) for c, a in _FuncFacts().call_sites(f)] == [("b", 2), ("c", 1)]


def test_func_facts_return_values_and_cli_flag():
    f = _func("def f(p):\n    if p:\n        return 1\n    return\n")
    facts = _FuncFacts()
    assert len(facts.return_values(f)) == 1  # a bare `return` has no value
    assert facts.is_cli_entry(f) is False
    g = _func("def g():\n    parser.parse_args()\n")
    assert facts.is_cli_entry(g) is True


def test_func_facts_are_memoised():
    f = _func("def f():\n    a(1)\n")
    facts = _FuncFacts()
    assert facts.call_sites(f) is facts.call_sites(f)


# ── the shared walk in _collect_scope_assignments ─────────────────────────────

def test_scope_assignments_keep_last_write_dead_branches_and_augassign():
    f = _func(
        "def f(request):\n"
        "    mode = 1\n"
        "    if mode == 1:\n"
        "        x = 'live'\n"
        "    else:\n"
        "        x = request.args.get('q')\n"
        "    n = 0\n"
        "    n += 2\n"
        "    d = {}\n"
        "    d['k'] = 'v'\n"
    )
    a = _collect_scope_assignments(f)
    assert isinstance(a["x"], ast.Constant) and a["x"].value == "live"   # dead branch ignored
    assert isinstance(a["n"], ast.Constant) and a["n"].value == 2        # constant fold of +=
    assert ("d", "k") in a                                               # dict-key tracking
