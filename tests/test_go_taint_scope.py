"""Go taint is kept per function: a local named like a tainted local elsewhere is its own variable.

What must survive the split: parameters seeded from an in-file caller, package-level vars (shared
by the whole file), func literals sharing the enclosing function's locals, methods, and tainted
function return values.
"""
from vulnscanner.analyzers.ast_go import GoASTAnalyzer

_HEAD = 'package main\nimport ("net/http"; "os/exec")\n'
_SINK = '    exec.Command("sh", "-c", cmd).Run()\n'
_H = "(w http.ResponseWriter, r *http.Request)"


def _lines(code, rule="GOAST-CMD-001"):
    return sorted({f.line_number for f in GoASTAnalyzer().analyze("app/x.go", _HEAD + code) if f.rule_id == rule})


def test_same_name_in_another_function_is_not_tainted():
    code = (f'func a{_H} {{\n    cmd := r.FormValue("c")\n{_SINK}}}\n'
            f'func b{_H} {{\n    cmd := "ls"\n{_SINK}}}\n')
    assert _lines(code) == [5]


def test_callers_tainted_argument_taints_the_callees_parameter():
    code = (f'func a{_H} {{\n    run(r.FormValue("c"))\n}}\n'
            f'func run(cmd string) {{\n{_SINK}}}\n')
    assert _lines(code) == [7]


def test_callee_parameter_stays_clean_when_the_caller_passes_a_literal():
    code = (f'func a{_H} {{\n    run("ls")\n}}\n'
            f'func run(cmd string) {{\n{_SINK}}}\n')
    assert _lines(code) == []


def test_grouped_parameters_are_seeded_by_position():
    code = (f'func a{_H} {{\n    run("x", r.FormValue("c"))\n}}\n'
            f'func run(a, cmd string) {{\n{_SINK}}}\n')
    assert _lines(code) == [7]


def test_method_parameter_is_seeded_by_its_caller():
    code = (f'type S struct{{}}\nfunc a{_H} {{\n    s := S{{}}\n    s.run(r.FormValue("c"))\n}}\n'
            f'func (s S) run(cmd string) {{\n{_SINK}}}\n')
    assert _lines(code) == [9]


def test_package_level_var_is_shared_between_functions():
    code = (f'var cmd string\nfunc a{_H} {{\n    cmd = r.FormValue("c")\n}}\n'
            f'func b() {{\n{_SINK}}}\n')
    assert _lines(code) == [8]


def test_func_literal_shares_the_enclosing_functions_locals():
    code = (f'func a{_H} {{\n    cmd := r.FormValue("c")\n'
            f'    f := func() {{\n    {_SINK.strip()}\n    }}\n    f()\n}}\n')
    assert _lines(code) == [6]


def test_function_that_returns_request_data_taints_its_callers():
    code = (f'func q(r *http.Request) string {{\n    return r.FormValue("c")\n}}\n'
            f'func b() {{\n    cmd := q(nil)\n{_SINK}}}\n')
    assert _lines(code) == [8]


def test_taint_flows_through_a_chain_of_locals_inside_one_function():
    code = f'func a{_H} {{\n    x := r.FormValue("c")\n    y := x\n    cmd := y\n{_SINK}}}\n'
    assert _lines(code) == [7]


def test_local_in_a_callee_does_not_leak_back_to_its_caller():
    code = (f'func a{_H} {{\n    cmd := "ls"\n    run(r.FormValue("c"))\n{_SINK}}}\n'
            f'func run(cmd string) {{\n    _ = cmd\n}}\n')
    assert _lines(code) == []
