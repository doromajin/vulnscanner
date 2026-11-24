"""Ruby taint is kept per method: a local named like a tainted local elsewhere is its own variable.

What must survive the split: parameters seeded from a caller, @ivars and tainted method names
(shared by the whole class/file), the top level of a Sinatra file, and blocks inside a method.
"""
import pytest

from vulnscanner.analyzers.ast_ruby import RubyASTAnalyzer


def _lines(code, rule="RBAST-CMD-001"):
    return sorted({f.line_number for f in RubyASTAnalyzer().analyze("app/x.rb", code) if f.rule_id == rule})


def test_same_name_in_another_method_is_not_tainted():
    code = "class C\n  def a\n    cmd = params[:c]\n    system(cmd)\n  end\n  def b\n    cmd = 'ls'\n    system(cmd)\n  end\nend\n"
    assert _lines(code) == [4]


def test_callers_tainted_argument_taints_the_callees_parameter():
    code = "class C\n  def a\n    run(params[:c])\n  end\n  def run(cmd)\n    system(cmd)\n  end\nend\n"
    assert _lines(code) == [6]


def test_callee_parameter_stays_clean_when_the_caller_passes_a_literal():
    code = "class C\n  def a\n    run('ls')\n  end\n  def run(cmd)\n    system(cmd)\n  end\nend\n"
    assert _lines(code) == []


def test_singleton_method_parameter_is_seeded_by_its_caller():
    code = "class C\n  def a\n    C.run(params[:c])\n  end\n  def self.run(cmd)\n    system(cmd)\n  end\nend\n"
    assert _lines(code) == [6]


def test_instance_variable_is_shared_between_methods():
    code = "class C\n  def set\n    @cmd = params[:c]\n  end\n  def go\n    system(@cmd)\n  end\nend\n"
    assert _lines(code) == [6]


def test_method_that_returns_request_data_taints_its_callers():
    code = "class C\n  def q\n    params[:q]\n  end\n  def go\n    system(q())\n  end\nend\n"
    assert _lines(code) == [6]


def test_sinatra_top_level_route_flow_is_kept():
    code = "get '/x' do\n  cmd = params[:c]\n  system(cmd)\nend\n"
    assert _lines(code) == [3]


def test_block_inside_a_method_shares_its_locals():
    code = "class C\n  def a\n    cmd = params[:c]\n    [1].each do |i|\n      system(cmd)\n    end\n  end\nend\n"
    assert _lines(code) == [5]


def test_taint_flows_through_a_chain_of_locals_inside_one_method():
    code = "class C\n  def a\n    x = params[:c]\n    y = x.strip\n    system(y)\n  end\nend\n"
    assert _lines(code) == [5]


def test_sink_in_a_nested_method_is_judged_in_that_methods_scope():
    code = ("class C\n  def a\n    cmd = params[:c]\n  end\n"
            "  def b(cmd)\n    system(cmd)\n  end\n  def c\n    b('ls')\n  end\nend\n")
    assert _lines(code) == []
