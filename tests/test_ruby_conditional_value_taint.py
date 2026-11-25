"""Ruby: a conditional used as a value is tainted when any arm is."""
from vulnscanner.analyzers.ast_ruby import RubyASTAnalyzer


def _lines(code, rule="RBAST-REDIR-001"):
    return sorted({f.line_number for f in RubyASTAnalyzer().analyze("app/controllers/x.rb", code) if f.rule_id == rule})


def _action(assign):
    return f"class C < ApplicationController\n  def create\n    {assign}\n    redirect_to path\n  end\nend\n"


def test_ternary_with_tainted_arm_reaches_redirect():
    assert _lines(_action("path = params[:url].present? ? params[:url] : home_path")) == [4]


def test_ternary_tainted_in_else_arm():
    assert _lines(_action("path = flag ? home_path : params[:url]")) == [4]


def test_if_expression_and_modifier_forms():
    assert _lines(_action("path = if flag then params[:url] else home_path end")) == [4]
    assert _lines(_action("path = (params[:url] unless flag)")) == [4]
    assert _lines(_action("path = case flag when 1 then params[:url] else home_path end")) == [4]


def test_ternary_with_literal_arms_is_clean():
    assert _lines(_action("path = params[:url].present? ? '/a' : home_path")) == []


def test_if_with_untainted_branches_is_clean():
    assert _lines(_action("path = if params[:go] then '/a' else '/b' end")) == []
