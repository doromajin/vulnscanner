"""Rails mass assignment (CWE-915): whole params hash into create/update/new, directly or via a helper."""
from vulnscanner.analyzers.ast_ruby import RubyASTAnalyzer
from vulnscanner.models import VulnType
from vulnscanner.cwe_map import get_cwe_id


def _mass(code):
    return [f for f in RubyASTAnalyzer().analyze("app/controllers/u.rb", code) if f.rule_id == "RBAST-MASS-001"]


def _ctrl(helper, call):
    return f"class UsersController < ApplicationController\n  def act\n    {call}\n  end\n  private\n  def user_params\n    {helper}\n  end\nend\n"


# --- TP ---
def test_direct_params_hash_is_mass_assignment_with_right_type():
    f = _mass("class C\n  def a\n    User.create(params[:user])\n  end\nend\n")
    assert len(f) == 1
    assert f[0].vuln_type == VulnType.MASS_ASSIGNMENT
    assert get_cwe_id("RBAST-MASS-001") == 915


def test_helper_returning_raw_params_new():
    assert len(_mass(_ctrl("params[:user]", "@user = User.new(user_params)"))) == 1


def test_helper_returning_raw_params_update_and_create():
    assert len(_mass(_ctrl("params[:user]", "@user.update(user_params)"))) == 1
    assert len(_mass(_ctrl("params[:user]", "User.create(user_params)"))) == 1


def test_permit_bang_and_unsafe_h_are_unsafe():
    assert len(_mass("class C\n  def a\n    User.create(params.permit!)\n  end\nend\n")) == 1
    assert len(_mass("class C\n  def a\n    User.create(params.to_unsafe_h)\n  end\nend\n")) == 1
    assert len(_mass("class C\n  def a\n    @u.update_attributes(params[:user])\n  end\nend\n")) == 1


# --- FP ---
def test_strong_params_helper_is_clean():
    assert _mass(_ctrl("params.require(:user).permit(:name, :email)", "User.new(user_params)")) == []
    assert _mass(_ctrl("params.permit(:name, :email)", "@user.update(user_params)")) == []


def test_inline_permit_and_explicit_attrs_are_clean():
    assert _mass("class C\n  def a\n    User.create(params.require(:user).permit(:name))\n  end\nend\n") == []
    assert _mass("class C\n  def a\n    User.new(name: params[:name])\n  end\nend\n") == []


# --- FN guard: helper in another method must not taint an unrelated local of the same name ---
def test_local_named_like_clean_helper_stays_clean():
    code = "class C\n  def a\n    user_params = {name: 'x'}\n    User.create(user_params)\n  end\n  def user_params\n    params[:user]\n  end\nend\n"
    assert _mass(code) == []


def test_trailing_comment_in_helper_does_not_hide_the_return_value():
    code = _ctrl("params[:user]\n    # params.require(:user).permit(:name)", "User.new(user_params)")
    assert len(_mass(code)) == 1
