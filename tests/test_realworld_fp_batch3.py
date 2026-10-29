"""Regression tests for the third batch of real-OSS false positives
(healthchecks, lobsters, vaultwarden).  Every class has FP cases that must stay quiet and
TP cases that must keep firing."""
from pathlib import Path

import pytest

from vulnscanner.analyzers.custom_rule_analyzer import CustomRuleAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer
from vulnscanner.models import Severity
from vulnscanner.rules.loader import load_rules

_BUILTIN = str(Path(__file__).resolve().parent.parent / "vulnscanner" / "rules" / "builtin")


def _py_ids(code, path="views.py"):
    from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
    return [f.rule_id for f in PythonASTAnalyzer().analyze(path, code)]


class TestXss004PlainTextTemplates:
    def _ids(self, path, code):
        return {f.rule_id for f in XSSAnalyzer().analyze(path, code)}

    def test_plain_text_template_safe_filter_not_flagged(self):
        assert "XSS-004" not in self._ids("integrations/ntfy_title.html", "{{ check.name_then_code|safe }} is {{ status|upper }}\n")

    def test_html_template_safe_filter_still_flagged(self):
        assert "XSS-004" in self._ids("front/page.html", "<p>{{ comment.body|safe }}</p>\n")

    def test_py_mark_safe_left_to_ast_analyzer(self):
        assert "XSS-004" not in self._ids("tags.py", "return mark_safe(value)\n")

    def test_py_format_html_concat_still_flagged(self):
        assert "XSS-004" in self._ids("tags.py", "return format_html('<b>' + name + '</b>')\n")


class TestMarkSafeArguments:
    def test_literal_and_numeric_fstring_not_flagged(self):
        code = (
            "from django.utils.safestring import mark_safe\n"
            "def a():\n    return mark_safe('<div id=\"x\">debug</div>')\n"
            "def b(email):\n    return mark_safe(''.join(f'&#{ord(c)};' for c in email))\n"
        )
        assert "AST-XSS-001" not in _py_ids(code)

    def test_data_in_markup_still_flagged(self):
        code = (
            "from django.utils.safestring import mark_safe\n"
            "def a(request):\n    return mark_safe(request.GET['x'])\n"
            "def b(name):\n    return mark_safe(f'<b>{name}</b>')\n"
        )
        assert _py_ids(code).count("AST-XSS-001") == 2


class TestCsrfExemptReach:
    def _sev(self, code):
        from vulnscanner.analyzers.csrf import CSRFAnalyzer
        f = [x for x in CSRFAnalyzer().analyze("views.py", code) if x.rule_id == "CSRF-001"]
        assert f
        return {x.severity for x in f}

    def test_token_endpoint_is_low(self):
        code = "@csrf_exempt\ndef ping(request, code):\n    check = get(code)\n    return HttpResponse('OK')\n"
        assert self._sev(code) == {Severity.LOW}

    @pytest.mark.parametrize("body", [
        "    if request.user.is_authenticated:\n        pass\n",
        "    request.session['x'] = 1\n",
    ])
    def test_session_view_stays_high(self, body):
        assert self._sev("@csrf_exempt\ndef save(request):\n" + body + "    return HttpResponse()\n") == {Severity.HIGH}

    def test_login_required_view_stays_high(self):
        code = "@csrf_exempt\n@login_required\ndef save(request):\n    return HttpResponse()\n"
        assert self._sev(code) == {Severity.HIGH}

    def test_session_use_in_next_view_does_not_leak(self):
        code = (
            "@csrf_exempt\ndef hook(request):\n    return HttpResponse()\n\n"
            "def other(request):\n    return request.user.name\n"
        )
        assert self._sev(code) == {Severity.LOW}


class TestLogInjectionReceivers:
    def test_django_messages_not_a_log_sink(self):
        code = "def v(request):\n    messages.warning(request, f\"bad {request.GET['a']}\")\n"
        assert "AST-LOG-001" not in _py_ids(code)

    def test_real_logger_still_flagged(self):
        code = "def v(request):\n    logger.warning(request.GET['a'])\n"
        assert "AST-LOG-001" in _py_ids(code)


class TestRedirectTargets:
    def test_reverse_is_internal(self):
        code = "def v(request):\n    return redirect(reverse('home', args=[request.GET['a']]))\n"
        assert not {"AST-REDIR-001", "AST-REDIR-002"} & set(_py_ids(code))

    def test_unvalidated_next_flagged(self):
        assert "AST-REDIR-001" in _py_ids("def v(request):\n    return redirect(request.GET['next'])\n")

    def test_user_defined_validator_guard(self):
        code = (
            "def v(request):\n    n = request.GET.get('next')\n"
            "    if n and _allow_redirect(n):\n        return redirect(n)\n    return redirect('/')\n"
        )
        assert "AST-REDIR-001" not in _py_ids(code)

    def test_unrelated_guard_name_does_not_suppress(self):
        code = (
            "def v(request):\n    n = request.GET.get('next')\n"
            "    if n and is_logged_in(n):\n        return redirect(n)\n"
        )
        assert "AST-REDIR-001" in _py_ids(code)

    def test_regex_rule_ignores_validator_call_name(self):
        from vulnscanner.analyzers.open_redirect import OpenRedirectAnalyzer

        def ids(c):
            return {f.rule_id for f in OpenRedirectAnalyzer().analyze("v.py", c)}

        assert "REDIR-010" not in ids("if _allow_redirect(request.GET.get('next')):\n    pass\n")
        assert "REDIR-010" in ids("return redirect(request.GET.get('next'))\n")


class TestExistsOnQuerysets:
    def test_orm_exists_not_a_path_check(self):
        code = "def v(request, e):\n    return User.objects.filter(email=e).exists()\n"
        assert "AST-PATH-004" not in _py_ids(code)

    def test_tainted_pathlib_exists_still_flagged(self):
        code = "from pathlib import Path\ndef v(request):\n    return Path(request.GET['p']).exists()\n"
        assert "AST-PATH-004" in _py_ids(code)


class TestVendorBundles:
    @pytest.mark.parametrize("path", [
        "src/static/scripts/datatables.js", "static/js/app.min.js", "css/site.min.css",
        "static/select2.full.js", "assets/popper.js",
    ])
    def test_vendor(self, path):
        from vulnscanner.analyzers.file_context import is_vendor_file
        assert is_vendor_file(path)

    @pytest.mark.parametrize("path", ["src/datatable_view.js", "static/js/admin.js", "src/minimal.js", "app/minute.php"])
    def test_not_vendor(self, path):
        from vulnscanner.analyzers.file_context import is_vendor_file
        assert not is_vendor_file(path)


class TestDomSimpleRulesReach:
    def _sev(self, code, rule):
        f = [x for x in XSSAnalyzer().analyze("a.js", code) if x.rule_id == rule]
        assert f
        return {x.severity for x in f}

    def test_insert_adjacent_html_without_source_is_low(self):
        assert self._sev("el.insertAdjacentHTML('beforeend', html);\n", "XSS-006") == {Severity.LOW}

    def test_insert_adjacent_html_with_url_source_keeps_severity(self):
        code = "const q = location.hash;\nel.insertAdjacentHTML('beforeend', q);\n"
        assert self._sev(code, "XSS-006") == {Severity.MEDIUM}


class TestWindowLocationReload:
    def _sev(self, code):
        r = CustomRuleAnalyzer(load_rules([_BUILTIN])).analyze("a.js", code)
        return [x.severity for x in r if x.rule_id == "JS-REDIR-001"]

    def test_self_assignment_reload_not_flagged(self):
        assert self._sev("window.location = window.location.href;\n") == []
        assert self._sev("window.location = location;\n") == []

    def test_real_redirect_still_flagged(self):
        assert self._sev("window.location = target;\n")


class TestRubyMassAssignSession:
    def _ids(self, code):
        from vulnscanner.analyzers.ast_ruby import RubyASTAnalyzer
        return {f.rule_id for f in RubyASTAnalyzer().analyze("c.rb", code)}

    def test_session_value_not_mass_assignment(self):
        code = "class C < ApplicationController\n  def show\n    totp = ROTP::TOTP.new(session[:totp_secret], issuer: 'x')\n  end\nend\n"
        assert "RBAST-MASS-001" not in self._ids(code)

    def test_params_hash_still_flagged(self):
        code = "class C < ApplicationController\n  def create\n    User.create(params[:user])\n  end\nend\n"
        assert "RBAST-MASS-001" in self._ids(code)


class TestTemplateLiteralVariables:
    def _ids(self, code):
        return {f.rule_id for f in XSSAnalyzer().analyze("emails/body.html", code)}

    def test_cycle_defined_literal_not_flagged(self):
        code = "{% cycle '' '</tr><tr>' as trtr silent %}\n<table><tr>{{ trtr|safe }} {% cycle trtr %}</tr></table>\n"
        assert "XSS-004" not in self._ids(code)

    def test_with_defined_literal_not_flagged(self):
        code = "{% with sep='<br>' %}<p>{{ sep|safe }}</p>{% endwith %}\n"
        assert "XSS-004" not in self._ids(code)

    def test_context_variable_still_flagged(self):
        code = "{% cycle '' '</tr><tr>' as trtr silent %}\n<p>{{ comment|safe }} {{ trtr|safe }}</p>\n"
        assert "XSS-004" in self._ids(code)

    def test_other_variable_on_same_line_still_flagged(self):
        code = "{% cycle 'a' 'b' as row silent %}\n<p>{{ row|safe }}{{ body|safe }}</p>\n"
        assert "XSS-004" in self._ids(code)
