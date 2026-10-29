"""Regression tests for the fourth batch of real-OSS false positives (healthchecks, lobsters).
Every class has FP cases that must stay quiet and TP cases that must keep firing."""
import pytest

from vulnscanner.models import Severity


def _py(code, path="views.py"):
    from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
    return PythonASTAnalyzer().analyze(path, code)


def _ids(code, path="views.py"):
    return [f.rule_id for f in _py(code, path)]


class TestSettingsIsServerConfig:
    def test_guarded_doc_path_under_settings_base_dir(self):
        code = (
            "import re\nfrom django.conf import settings\nfrom django.http import Http404\n"
            "def doc(request, name):\n"
            "    if not re.match(r'^[0-9a-z_]+$', name):\n        raise Http404()\n"
            "    path = settings.BASE_DIR / f'templates/docs/{name}.html'\n"
            "    with path.open('r') as f:\n        return f.read()\n"
        )
        assert "AST-PATH-004" not in _ids(code)

    def test_unguarded_request_path_still_flagged(self):
        code = (
            "from pathlib import Path\nfrom django.conf import settings\n"
            "def doc(request):\n    p = settings.BASE_DIR / request.GET['name']\n    return p.read_text()\n"
        )
        assert "AST-PATH-004" in _ids(code)


class TestExistsWithoutPathlib:
    def test_related_manager_exists_not_flagged(self):
        code = "def v(request):\n    return {'last': not request.user.credentials.exists()}\n"
        assert "AST-PATH-004" not in _ids(code)

    def test_pathlib_module_still_flagged(self):
        code = "from pathlib import Path\ndef v(request):\n    return Path(request.GET['p']).exists()\n"
        assert "AST-PATH-004" in _ids(code)


class TestInternalUrlPrefix:
    def test_reverse_plus_suffix_not_flagged(self):
        code = (
            "def v(request, code):\n    url = reverse('checks', args=[code])\n"
            "    url += request.GET.urlencode()\n    return redirect(url)\n"
        )
        assert not {"AST-REDIR-001", "AST-REDIR-002"} & set(_ids(code))

    def test_request_url_with_suffix_still_flagged(self):
        code = "def v(request):\n    url = request.GET['next']\n    url += '/x'\n    return redirect(url)\n"
        assert {"AST-REDIR-001", "AST-REDIR-002"} & set(_ids(code))

    def test_reassigned_after_reverse_still_flagged(self):
        code = (
            "def v(request):\n    url = reverse('home')\n    url = request.GET['next']\n    return redirect(url)\n"
        )
        assert {"AST-REDIR-001", "AST-REDIR-002"} & set(_ids(code))

    def test_prefix_append_before_reverse_is_not_internal(self):
        code = (
            "def v(request):\n    url = reverse('home')\n    url = request.GET['host'] + url\n    return redirect(url)\n"
        )
        assert {"AST-REDIR-001", "AST-REDIR-002"} & set(_ids(code))


class TestWeakRandomContext:
    def _sev(self, code):
        # AST-CRYPTO-002 (weak RNG assigned to a security-named variable) outranks 003 on the same call
        f = [x for x in _py(code) if x.rule_id in ("AST-CRYPTO-002", "AST-CRYPTO-003")]
        assert f
        return {x.severity for x in f}

    def test_jitter_is_low(self):
        code = "import random\ndef next_run(dt):\n    return dt + td(minutes=random.randrange(0, 120))\n"
        assert self._sev(code) == {Severity.LOW}

    @pytest.mark.parametrize("code", [
        "import random\ndef make_token():\n    return ''.join(random.choice('abc') for _ in range(8))\n",
        "import random\ndef f():\n    reset_code = random.randint(100000, 999999)\n    return reset_code\n",
        "import random\ndef generate_session_id():\n    return random.getrandbits(64)\n",
        "import random\ndef f():\n    password = random.choice(WORDS)\n    return password\n",
    ])
    def test_security_context_stays_high(self, code):
        assert self._sev(code) == {Severity.HIGH}


class TestAuthOnWebhooks:
    def _sev(self, code):
        from vulnscanner.analyzers.missing_auth import MissingAuthAnalyzer
        f = [x for x in MissingAuthAnalyzer().analyze("views.py", code) if x.rule_id == "AUTH-001"]
        assert f
        return {x.severity for x in f}

    def test_csrf_exempt_webhook_without_session_is_low(self):
        code = "@csrf_exempt\n@require_POST\ndef hook(request, code):\n    return HttpResponse()\n"
        assert self._sev(code) == {Severity.LOW}

    def test_csrf_exempt_using_session_stays_high(self):
        code = (
            "@csrf_exempt\n@require_POST\ndef hook(request):\n"
            "    request.session['x'] = 1\n    return HttpResponse()\n"
        )
        assert self._sev(code) == {Severity.HIGH}

    def test_plain_post_view_stays_high(self):
        code = "@require_POST\ndef change(request):\n    return HttpResponse()\n"
        assert self._sev(code) == {Severity.HIGH}


class TestRubyScalarParams:
    def _ids(self, code):
        from vulnscanner.analyzers.ast_ruby import RubyASTAnalyzer
        return {f.rule_id for f in RubyASTAnalyzer().analyze("c.rb", code)}

    def _ctl(self, call):
        return f"class C < ApplicationController\n  def show\n    x = {call}\n  end\nend\n"

    @pytest.mark.parametrize("call", ["FlaggedCommenters.new(params[:period])", "Search.new(params[:q])"])
    def test_scalar_param_constructor_not_flagged(self, call):
        assert "RBAST-MASS-001" not in self._ids(self._ctl(call))

    @pytest.mark.parametrize("call", ["User.new(params[:user])", "Story.build(params[:story])"])
    def test_hash_param_constructor_still_flagged(self, call):
        assert "RBAST-MASS-001" in self._ids(self._ctl(call))

    def test_scalar_name_with_update_still_flagged(self):
        code = "class C < ApplicationController\n  def u\n    User.update(params[:id])\n  end\nend\n"
        assert "RBAST-MASS-001" in self._ids(code)


class TestGemfileLockPlatforms:
    LOCK = (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    nokogiri (1.19.4-aarch64-linux-gnu)\n"
        "    nokogiri (1.19.4-arm64-darwin)\n"
        "    nokogiri (1.19.4-x86_64-linux-gnu)\n"
        "    rails (7.1.3)\n"
        "    ffi (1.17.0-java)\n"
        "    ffi (1.17.0)\n\n"
        "PLATFORMS\n  ruby\n"
    )

    def test_platform_suffix_stripped_and_deduplicated(self):
        from vulnscanner.analyzers.dependencies import _parse_gemfile_lock
        pkgs = [(n, v) for n, v, _eco, _ln in _parse_gemfile_lock(self.LOCK)]
        assert pkgs == [("nokogiri", "1.19.4"), ("rails", "7.1.3"), ("ffi", "1.17.0")]


class TestKoelJhipsterFindings:
    def test_static_user_unserialize_not_php_builtin(self):
        from vulnscanner.analyzers.deserialization import DeserializationAnalyzer
        ids = lambda c: {f.rule_id for f in DeserializationAnalyzer().analyze("Cast.php", c)}
        assert "DESER-004" not in ids("return ThemeProperties::unserialize(json_decode($value));\n")
        assert "DESER-004" in ids("$prefs = unserialize($user->preferences);\n")
        assert "DESER-004" in ids(r"$x = \unserialize($_COOKIE['c']);" + "\n")

    def test_build_script_json_file_merge_not_proto_pollution(self):
        from vulnscanner.analyzers.prototype_pollution import PrototypePollutionAnalyzer
        ids = lambda c: {f.rule_id for f in PrototypePollutionAnalyzer().analyze("build.ts", c)}
        assert "PROTO-004" not in ids("merged = deepmerge(merged, JSON.parse(await readFile(src, 'utf-8')));\n")
        assert "PROTO-004" not in ids("cfg = _.merge(base, JSON.parse(fs.readFileSync(p)));\n")
        assert "PROTO-004" in ids("merged = deepmerge(merged, JSON.parse(body));\n")
        assert "PROTO-004" in ids("_.merge(target, req.body);\n")

    def test_service_worker_message_listener_not_flagged(self):
        from vulnscanner.analyzers.client_side import ClientSideAnalyzer
        sw = (
            "self.addEventListener('install', () => self.skipWaiting());\n"
            "self.addEventListener('message', (event) => { use(event.data); });\n"
        )
        ids = lambda c: {f.rule_id for f in ClientSideAnalyzer().analyze("sw.js", c)}
        assert "CLIENT-MSG-001" not in ids(sw)
        assert "CLIENT-MSG-001" in ids("window.addEventListener('message', (e) => { use(e.data); });\n")
