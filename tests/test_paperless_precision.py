from vulnscanner.analyzers.ast_python import PythonASTAnalyzer


def _hits(src: str):
    return [(f.rule_id, f.severity.name) for f in PythonASTAnalyzer().analyze("app/views.py", src)
            if f.rule_id == "AST-PATH-004"]


_HEAD = "from pathlib import Path\nfrom django.http import HttpResponse\n\n"


def test_queryset_exists_is_not_a_path_check():
    src = _HEAD + ("def v(request):\n    docs = Document.objects.all()\n"
                   "    if docs.exclude(pk=request.GET['id']).exists():\n        return HttpResponse()\n")
    assert _hits(src) == []


def test_tainted_stat_is_only_a_low_metadata_probe():
    src = _HEAD + "def v(request):\n    p = Path(request.GET['f'])\n    return HttpResponse(p.stat().st_size)\n"
    assert _hits(src) == [("AST-PATH-004", "LOW")]


def test_tainted_read_text_stays_high():
    src = _HEAD + "def v(request):\n    p = Path(request.GET['f'])\n    return HttpResponse(p.read_text())\n"
    assert _hits(src) == [("AST-PATH-004", "HIGH")]


def _ids(src: str, path: str = "app/mod.py"):
    return {(f.rule_id, f.severity.name) for f in PythonASTAnalyzer().analyze(path, src)}


def test_class_import_path_is_not_a_hardcoded_secret():
    assert not any(r == "AST-SEC-001" for r, _ in _ids('TOKEN_STRATEGY = "pkg.adapter.DrfTokenStrategy"\n'))
    assert any(r == "AST-SEC-001" for r, _ in _ids('API_TOKEN = "s3cr3t-value-9f2a"\n'))


_SIGNED = ("import pickle, hmac\n"
           "def loads(data, sig, key):\n"
           "    expected = hmac.new(key, data, 'sha256').digest()\n"
           "    if not hmac.compare_digest(sig, expected):\n        raise ValueError\n"
           "    return pickle.loads(data)\n")
_UNSIGNED = "import pickle\ndef loads(data):\n    return pickle.loads(data)\n"


def test_pickle_after_hmac_verification_is_low():
    assert ("AST-DESER-001", "LOW") in _ids(_SIGNED)


def test_pickle_without_verification_stays_critical():
    assert ("AST-DESER-001", "CRITICAL") in _ids(_UNSIGNED)


def test_e2e_directory_counts_as_test_code():
    from vulnscanner.analyzers.file_context import is_test_path
    assert is_test_path("src-ui/e2e/backend.py")
    assert not is_test_path("src/app/views.py")


def test_token_name_constants_are_not_secrets():
    for line in ("REQUEST_TOKEN = 'request'", "MODULE_TOKEN = '{module}'", "CONSTRAINT_TOKEN_USER = '$user'",
                 "TOKEN_PREFIX = 'nbt_'", "SECRET_KEY_CHARSET = 'abcdefghijklmnopqrstuvwxyz0123'"):
        assert not any(r == "AST-SEC-001" for r, _ in _ids(line + "\n")), line
    assert any(r == "AST-SEC-001" for r, _ in _ids("DB_PASSWORD = 'hunter2hunter2'\n"))


def test_re_search_is_not_an_ldap_filter():
    src = "import re\ndef f(request):\n    v = request.GET['q']\n    return re.search(PATTERN, v)\n"
    assert not any(r == "AST-LDAP-001" for r, _ in _ids(src))
    ldap = ("import ldap3\ndef f(request, conn):\n    u = request.GET['u']\n"
            "    conn.search('dc=x', '(uid=' + u + ')')\n")
    assert any(r == "AST-LDAP-001" for r, _ in _ids(ldap))
