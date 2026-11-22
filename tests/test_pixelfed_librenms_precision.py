from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
from vulnscanner.analyzers.file_context import is_vendor_file
from vulnscanner.analyzers.framework_config import FrameworkConfigAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer


def _cmd(src, path="app/Jobs/Video.php"):
    return [(f.rule_id, f.severity.name) for f in CommandInjectionAnalyzer().analyze(path, src)
            if f.rule_id.startswith("CMD-00")]


def test_shell_exec_of_a_variable_without_request_input_is_not_critical():
    src = "<?php\nclass J { function handle() {\n  $bin = config('ffmpeg.bin');\n  $o = shell_exec($bin.' -version');\n} }\n"
    assert _cmd(src) == [("CMD-005", "MEDIUM")]


def test_shell_exec_of_a_variable_in_a_request_file_stays_critical():
    src = "<?php\nclass C { function run(Request $request) {\n  $c = $request->input('c');\n  $o = shell_exec($c);\n} }\n"
    assert ("CMD-005", "CRITICAL") in _cmd(src, "app/Http/Controllers/C.php")


def test_mini_suffix_marks_a_vendored_script():
    assert is_vendor_file("html/js/overlib_mini.js")
    assert is_vendor_file("static/lib.mini.js")
    assert not is_vendor_file("html/js/administration.js")


def _secrets(path, line):
    return [f.rule_id for f in HardcodedSecretsAnalyzer().analyze(path, line + "\n") if f.rule_id == "SEC-001"]


def test_throwaway_ci_database_password_is_not_a_secret():
    line = '          mysql --user="root" --password="root" -e "CREATE DATABASE t"'
    assert _secrets(".github/workflows/web.yml", line) == []


def test_a_real_looking_password_in_a_workflow_is_still_flagged():
    line = '          mysql --user="root" --password="Zq8!vR2mLp0x" -e "CREATE DATABASE t"'
    assert _secrets(".github/workflows/web.yml", line) == ["SEC-001"]


def test_the_same_throwaway_value_in_application_code_is_still_flagged():
    assert _secrets("app/db.py", 'db_password = "root"') == ["SEC-001"]


def test_dotenv_testing_key_is_low_and_a_production_env_is_high():
    key = "APP_KEY=base64:SECRETSECRETSECRET=\nAPP_DEBUG=true\n"
    assert [(f.rule_id, f.severity.name) for f in FrameworkConfigAnalyzer().analyze(".env.testing", key)] == [("CFG-LV-007", "LOW")]
    assert [(f.rule_id, f.severity.name) for f in FrameworkConfigAnalyzer().analyze(".env", key)][0] == ("CFG-LV-007", "HIGH")


def _php(src: str, path="app/Http/Controllers/C.php"):
    from vulnscanner.analyzers.ast_php import PhpASTAnalyzer
    return {f.rule_id for f in PhpASTAnalyzer().analyze(path, src)}


def test_uploaded_file_object_is_not_a_client_chosen_path():
    src = ("<?php\nclass C { function store(Request $request) {\n  $media = $request->file('media');\n"
           "  $data = file_get_contents($media);\n} }\n")
    assert "PHAST-PATH-001" not in _php(src)


def test_a_client_chosen_name_is_still_a_path():
    src = ("<?php\nclass C { function show(Request $request) {\n  $name = $request->input('name');\n"
           "  $data = file_get_contents($name);\n} }\n")
    assert "PHAST-PATH-001" in _php(src)


def test_int_typed_property_is_not_tainted():
    src = ("<?php\nclass C {\n  private int $vlanId;\n  function __construct(Request $request) {\n"
           "    $this->vlanId = $request->input('vlan', 1);\n  }\n  function q() {\n"
           "    return DB::raw(\"x = $this->vlanId\");\n  }\n}\n")
    assert "PHAST-SQL-001" not in _php(src)


def test_untyped_property_still_carries_the_request_value():
    src = ("<?php\nclass C {\n  private $vlanId;\n  function __construct(Request $request) {\n"
           "    $this->vlanId = $request->input('vlan', 1);\n  }\n  function q() {\n"
           "    return DB::raw(\"x = $this->vlanId\");\n  }\n}\n")
    assert "PHAST-SQL-001" in _php(src)


def test_echo_of_a_pdf_body_is_not_xss():
    src = ("<?php\nclass C { function show(Request $request) {\n  $pdf = $request->input('data');\n"
           "  return response()->streamDownload(function () use ($pdf) {\n    echo $pdf;\n"
           "  }, 'a.pdf', ['Content-Type' => 'application/pdf']);\n} }\n")
    assert "PHAST-XSS-001" not in _php(src)


def test_echo_of_request_data_in_an_html_response_is_still_xss():
    src = "<?php\nclass C { function show(Request $request) {\n  $x = $request->input('q');\n  echo $x;\n} }\n"
    assert "PHAST-XSS-001" in _php(src)


def _blade_xss(src: str):
    from vulnscanner.analyzers.xss import XSSAnalyzer
    return {f.severity.name for f in XSSAnalyzer().analyze("resources/views/x.blade.php", "<script>\n" + src + "\n</script>\n")
            if f.rule_id == "XSS-001"}


def test_blade_innerhtml_of_literals_and_escaped_expressions_is_not_a_finding():
    assert _blade_xss("""heading.innerHTML = "{{ ctrans('texts.heading', [], $lang ?? 'en') }}";""") == set()
    assert _blade_xss("""el.innerHTML = '<span>' + '{{ ctrans("texts.status") }}' + '</span>';""") == set()


def test_blade_innerhtml_with_a_js_variable_is_still_a_finding():
    assert _blade_xss("""el.innerHTML = '{{ ctrans("x") }} ' + failedReason;""") != set()
    assert _blade_xss("el.innerHTML = location.hash;") == {"HIGH"}
