"""Known limit: Go and JS keep one taint map per file, keyed by variable name.

`cmd` tainted in method `a` makes `cmd = 'ls'` in method `b` look tainted too (PHP had the same
bug until `_build_taint_scoped`).  Each case is a strict xfail: the day a language gets scoped
taint maps, its test starts passing and strict mode forces the marker to be removed.
Ruby (scoped taint map) and Java (per-method effective taint) and Rust are scoped and run as plain tests.
"""
import pytest

from vulnscanner.analyzers.ast_go import GoASTAnalyzer
from vulnscanner.analyzers.ast_java import JavaASTAnalyzer
from vulnscanner.analyzers.ast_js import JSASTAnalyzer
from vulnscanner.analyzers.ast_ruby import RubyASTAnalyzer
from vulnscanner.analyzers.ast_rust import RustASTAnalyzer

# (analyzer, path, source, line of the literal-only sink in the second function)
_CASES = {
    "ruby": (RubyASTAnalyzer, "a.rb",
             "class C\n  def a\n    cmd = params[:c]\n    system(cmd)\n  end\n"
             "  def b\n    cmd = 'ls'\n    system(cmd)\n  end\nend\n", 8),
    "go": (GoASTAnalyzer, "a.go",
           'package main\nimport ("net/http"; "os/exec")\n'
           'func a(w http.ResponseWriter, r *http.Request) {\n    cmd := r.FormValue("c")\n'
           '    exec.Command("sh", "-c", cmd).Run()\n}\n'
           'func b(w http.ResponseWriter, r *http.Request) {\n    cmd := "ls"\n'
           '    exec.Command("sh", "-c", cmd).Run()\n}\n', 9),
    "js": (JSASTAnalyzer, "a.js",
           "const cp = require('child_process');\nfunction a(req, res) {\n  const cmd = req.query.c;\n"
           "  cp.exec(cmd);\n}\nfunction b(req, res) {\n  const cmd = 'ls';\n  cp.exec(cmd);\n}\n", 8),
    "java": (JavaASTAnalyzer, "A.java",
             "import javax.servlet.http.*;\npublic class A {\n"
             "  void a(HttpServletRequest request) throws Exception {\n"
             '    String cmd = request.getParameter("c");\n    Runtime.getRuntime().exec(cmd);\n  }\n'
             "  void b(HttpServletRequest request) throws Exception {\n"
             '    String cmd = "ls";\n    Runtime.getRuntime().exec(cmd);\n  }\n}\n', 9),
    "rust": (RustASTAnalyzer, "a.rs",
             "use std::process::Command;\nfn a() {\n    let cmd = std::env::args().nth(1).unwrap();\n"
             '    Command::new(cmd).spawn();\n}\nfn b() {\n    let cmd = "ls";\n'
             "    Command::new(cmd).spawn();\n}\n", 8),
}


def _flags_second_function(lang):
    cls, path, src, line = _CASES[lang]
    return any(f.line_number == line for f in cls().analyze(path, src))


@pytest.mark.parametrize("lang", ["go", "js"])
@pytest.mark.xfail(strict=True, reason="taint map is per file, keyed by variable name")
def test_taint_in_one_function_does_not_reach_a_literal_in_another(lang):
    assert not _flags_second_function(lang)


@pytest.mark.parametrize("lang", ["ruby", "java", "rust"])
def test_scoped_languages_keep_taint_inside_one_function(lang):
    assert not _flags_second_function(lang)


@pytest.mark.parametrize("lang", ["ruby", "go", "js", "java", "rust"])
def test_the_tainted_function_itself_is_still_flagged(lang):
    cls, path, src, _ = _CASES[lang]
    first_sink = {"ruby": 4, "go": 5, "js": 4, "java": 5, "rust": 4}[lang]
    assert any(f.line_number == first_sink for f in cls().analyze(path, src))
