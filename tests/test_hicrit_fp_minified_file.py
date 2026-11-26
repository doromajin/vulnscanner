from vulnscanner.analyzers.file_context import is_minified_file


def _closure_like(n: int = 80) -> list[str]:
    # compiler output: mangled names, ~450 chars per line, no blank lines
    return ["K.a%d=function(b){return b+1};" % i * 14 for i in range(n)]


def test_closure_compiled_loader_is_minified_file():
    assert is_minified_file("app/static/loader.js", _closure_like())


def test_handwritten_source_is_not_minified():
    src = ["function handler(req, res) {", "  const v = req.query.x;", "  res.send(v);", "}"] * 2000
    assert not is_minified_file("app/static/handler.js", src)


def test_small_or_non_js_files_are_not_judged():
    assert not is_minified_file("tiny.js", ["x" * 400] * 5)
    assert not is_minified_file("data.txt", _closure_like())


def test_hand_written_eval_in_mostly_short_lines_stays_reportable():
    src = ["var a = 1;"] * 3000 + ["x" * 1000] * 5 + ["eval(userInput);"]
    assert not is_minified_file("app.js", src)
