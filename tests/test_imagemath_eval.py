from vulnscanner.analyzers.ast_python import PythonASTAnalyzer


def _ids(src: str):
    return {(f.rule_id, f.severity.name) for f in PythonASTAnalyzer().analyze("app/views.py", src)}


_HEAD = "from PIL import Image, ImageMath\n"


def test_imagemath_eval_with_request_expression_is_critical():
    src = _HEAD + "def v(request):\n    e = request.POST['expr']\n    return ImageMath.eval(e, a=1)\n"
    assert ("AST-CMD-006", "CRITICAL") in _ids(src)


def test_imagemath_eval_with_literal_expression_is_not_flagged():
    src = _HEAD + "def v(request):\n    return ImageMath.eval('a+1', a=1)\n"
    assert not any(r == "AST-CMD-006" for r, _ in _ids(src))


def test_lambda_eval_is_not_flagged():
    src = _HEAD + "def v(request):\n    e = request.POST['expr']\n    return ImageMath.lambda_eval(lambda a: a['a'], a=1)\n"
    assert not any(r == "AST-CMD-006" for r, _ in _ids(src))
