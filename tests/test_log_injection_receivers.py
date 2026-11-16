"""AST-LOG-001: only logging calls are log sinks, not `Response.error(...)`."""
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer

AST = PythonASTAnalyzer()


def _log(call):
    code = "def view(request):\n    x = request.args.get('q')\n    " + call + "\n"
    return [f for f in AST.analyze("views.py", code) if f.rule_id == "AST-LOG-001" and not f.suppression_reason]


# ── false positives: HTTP responses, flash messages ───────────────────────────

def test_response_class_error_is_not_a_log_call():
    assert not _log("return Response.error(f'Unknown action: {x}', 404)")


def test_other_response_classes_are_not_log_calls():
    assert not _log("return JsonResponse.warning(x)")
    assert not _log("return HttpResponses.error([x])")


def test_django_messages_stay_excluded():
    assert not _log("messages.error(request, x)")


# ── true positives: real loggers, whatever they are called ────────────────────

def test_lowercase_logger_is_a_log_sink():
    assert _log("logger.error(x)")
    assert _log("log.warning(x)")


def test_attribute_logger_is_a_log_sink():
    assert _log("self.logger.info(x)")
    assert _log("current_app.logger.warning(x)")


def test_all_caps_logger_is_a_log_sink():
    assert _log("LOGGER.error(x)")


def test_static_logger_classes_are_log_sinks():
    assert _log("Logger.error(x)")
    assert _log("Log.warning(x)")
    assert _log("AppLogger.info(x)")


def test_module_level_logging_function_is_a_log_sink():
    assert _log("logging.error(x)")


def test_untainted_argument_is_never_reported():
    code = "def view(request):\n    logger.error('fixed message')\n"
    assert not [f for f in AST.analyze("views.py", code) if f.rule_id == "AST-LOG-001"]
