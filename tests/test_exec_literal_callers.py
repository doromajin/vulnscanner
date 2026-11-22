from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer


def _cmd004(src: str):
    return [f for f in CommandInjectionAnalyzer().analyze("src/info.js", src) if f.rule_id == "CMD-004"]


_HELPER = ("const { exec } = require('child_process');\n"
           "async function git() {\n"
           "\tfunction get(cmd, callback) {\n"
           "\t\texec(cmd, (err, out) => callback(null, out));\n"
           "\t}\n"
           "\tconst getAsync = require('util').promisify(get);\n"
           "%s"
           "}\n")


def test_helper_called_only_with_literals_is_not_flagged():
    src = _HELPER % "\tawait getAsync('git rev-parse HEAD');\n\tawait getAsync('git rev-parse --abbrev-ref HEAD');\n"
    assert _cmd004(src) == []


def test_one_variable_caller_keeps_the_finding():
    src = _HELPER % "\tawait getAsync('git rev-parse HEAD');\n\tawait getAsync(req.query.c);\n"
    assert len(_cmd004(src)) == 1


def test_helper_with_no_callers_keeps_the_finding():
    assert len(_cmd004(_HELPER % "")) == 1


def test_plain_exec_of_a_parameter_in_exported_function_keeps_the_finding():
    src = "const { exec } = require('child_process');\nmodule.exports = function run(cmd) {\n\texec(cmd);\n};\n"
    assert len(_cmd004(src)) == 1
