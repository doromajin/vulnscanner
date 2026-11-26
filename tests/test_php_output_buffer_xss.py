"""A request value concatenated into an HTML buffer variable ($html .= '<pre>' . $_GET['x'] . '</pre>').

Single file: the buffer reaching echo / print / heredoc / return is HIGH (PHAST-XSS-001).
Cross file (view echoes $html defined in an included file): MEDIUM at the assignment (PHAST-XSS-002).
Encoders and numeric casts suppress.
"""
from vulnscanner.analyzers.ast_php import PhpASTAnalyzer

_PATH = "vulnerabilities/xss_r/source/low.php"


def _hits(php: str) -> set[tuple[str, str]]:
    return {(f.rule_id, f.severity.name) for f in PhpASTAnalyzer().analyze(_PATH, php)}


def test_buffer_assignment_without_output_is_medium():
    php = "<?php\nif (isset($_GET['name'])) {\n    $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';\n}\n"
    assert ("PHAST-XSS-002", "MEDIUM") in _hits(php)


def test_buffer_echoed_in_same_file_is_high():
    php = "<?php\n$html .= '<p>' . $_POST['m'] . '</p>';\necho $html;\n"
    assert ("PHAST-XSS-001", "HIGH") in _hits(php)
    php = "<?php\n$out = '<p>' . $_GET['m'] . '</p>';\nprint $out;\n"
    assert ("PHAST-XSS-001", "HIGH") in _hits(php)


def test_heredoc_and_interpolated_output_is_high():
    php = "<?php\n$html .= '<b>' . $_GET['a'] . '</b>';\necho <<<EOT\n<div>{$html}</div>\nEOT;\n"
    assert ("PHAST-XSS-001", "HIGH") in _hits(php)
    php = "<?php\n$html = '<b>' . $_GET['a'] . '</b>';\necho \"<div>$html</div>\";\n"
    assert ("PHAST-XSS-001", "HIGH") in _hits(php)


def test_returned_buffer_is_reported():
    php = "<?php\nfunction render() {\n    $html = '<b>' . $_GET['a'] . '</b>';\n    return $html;\n}\n"
    assert _hits(php) & {("PHAST-XSS-001", "HIGH"), ("PHAST-XSS-002", "MEDIUM")}


def test_encoded_or_cast_values_are_ignored():
    for expr in ("htmlspecialchars($_GET['n'])", "htmlentities($_GET['n'], ENT_QUOTES)",
                 "esc_html($_GET['n'])", "intval($_GET['n'])", "(int) $_GET['n']"):
        php = f"<?php\n$html .= '<pre>Hello ' . {expr} . '</pre>';\necho $html;\n"
        assert not {h for h in _hits(php) if h[0].startswith("PHAST-XSS")}, expr


def test_non_markup_or_non_buffer_names_are_ignored():
    assert not {h for h in _hits("<?php\n$id = 'x' . $_GET['n'];\n") if h[0].startswith("PHAST-XSS")}
    assert not {h for h in _hits("<?php\n$html .= 'plain text only';\n") if h[0].startswith("PHAST-XSS")}
    assert not {h for h in _hits("<?php\n$html .= 'Hello ' . $_GET['n'];\n") if h[0] == "PHAST-XSS-002"}
