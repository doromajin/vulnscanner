from vulnscanner.analyzers.xss import XSSAnalyzer


def _sev(src: str, path: str):
    return {f.severity.name for f in XSSAnalyzer().analyze(path, src) if f.rule_id == "XSS-001"}


_SERVER_DATA = "<script>\nfinalPrice.innerHTML = variant.final.formatted_price;\n</script>\n"
_URL_DATA = "<script>\nel.innerHTML = location.hash;\n</script>\n"


def test_blade_script_without_browser_input_is_low():
    assert _sev(_SERVER_DATA, "views/product.blade.php") == {"LOW"}


def test_blade_script_reading_the_url_stays_high():
    assert _sev(_URL_DATA, "views/product.blade.php") == {"HIGH"}


def test_plain_js_behaviour_is_unchanged():
    assert _sev(_SERVER_DATA, "static/app.js") == {"LOW"}
    assert _sev(_URL_DATA, "static/app.js") == {"HIGH"}
