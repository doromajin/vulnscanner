from vulnscanner.analyzers.xss import XSSAnalyzer


def _sev(src: str, path: str = "static/app.js"):
    return {f.severity.name for f in XSSAnalyzer().analyze(path, src) if f.rule_id == "XSS-001"}


# FP: the page only WRITES browser-side state (cookie assignment, empty params object for a request,
# handler reset, location redirect); nothing read from the URL/cookie/message reaches the sink.
_WRITES_ONLY = (
    "const q = new URLSearchParams();\n"
    "q.set('a', '1');\n"
    "document.cookie = 'k=v; path=/';\n"
    "ws.onmessage = null;\n"
    "window.location.href = '/next';\n"
    "box.innerHTML = '<b>' + data.content + '</b>';\n"
)


def test_write_only_browser_state_is_not_a_dom_source():
    assert _sev(_WRITES_ONLY) == {"LOW"}


# TP: real reads still make the sink reachable
def test_reads_of_location_and_cookie_stay_high():
    assert _sev("el.innerHTML = location.hash;\n") == {"HIGH"}
    assert _sev("const c = document.cookie;\nel.innerHTML = '<i>' + c + '</i>';\n") == {"HIGH"}
    assert _sev("const p = new URLSearchParams(location.search);\nel.innerHTML = p.x;\n") == {"HIGH"}
    assert _sev("window.addEventListener('message', e => {});\nel.innerHTML = msg;\n") == {"HIGH"}


# FN guard: an input element's value (or the URL) read straight into the sink is HIGH with no other source
def test_input_value_into_sink_is_high():
    assert _sev("out.innerHTML = box.value;\n") == {"HIGH"}
    assert _sev("out.innerHTML = '<p>' + input.value + '</p>';\n") == {"HIGH"}
