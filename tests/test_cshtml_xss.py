from vulnscanner.analyzers.cshtml_xss import CshtmlXSSAnalyzer
from vulnscanner.analyzers import ALL_ANALYZERS
from vulnscanner.fetcher.local import _SCAN_EXTENSIONS


def _hits(src: str, path: str = "Views/Home/Index.cshtml"):
    return {(f.rule_id, f.severity.name) for f in CshtmlXSSAnalyzer().analyze(path, src)}


def _lines(src: str, path: str = "Views/Home/Index.cshtml"):
    return [f.line_number for f in CshtmlXSSAnalyzer().analyze(path, src)]


def test_extensions_are_scanned_and_routed():
    assert ".cshtml" in _SCAN_EXTENSIONS and ".razor" in _SCAN_EXTENSIONS
    assert any(isinstance(a, CshtmlXSSAnalyzer) for a in ALL_ANALYZERS)
    assert CshtmlXSSAnalyzer().supports("a/b.razor") and not CshtmlXSSAnalyzer().supports("a.cs")


# --- TP ---
def test_viewdata_and_request_raw_is_high():
    assert ("CSHTML-XSS-001", "HIGH") in _hits('<div>@Html.Raw((string)ViewData["query"])</div>')
    assert ("CSHTML-XSS-001", "HIGH") in _hits('<p>@Html.Raw(Context.Request.Query["q"])</p>')
    assert ("CSHTML-XSS-001", "HIGH") in _hits("<p>@Html.Raw(ViewBag.Msg)</p>")


def test_model_and_loop_variable_raw_is_high():
    assert ("CSHTML-XSS-001", "HIGH") in _hits("<p>@Html.Raw(Model.Comment)</p>", "a.razor")
    assert ("CSHTML-XSS-001", "HIGH") in _hits("@foreach (var item in Model) {\n<p>@Html.Raw(item.Text)</p>\n}")
    assert ("CSHTML-XSS-001", "HIGH") in _hits("<p>@(new HtmlString(Model.Bio))</p>")


def test_multiline_expression_reports_start_line():
    assert _lines("<p>\n@Html.Raw(\n  Model.Body\n)</p>") == [2]


# --- FP ---
def test_auto_encoded_output_and_literals_not_reported():
    assert _hits("<p>@Model.Name @item.Text @(Model.Count + 1)</p>") == set()
    assert _hits('<p>@Html.Raw("<b>hi</b>") @Html.Raw(@"x")</p>') == set()


def test_comments_and_escaped_at_ignored():
    assert _hits("@* @Html.Raw(Model.X) *@") == set()
    assert _hits("<!-- @Html.Raw(Model.X) -->") == set()
    assert _hits("<code>@@Html.Raw(item.Text)</code>") == set()


def test_encoded_values_are_low():
    for expr in ("Html.Encode(Model.X)", "HttpUtility.HtmlEncode(Model.X)", "sanitizer.Sanitize(Model.X)"):
        assert _hits(f"<p>@Html.Raw({expr})</p>") == {("CSHTML-XSS-002", "LOW")}, expr


def test_localised_and_configuration_text_is_not_reported():
    for expr in ('Localizer["Hello"]', 'Configuration["Footer"]', 'Localizer["Hello"].Value'):
        assert _hits(f"<p>@Html.Raw({expr})</p>") == set(), expr


def test_json_in_script_is_medium():
    src = "<script>var m = @Html.Raw(Json.Serialize(Model));</script>"
    assert _hits(src) == {("CSHTML-XSS-003", "MEDIUM")}


# --- FN guard: only the raw one is reported next to safe ones ---
def test_only_raw_reported_among_safe():
    src = '<p>@Model.A</p>' + chr(10) + '<p>@Html.Raw(Model.B)</p>' + chr(10) + '<p>@Model.C</p>'
    assert _lines(src) == [2]


def test_script_block_innerhtml_in_view_is_reported_but_razor_lines_are_not():
    from vulnscanner.analyzers.xss import XSSAnalyzer
    src = chr(10).join(['<script>', " var t = document.querySelector('#a').value;", ' el.innerHTML = `x ${t}`;',
                        '</script>', '<p>@Model.Name</p>'])
    got = XSSAnalyzer().analyze('Pages/Index.cshtml', src)
    assert [f.rule_id for f in got] == ['XSS-001']


def test_local_member_without_content_name_is_low():
    assert _hits('<p>@Html.Raw(style.Tag)</p>') == {('CSHTML-XSS-004', 'LOW')}
