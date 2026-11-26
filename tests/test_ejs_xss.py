from vulnscanner.analyzers.ejs_xss import EjsXSSAnalyzer


def _hits(src: str, path: str = "views/app/products.ejs"):
    return [(f.rule_id, f.severity.name, f.line_number) for f in EjsXSSAnalyzer().analyze(path, src)]


def test_unescaped_user_value_is_high():
    src = "<tr>\n<td><%- output.products[i].name %></td>\n</tr>"
    assert ("EJS-XSS-001", "HIGH", 2) in _hits(src)
    assert ("EJS-XSS-001", "HIGH", 1) in _hits("<b><%- req.query.q %></b>")


def test_escaped_output_comment_and_scriptlet_are_ignored():
    src = "<td><%= output.products[i].name %></td>\n<%# <%- note %> %>\n<% if (x) { %>ok<% } %>"
    assert _hits(src) == []


def test_layout_idioms_are_not_high():
    assert _hits("<%- include('partials/header') %>") == []
    assert _hits("<%- include(vuln_scenario) %>") == []
    assert all(sev == "LOW" for _, sev, _ in _hits("<main><%- body %></main>"))
    assert all(sev == "LOW" for _, sev, _ in _hits("<script>var d = <%- JSON.stringify(data) %>;</script>"))


def test_encoders_downgrade_to_low():
    for expr in ("encodeURIComponent(q)", "escape(name)", "sanitize(html)", "DOMPurify.sanitize(x)"):
        assert all(sev == "LOW" for _, sev, _ in _hits(f"<p><%- {expr} %></p>")), expr


def test_server_constants_are_medium_and_literals_ignored():
    assert all(sev == "MEDIUM" for _, sev, _ in _hits("<link href=\"<%- config.assetUrl %>\">"))
    assert _hits("<%- '<hr>' %>") == []


def test_non_ejs_extension_not_handled():
    assert EjsXSSAnalyzer().supports("views/a.ejs")
    assert not EjsXSSAnalyzer().supports("views/a.js")
