"""Rust: SSRF / open redirect / XSS / SQL sinks (TP, FP, FN trio each)."""
import pytest

from vulnscanner.analyzers.ast_rust import RustASTAnalyzer


def _rules(src):
    return sorted((f.rule_id, f.line_number) for f in RustASTAnalyzer().analyze("src/main.rs", src))


def _h(body, params="req: HttpRequest"):
    return (f"async fn h({params}) -> Result<HttpResponse> {{\n"
            "    let qs = req.query_string();\n"
            "    let p: HashMap<String, String> = serde_urlencoded::from_str(qs).unwrap_or_default();\n"
            "    let u = p.get(\"u\").map(|s| s.as_str()).unwrap_or(\"\");\n"
            f"{body}\n"
            "    Ok(HttpResponse::Ok().finish())\n}\n")


# ---- SSRF (CWE-918) ----
@pytest.mark.parametrize("call", [
    "reqwest::get(u)",
    "reqwest::Client::new().get(u)",
    "reqwest::Client::new().post(u)",
    "client.delete(u)",
    "ureq::get(u)",
    "isahc::get(u)",
    "reqwest::get(format!(\"http://{}/x\", u))",
    "hyper::Request::builder().uri(u)",
    "client.request(Method::GET, u)",
])
def test_ssrf_tp(call):
    assert _rules(_h(f"    let r = {call};")) == [("RAST-SSRF-001", 5)]


@pytest.mark.parametrize("call", [
    "reqwest::get(\"https://example.com/api\")",
    "reqwest::get(format!(\"https://example.com/{}\", 3))",
    "client.get(\"https://example.com\")",
    "p.get(\"u\")",
])
def test_ssrf_fp_literals_clean(call):
    assert _rules(_h(f"    let r = {call};")) == []


def test_ssrf_fn_through_variable_still_found():
    src = _h("    let target = format!(\"{}/v1\", u);\n    let r = ureq::get(&target);")
    assert _rules(src) == [("RAST-SSRF-001", 6)]


# ---- open redirect (CWE-601) ----
@pytest.mark.parametrize("expr", [
    "HttpResponse::Found().header(\"Location\", u).finish()",
    "HttpResponse::Found().insert_header((LOCATION, u)).finish()",
    "HttpResponse::Found().insert_header((header::LOCATION, u)).finish()",
    "web::Redirect::to(u.to_string())",
    "Redirect::temporary(u)",
    "Redirect::permanent(u)",
    "Redirect::to(u)",
])
def test_redirect_tp(expr):
    assert _rules(_h(f"    let r = {expr};")) == [("RAST-REDIR-001", 5)]


@pytest.mark.parametrize("expr", [
    "HttpResponse::Found().header(\"Location\", \"/home\").finish()",
    "Redirect::to(\"/login\")",
    "Redirect::to(format!(\"/home/{}\", u))",
    "HttpResponse::Found().insert_header((LOCATION, format!(\"/a/{}\", u))).finish()",
    "HttpResponse::Ok().header(\"X-Id\", u).finish()",
])
def test_redirect_fp_clean(expr):
    assert _rules(_h(f"    let r = {expr};")) == []


def test_redirect_fn_protocol_relative_prefix_not_exempt():
    assert _rules(_h("    let r = Redirect::to(format!(\"/{}\", u));")) == [("RAST-REDIR-001", 5)]


# ---- XSS (CWE-79) ----
@pytest.mark.parametrize("expr", [
    "HttpResponse::Ok().content_type(\"text/html\").body(format!(\"<h1>{}</h1>\", u))",
    "HttpResponse::Ok().content_type(\"text/html; charset=utf-8\").body(u.to_string())",
    "HttpResponse::Ok().body(format!(\"<p>{}</p>\", u))",
    "Html(format!(\"<b>{}</b>\", u))",
    "Html(format!(\"<b>{u}</b>\"))",
])
def test_xss_tp(expr):
    assert _rules(_h(f"    let r = {expr};")) == [("RAST-XSS-001", 5)]


@pytest.mark.parametrize("expr", [
    "HttpResponse::Ok().content_type(\"application/json\").body(format!(\"{{\\\"q\\\": \\\"{}\\\"}}\", u))",
    "HttpResponse::Ok().json(u)",
    "Json(u)",
    "HttpResponse::Ok().content_type(\"text/html\").body(\"<h1>hi</h1>\")",
    "HttpResponse::Ok().content_type(\"text/html\").body(format!(\"<h1>{}</h1>\", html_escape::encode_text(u)))",
    "HttpResponse::Ok().body(format!(\"count={}\", u))",
])
def test_xss_fp_clean(expr):
    assert _rules(_h(f"    let r = {expr};")) == []


def test_xss_fn_text_plain_is_clean_but_unspecified_html_literal_flags():
    assert _rules(_h("    let r = HttpResponse::Ok().content_type(\"text/plain\").body(format!(\"<{}>\", u));")) == []
    assert _rules(_h("    let r = HttpResponse::Ok().body(format!(\"<i>{}</i>\", u));")) == [("RAST-XSS-001", 5)]


# ---- SQL (CWE-89) ----
@pytest.mark.parametrize("call", [
    "conn.execute(&format!(\"DELETE FROM t WHERE id = {}\", u), [])",
    "conn.query_row(&format!(\"SELECT a FROM t WHERE n = '{}'\", u), [], |r| r.get(0))",
    "conn.prepare(&format!(\"SELECT a FROM t WHERE n = '{}'\", u))",
    "diesel::sql_query(format!(\"SELECT * FROM t WHERE n = '{}'\", u))",
    "sqlx::query_as::<_, User>(&format!(\"SELECT * FROM t WHERE n = '{}'\", u))",
    "sqlx::query_scalar(&format!(\"SELECT n FROM t WHERE n = '{}'\", u))",
    "sqlx::query(&format!(\"SELECT * FROM t WHERE n = '{u}'\"))",
])
def test_sql_tp(call):
    assert _rules(_h(f"    let r = {call};")) == [("RAST-SQL-001", 5)]


@pytest.mark.parametrize("call", [
    "sqlx::query(\"SELECT * FROM t WHERE n = $1\").bind(u)",
    "sqlx::query_as::<_, User>(\"SELECT * FROM t WHERE n = ?\").bind(u)",
    "conn.execute(\"DELETE FROM t WHERE id = ?1\", params![u])",
    "conn.prepare(\"SELECT a FROM t WHERE n = ?1\")",
])
def test_sql_fp_bound_params_clean(call):
    assert _rules(_h(f"    let r = {call};")) == []


def test_sql_string_built_from_json_extractor_without_visible_sink():
    """Login-style handler: a tainted SQL string is built but run through an unseen wrapper."""
    src = ("async fn login(data: web::Json<LoginRequest>) -> Result<HttpResponse> {\n"
           "    let username = &data.username;\n"
           "    let q = format!(\"SELECT * FROM users WHERE username = '{}'\", username);\n"
           "    Ok(HttpResponse::Ok().json(json!({ \"query\": q })))\n}\n")
    assert _rules(src) == [("RAST-SQL-002", 3)]


def test_sql_string_building_clean_cases():
    lit = ("async fn f(data: web::Json<L>) -> Result<HttpResponse> {\n"
           "    let q = format!(\"SELECT * FROM users WHERE id = {}\", 5);\n"
           "    Ok(HttpResponse::Ok().finish())\n}\n")
    assert _rules(lit) == []
    msg = ("async fn f(data: web::Json<L>) -> Result<HttpResponse> {\n"
           "    let q = format!(\"Please select an item from {}\", data.name);\n"
           "    Ok(HttpResponse::Ok().finish())\n}\n")
    assert _rules(msg) == []
