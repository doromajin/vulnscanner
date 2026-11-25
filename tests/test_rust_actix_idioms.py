"""Rust: actix HttpRequest accessors, parse calls and closures keep taint."""
from vulnscanner.analyzers.ast_rust import RustASTAnalyzer


def _rules(src):
    return sorted((f.rule_id, f.line_number) for f in RustASTAnalyzer().analyze("src/main.rs", src))


_CMD = (
    "async fn exec(req: HttpRequest) -> Result<HttpResponse> {\n"
    "    let qs = req.query_string();\n"
    "    let params: HashMap<String, String> = serde_urlencoded::from_str(qs).unwrap_or_default();\n"
    "    let cmd = params.get(\"cmd\").map(|s| s.as_str()).unwrap_or(\"\");\n"
    "    let out = Command::new(\"sh\").arg(cmd).output();\n"
    "    Ok(HttpResponse::Ok().finish())\n}\n"
)


def test_query_string_parse_map_unwrap_chain_reaches_command_arg():
    assert _rules(_CMD) == [("RAST-CMD-001", 5)]


def test_same_chain_reaching_fs_read_is_flagged():
    src = _CMD.replace('Command::new("sh").arg(cmd).output()', "fs::read_to_string(cmd)")
    assert _rules(src) == [("RAST-PATH-001", 5)]


def test_match_info_and_uri_and_headers_are_tainted():
    for acc in ("req.match_info().get(\"f\").unwrap()", "req.uri().path()", "req.headers().get(\"x\").unwrap()"):
        src = ("async fn h(req: HttpRequest) -> Result<HttpResponse> {\n"
               f"    let f = {acc};\n"
               "    let c = fs::read_to_string(f);\n    Ok(HttpResponse::Ok().finish())\n}\n")
        assert _rules(src) == [("RAST-PATH-001", 3)], acc


def test_from_str_and_json_parse_propagate_argument_taint():
    src = ("async fn h(body: String, req: HttpRequest) -> Result<HttpResponse> {\n"
           "    let q = req.query_string();\n"
           "    let v: Foo = serde_json::from_str(q)?;\n"
           "    let c = fs::read_to_string(v.name);\n    Ok(HttpResponse::Ok().finish())\n}\n")
    assert _rules(src) == [("RAST-PATH-001", 4)]


def test_literal_parse_is_clean():
    src = ("async fn h(req: HttpRequest) -> Result<HttpResponse> {\n"
           "    let params: HashMap<String, String> = serde_urlencoded::from_str(\"a=b\").unwrap_or_default();\n"
           "    let cmd = params.get(\"cmd\").map(|s| s.as_str()).unwrap_or(\"\");\n"
           "    let out = Command::new(\"sh\").arg(cmd).output();\n    Ok(HttpResponse::Ok().finish())\n}\n")
    assert _rules(src) == []


def test_closure_that_discards_its_input_is_clean():
    src = ("async fn h(req: HttpRequest) -> Result<HttpResponse> {\n"
           "    let qs = req.query_string();\n"
           "    let cmd = Some(qs).map(|_s| \"ls\").unwrap_or(\"ls\");\n"
           "    let out = Command::new(\"sh\").arg(cmd).output();\n    Ok(HttpResponse::Ok().finish())\n}\n")
    assert _rules(src) == []


def test_non_request_receiver_accessors_are_clean():
    src = ("fn h(cfg: Config) {\n"
           "    let qs = cfg.query_string();\n"
           "    let out = Command::new(\"sh\").arg(qs).output();\n}\n")
    assert _rules(src) == []
