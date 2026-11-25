"""Rust analysis: web-extractor detection by whole type name, destructuring extractors,
field/method propagation, #[cfg(test)] suppression and .rs files being scanned at all."""
from vulnscanner.analyzers.ast_rust import RustASTAnalyzer
from vulnscanner.fetcher.local import _SCAN_EXTENSIONS


def _rules(src):
    return sorted((f.rule_id, f.line_number) for f in RustASTAnalyzer().analyze("src/h.rs", src))


def test_rs_files_are_scanned():
    assert ".rs" in _SCAN_EXTENSIONS


# --- item 1: extractor type detection -------------------------------------------------

def test_axum_path_extractor_param_is_source():
    src = "async fn h(id: Path<String>) {\n    let _ = std::fs::read_to_string(id);\n}\n"
    assert _rules(src) == [("RAST-PATH-001", 2)]


def test_std_path_ref_param_is_not_source():
    src = "fn h(p: &Path) {\n    let _ = std::fs::read_to_string(p);\n}\n"
    assert _rules(src) == []


def test_pathbuf_param_is_not_source():
    src = "fn h(p: PathBuf, q: &PathBuf) {\n    let _ = std::fs::read_to_string(p);\n    let _ = std::fs::read(q);\n}\n"
    assert _rules(src) == []


def test_actix_scoped_web_query_is_source():
    src = "async fn h(q: web::Query<P>) {\n    let _ = std::fs::read_to_string(q);\n}\n"
    assert _rules(src) == [("RAST-PATH-001", 2)]


def test_plain_params_type_name_is_not_source():
    src = "fn h(p: Params) {\n    let _ = std::fs::read_to_string(p);\n}\n"
    assert _rules(src) == []


# --- item 2: destructuring and propagation --------------------------------------------

def test_query_destructuring_taints_inner_name():
    src = "async fn h(Query(p): Query<P>) {\n    let _ = std::fs::read_to_string(p.name);\n}\n"
    assert _rules(src) == [("RAST-PATH-001", 2)]


def test_json_mut_and_form_destructuring():
    src = ("async fn h(Json(mut b): Json<B>, Form(f): Form<F>) {\n"
           "    let _ = std::fs::read_to_string(&b.path);\n"
           "    let _ = std::fs::read(f.name.clone());\n}\n")
    assert _rules(src) == [("RAST-PATH-001", 2), ("RAST-PATH-001", 3)]


def test_nested_tuple_path_destructuring():
    src = "async fn h(Path((a, b)): Path<(String, String)>) {\n    let _ = std::fs::read_to_string(b);\n}\n"
    assert _rules(src) == [("RAST-PATH-001", 2)]


def test_field_method_chain_propagates_to_sql_and_command():
    src = ("async fn h(Query(p): Query<P>) {\n"
           "    let q = format!(\"SELECT * FROM t WHERE n = {}\", p.name.as_str());\n"
           "    sqlx::query(&q);\n"
           "    std::process::Command::new(p.cmd.to_string());\n}\n")
    assert _rules(src) == [("RAST-CMD-001", 4), ("RAST-SQL-001", 3)]


def test_destructured_value_with_literal_sink_is_clean():
    src = "async fn h(Query(p): Query<P>) {\n    let _ = p.name;\n    let _ = std::fs::read_to_string(\"a.txt\");\n}\n"
    assert _rules(src) == []


def test_untainted_field_is_clean():
    src = "fn h(cfg: Config) {\n    let _ = std::fs::read_to_string(cfg.path);\n}\n"
    assert _rules(src) == []


# --- item 3: cfg(test) -----------------------------------------------------------------

def test_cfg_test_module_is_suppressed():
    src = ("#[cfg(test)]\nmod tests {\n    use super::*;\n"
           "    fn t(id: Path<String>) {\n        let _ = std::fs::read_to_string(id);\n    }\n}\n")
    assert _rules(src) == []


def test_test_attribute_function_is_suppressed():
    src = "#[test]\nfn t(id: Path<String>) {\n    let _ = std::fs::read_to_string(id);\n}\n"
    assert _rules(src) == []


def test_non_test_module_still_flagged():
    src = ("mod handlers {\n    pub fn t(id: Path<String>) {\n"
           "        let _ = std::fs::read_to_string(id);\n    }\n}\n")
    assert _rules(src) == [("RAST-PATH-001", 3)]
