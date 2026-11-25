"""C#: taint handed from a controller / Razor PageModel to an injected service method (cross-file by name + arity)."""
from vulnscanner.analyzers.ast_csharp import (
    CSharpASTAnalyzer,
    build_csharp_cross_file_context,
    set_csharp_cross_file_context,
)

_CTRL = (
    "public class MovieController : ControllerBase {\n"
    "  private readonly IMovieService _movieService;\n"
    "  [HttpGet] public IActionResult Find(string q) {\n"
    "    var r = _movieService.Search(q);\n"
    "    return Ok(r);\n"
    "  }\n"
    "}\n"
)

_SERVICE_RAW = (
    "public class MovieService : IMovieService {\n"
    "  public object Search(string term) {\n"
    '    var sql = "select * from Movies where Title = \'" + term + "\'";\n'
    "    return ctx.Movies.FromSqlRaw(sql).ToList();\n"
    "  }\n"
    "}\n"
)


def _scan(files, target):
    set_csharp_cross_file_context(build_csharp_cross_file_context(files))
    try:
        return [f for f in CSharpASTAnalyzer().analyze(target, files[target]) if f.rule_id == "CSAST-SQL-001"]
    finally:
        set_csharp_cross_file_context(None)


# ── TP ────────────────────────────────────────────────────────────────────────

def test_service_method_receives_taint_from_controller_in_another_file():
    found = _scan({"C.cs": _CTRL, "S.cs": _SERVICE_RAW}, "S.cs")
    assert [f.line_number for f in found] == [4]


def test_taint_follows_a_second_hop_service_to_repository():
    svc = ("public class MovieService {\n"
           "  public object Search(string term) { return repo.Load(term); }\n"
           "}\n")
    repo = ("public class Repo {\n"
            "  public object Load(string name) {\n"
            '    return ctx.Movies.FromSqlRaw($"select * from M where T = \'{name}\'").ToList();\n'
            "  }\n"
            "}\n")
    assert [f.line_number for f in _scan({"C.cs": _CTRL, "S.cs": svc, "R.cs": repo}, "R.cs")] == [3]


def test_razor_bindproperty_is_a_taint_source_for_service_calls():
    page = ("public class IndexModel : PageModel {\n"
            "  [BindProperty] public string Title { get; set; }\n"
            "  public void OnPost() { var m = movieService.Search(Title); }\n"
            "}\n")
    assert len(_scan({"P.cs": page, "S.cs": _SERVICE_RAW}, "S.cs")) == 1


# ── FP ────────────────────────────────────────────────────────────────────────

def test_service_only_called_with_literals_stays_clean():
    ctrl = _CTRL.replace("Search(q)", 'Search("fixed")')
    assert _scan({"C.cs": ctrl, "S.cs": _SERVICE_RAW}, "S.cs") == []


def test_numeric_service_parameter_is_not_seeded():
    ctrl = _CTRL.replace("string q", "int q")
    svc = _SERVICE_RAW.replace("string term", "int term")
    assert _scan({"C.cs": ctrl, "S.cs": svc}, "S.cs") == []


def test_parameterised_service_queries_stay_clean():
    for body in ('ctx.Movies.FromSqlInterpolated($"select * from M where T = {term}")',
                 'conn.Query<Movie>("select * from M where T = @t", new { t = term })',
                 'ctx.Movies.FromSqlRaw("select * from M where T = {0}", term)'):
        svc = f"public class MovieService {{\n  public object Search(string term) {{\n    return {body};\n  }}\n}}\n"
        assert _scan({"C.cs": _CTRL, "S.cs": svc}, "S.cs") == [], body


def test_arity_mismatch_does_not_seed():
    ctrl = _CTRL.replace("Search(q)", "Search(q, 1)")
    assert _scan({"C.cs": ctrl, "S.cs": _SERVICE_RAW}, "S.cs") == []


# ── FN guard: behaviour without any context is unchanged ─────────────────────

def test_service_alone_without_a_caller_is_not_flagged():
    set_csharp_cross_file_context(None)
    assert [f for f in CSharpASTAnalyzer().analyze("S.cs", _SERVICE_RAW) if f.rule_id == "CSAST-SQL-001"] == []


def test_intra_file_service_call_seeds_the_callee():
    both = _CTRL + _SERVICE_RAW
    set_csharp_cross_file_context(None)
    found = [f for f in CSharpASTAnalyzer().analyze("B.cs", both) if f.rule_id == "CSAST-SQL-001"]
    assert len(found) == 1


def test_service_fileinfo_handle_from_call_site_is_not_reported_but_file_read_is():
    svc = ("public class DiskService {\n"
           "  public long Size(string p) { var fi = new FileInfo(p); return fi.Length; }\n"
           "  public string Load(string p) { return File.ReadAllText(p); }\n"
           "}\n")
    ctrl = ("public class DiskController : ControllerBase {\n"
            "  [HttpGet] public IActionResult A(string q) { disk.Size(q); disk.Load(q); return Ok(); }\n"
            "}\n")
    set_csharp_cross_file_context(build_csharp_cross_file_context({"C.cs": ctrl, "S.cs": svc}))
    try:
        found = [f.line_number for f in CSharpASTAnalyzer().analyze("S.cs", svc) if f.rule_id == "CSAST-PATH-001"]
    finally:
        set_csharp_cross_file_context(None)
    assert found == [3]
