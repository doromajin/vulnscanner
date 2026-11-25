"""Every source extension an analyzer claims must reach it: a file the fetcher drops is never analyzed."""
from vulnscanner.analyzers.ast_js import _JS_AST_EXTS
from vulnscanner.fetcher.local import _SCAN_EXTENSIONS, _SCAN_FILENAMES, LocalFetcher


def test_every_javascript_ast_extension_is_scanned():
    assert set(_JS_AST_EXTS) <= _SCAN_EXTENSIONS


def test_rust_and_csharp_are_scanned():
    assert {".rs", ".cs"} <= _SCAN_EXTENSIONS


def test_php_runtime_version_files_are_scanned():
    assert {"composer.lock", ".php-version"} <= _SCAN_FILENAMES


def test_mjs_file_is_yielded_by_the_local_fetcher(tmp_path):
    (tmp_path / "a.mjs").write_text("export const x = 1;\n", encoding="utf-8")
    assert [p for p, _ in LocalFetcher(str(tmp_path)).iter_files()] == ["a.mjs"]


def test_worktree_copies_are_pruned_by_the_repos_own_ignore_file():
    ignore = (__import__("pathlib").Path(__file__).resolve().parents[1] / ".vulnscannerignore").read_text(encoding="utf-8")
    assert "worktrees/" in ignore
