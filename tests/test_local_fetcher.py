"""Tests for LocalFetcher skip rules."""
from vulnscanner.fetcher.local import LocalFetcher

_SRC = "import os\nos.system(input())\n"


def _scan(root) -> set[str]:
    return {fp for fp, _ in LocalFetcher(str(root)).iter_files()}


def test_root_parent_named_like_skip_dir_is_not_skipped(tmp_path):
    # Regression: a root under .../lib/ or .../build/ used to yield zero files.
    root = tmp_path / "lib" / "build" / "proj"
    root.mkdir(parents=True)
    (root / "a.py").write_text(_SRC)
    assert _scan(root) == {"a.py"}


def test_skip_dir_below_root_is_still_skipped(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "x.py").write_text(_SRC)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "y.py").write_text(_SRC)
    assert _scan(tmp_path) == {"app/y.py"}


def test_unrelated_name_sharing_library_prefix_is_scanned(tmp_path):
    # Regression: reactor.py used to be dropped because it starts with "react".
    (tmp_path / "reactor.py").write_text(_SRC)
    (tmp_path / "angularfire_sync.py").write_text(_SRC)
    assert _scan(tmp_path) == {"reactor.py", "angularfire_sync.py"}


def test_real_vendored_library_names_are_skipped(tmp_path):
    for name in ("jquery.js", "jquery-3.6.0.js", "bootstrap.bundle.js", "react.js"):
        (tmp_path / name).write_text("var x = 1;\n")
    assert _scan(tmp_path) == set()


def test_exclude_predicate_prunes_dirs_and_files(tmp_path):
    (tmp_path / "big").mkdir()
    (tmp_path / "big" / "x.py").write_text(_SRC)
    (tmp_path / "keep.py").write_text(_SRC)
    (tmp_path / "skip_me.py").write_text(_SRC)
    fetcher = LocalFetcher(
        str(tmp_path),
        is_excluded=lambda p: p.split("/")[0] in ("big", "skip_me.py"),
    )
    assert {fp for fp, _ in fetcher.iter_files()} == {"keep.py"}


def test_lib_and_plugins_dirs_are_scanned(tmp_path):
    # Own code often lives in lib/ (Rails) or plugins/ (WordPress).
    for d in ("lib", "libs", "plugins"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "m.py").write_text(_SRC)
    assert _scan(tmp_path) == {"lib/m.py", "libs/m.py", "plugins/m.py"}
