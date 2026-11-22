from vulnscanner.fetcher.local import LocalFetcher


def _names(root, **kw):
    return sorted(fp for fp, _ in LocalFetcher(str(root), **kw).iter_files())


def _make(root):
    (root / ".env").write_text("APP_KEY=base64:abc\n", encoding="utf-8")
    (root / ".env.production").write_text("APP_DEBUG=true\n", encoding="utf-8")
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")


def test_dotenv_is_not_scanned_by_default(tmp_path):
    _make(tmp_path)
    assert _names(tmp_path) == ["app.py"]


def test_dotenv_files_are_scanned_with_the_option(tmp_path):
    _make(tmp_path)
    assert _names(tmp_path, include_dotenv=True) == [".env", ".env.production", "app.py"]


def test_cli_exposes_the_option():
    from click.testing import CliRunner
    from vulnscanner.cli import scan
    assert "--include-dotenv" in CliRunner().invoke(scan, ["--help"]).output
