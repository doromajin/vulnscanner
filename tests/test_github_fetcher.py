"""Tests for GitHubFetcher using an in-memory fake repo (no network)."""
import base64

import pytest
from github import GithubException

from vulnscanner import scanner as scanner_mod
from vulnscanner.fetcher.github import GitHubFetcher, parse_repo_slug

_SRC = "import os\nos.system(input())\n"


class _Item:
    def __init__(self, type_, path, content="", size=None):
        self.type = type_
        self.path = path
        self.name = path.rsplit("/", 1)[-1]
        self._raw = content
        self.content = base64.b64encode(content.encode()).decode()
        self.size = len(content) if size is None else size


class _Repo:
    full_name = "o/r"

    def __init__(self, tree, broken_dirs=()):
        self._tree = tree  # dir path -> list[_Item]
        self._broken = set(broken_dirs)
        self.listed: list[str] = []

    def get_contents(self, path):
        self.listed.append(path)
        if path in self._broken:
            raise GithubException(403, {"message": "rate limit exceeded"}, None)
        return self._tree[path]


def _files(fetcher, repo, **kw):
    return {p for p, _ in fetcher.iter_files(repo, **kw)}


def test_scans_same_languages_as_local_fetcher():
    repo = _Repo({"": [_Item("file", "a.c", _SRC), _Item("file", "b.tf", "x"), _Item("file", "c.py", _SRC)]})
    assert _files(GitHubFetcher(), repo) == {"a.c", "b.tf", "c.py"}


def test_skips_vendored_names_but_not_lookalikes():
    repo = _Repo({"": [
        _Item("file", "jquery-3.6.0.js", "x"), _Item("file", "app.min.js", "x"),
        _Item("file", "reactor.py", _SRC),
    ]})
    assert _files(GitHubFetcher(), repo) == {"reactor.py"}


def test_skip_dir_match_is_case_insensitive():
    repo = _Repo({"": [_Item("dir", "Vendor"), _Item("file", "ok.py", _SRC)]})
    assert _files(GitHubFetcher(), repo) == {"ok.py"}
    assert repo.listed == [""]


def test_excluded_dirs_are_not_listed_and_files_not_downloaded():
    big = _Item("file", "big/x.py", _SRC)
    repo = _Repo({"": [_Item("dir", "big"), _Item("file", "keep.py", _SRC)], "big": [big]})
    f = GitHubFetcher()
    assert _files(f, repo, is_excluded=lambda p: p.split("/")[0] == "big") == {"keep.py"}
    assert "big" not in repo.listed


def test_api_error_on_directory_is_recorded_not_silent():
    repo = _Repo(
        {"": [_Item("dir", "src"), _Item("file", "top.py", _SRC)], "src": []},
        broken_dirs=["src"],
    )
    f = GitHubFetcher()
    assert _files(f, repo) == {"top.py"}
    assert len(f.skipped) == 1 and f.skipped[0].startswith("src/")


@pytest.mark.parametrize("url", [
    "owner/repo",
    "https://github.com/owner/repo",
    "https://github.com/owner/repo/",
    "https://github.com/owner/repo.git",
    "http://www.github.com/owner/repo",
    "git@github.com:owner/repo.git",
    "https://github.com/owner/repo/tree/main/src",
])
def test_parse_repo_slug(url):
    assert parse_repo_slug(url) == "owner/repo"


def test_scan_github_reports_incomplete_scan(monkeypatch):
    repo = _Repo(
        {"": [_Item("dir", "src"), _Item("file", "top.py", _SRC)], "src": []},
        broken_dirs=["src"],
    )

    class _Fetcher(GitHubFetcher):
        def __init__(self, token=None):
            super().__init__(None)

        def get_repo(self, url):
            return repo

        def fetch_file(self, repo_, path):
            return None

    monkeypatch.setattr(scanner_mod, "GitHubFetcher", _Fetcher)
    result = scanner_mod.VulnScanner().scan("owner/repo")
    assert any("Skipped (scan incomplete): src/" in e for e in result.errors)
