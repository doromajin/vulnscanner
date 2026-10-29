from __future__ import annotations

import base64
import re
from typing import Iterator

from typing import Callable

from github import Github, GithubException
from github.Repository import Repository

# Scan/skip rules are shared with the local fetcher so a repo gets the same
# coverage whether it is scanned from a checkout or through the GitHub API.
from vulnscanner.fetcher.local import (
    _MAX_FILE_BYTES,
    _SCAN_EXTENSIONS as _LOCAL_SCAN_EXTENSIONS,
    _SCAN_FILENAMES,
    _SKIP_DIRS,
    is_vendored_filename,
)

# `.env` files are matched by name suffix here (committed .env files are findings).
_SCAN_EXTENSIONS = _LOCAL_SCAN_EXTENSIONS | {".env"}


def parse_repo_slug(repo_url: str) -> str:
    """Return ``owner/repo`` from the URL forms people actually paste.

    Accepts ``owner/repo``, ``https://github.com/owner/repo(.git)``, ``www.``
    hosts, ``git@github.com:owner/repo.git`` and deep links such as
    ``.../owner/repo/tree/main/src``.
    """
    s = repo_url.strip()
    s = re.sub(r"^git@github\.com:", "", s)
    s = re.sub(r"^(?:https?://)?(?:www\.)?github\.com/", "", s, flags=re.IGNORECASE)
    parts = [p for p in s.split("/") if p]
    if len(parts) < 2:
        return s.rstrip("/")
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[: -len(".git")]
    return f"{owner}/{name}"


class GitHubFetcher:
    def __init__(self, token: str | None = None) -> None:
        self._gh = Github(token) if token else Github()
        # Paths that could not be read during the last iter_files() run (API
        # errors, undecodable files). Callers report them so a partial scan is
        # never mistaken for a complete one.
        self.skipped: list[str] = []

    def get_repo(self, repo_url: str) -> Repository:
        """Parse a GitHub URL and return the Repository object."""
        return self._gh.get_repo(parse_repo_slug(repo_url))

    def fetch_file(self, repo: Repository, path: str) -> str | None:
        """Return decoded content of a single file, or None if it doesn't exist."""
        try:
            item = repo.get_contents(path)
            return base64.b64decode(item.content).decode("utf-8", errors="replace")
        except Exception:
            return None

    def iter_files(
        self,
        repo: Repository,
        is_excluded: Callable[[str], bool] | None = None,
    ) -> Iterator[tuple[str, str]]:
        """Yield (file_path, content) for every scannable file in the repo.

        *is_excluded* is checked on repo-relative paths before a directory is
        listed or a file is downloaded, so excluded trees cost no API calls.
        """
        excluded = is_excluded or (lambda _p: False)
        self.skipped = []
        try:
            contents = repo.get_contents("")
        except GithubException as exc:
            raise RuntimeError(f"Cannot read repo contents: {exc}") from exc

        stack = list(contents)
        while stack:
            item = stack.pop()
            if item.type == "dir":
                if item.name.lower() in _SKIP_DIRS or excluded(item.path):
                    continue
                try:
                    stack.extend(repo.get_contents(item.path))
                except GithubException as exc:
                    self.skipped.append(f"{item.path}/: cannot list directory ({exc})")
                    continue
            elif item.type == "file":
                if (not any(item.name.endswith(ext) for ext in _SCAN_EXTENSIONS)
                        and item.name not in _SCAN_FILENAMES):
                    continue
                if is_vendored_filename(item.name) or excluded(item.path):
                    continue
                if item.size > _MAX_FILE_BYTES:
                    continue
                try:
                    raw = base64.b64decode(item.content).decode("utf-8", errors="replace")
                    yield item.path, raw
                except Exception as exc:
                    self.skipped.append(f"{item.path}: cannot read file ({exc})")
                    continue
