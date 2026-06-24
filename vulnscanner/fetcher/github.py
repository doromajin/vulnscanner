from __future__ import annotations

import base64
from typing import Iterator

from github import Github, GithubException
from github.Repository import Repository


# File extensions worth scanning
_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".php", ".java", ".rb", ".go",
    ".html", ".htm", ".sh",
    ".env", ".yml", ".yaml", ".json", ".config",
}

# Specific filenames to scan regardless of extension (dependency manifests)
_SCAN_FILENAMES = frozenset({
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile", "Pipfile.lock",
    "package.json",
    "Gemfile.lock",
    "go.mod",
})

# Skip directories that are rarely production code
_SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__"}

# Max file size to fetch (bytes) - avoid huge generated files
_MAX_FILE_BYTES = 500_000


class GitHubFetcher:
    def __init__(self, token: str | None = None) -> None:
        self._gh = Github(token) if token else Github()

    def get_repo(self, repo_url: str) -> Repository:
        """Parse a GitHub URL and return the Repository object."""
        # Accept both https://github.com/owner/repo and owner/repo
        slug = repo_url.replace("https://github.com/", "").rstrip("/")
        return self._gh.get_repo(slug)

    def fetch_file(self, repo: Repository, path: str) -> str | None:
        """Return decoded content of a single file, or None if it doesn't exist."""
        try:
            item = repo.get_contents(path)
            return base64.b64decode(item.content).decode("utf-8", errors="replace")
        except Exception:
            return None

    def iter_files(self, repo: Repository) -> Iterator[tuple[str, str]]:
        """Yield (file_path, content) for every scannable file in the repo."""
        try:
            contents = repo.get_contents("")
        except GithubException as exc:
            raise RuntimeError(f"Cannot read repo contents: {exc}") from exc

        stack = list(contents)
        while stack:
            item = stack.pop()
            if item.type == "dir":
                if item.name in _SKIP_DIRS:
                    continue
                try:
                    stack.extend(repo.get_contents(item.path))
                except GithubException:
                    continue
            elif item.type == "file":
                if (not any(item.name.endswith(ext) for ext in _SCAN_EXTENSIONS)
                        and item.name not in _SCAN_FILENAMES):
                    continue
                if item.size > _MAX_FILE_BYTES:
                    continue
                try:
                    raw = base64.b64decode(item.content).decode("utf-8", errors="replace")
                    yield item.path, raw
                except Exception:
                    continue
