from __future__ import annotations

from pathlib import Path
from typing import Iterator

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

# Directory names that are always skipped (exact match on any path component)
_SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".mvn", "bower_components",
    # Common frontend third-party asset dirs inside Java/Rails/etc. projects
    "plugins", "libs", "lib",
}

# Additional path-segment pairs: skip when BOTH parent and child match
# e.g. static/js/jquery → skip; static/js/app → keep
_SKIP_PATH_SEGMENTS = {
    "jquery", "bootstrap", "modernizr", "angular", "react",
    "lodash", "underscore", "backbone", "ember",
}

# Never scan minified bundles — they're unreadable and flood results
_SKIP_FILENAME_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".chunk.js")

_MAX_FILE_BYTES = 500_000


class LocalFetcher:
    def __init__(self, root: str) -> None:
        self._root = Path(root).resolve()

    def ignore_file_path(self) -> Path:
        """Return the path to .vulnscannerignore if it exists in the root."""
        return self._root / ".vulnscannerignore"

    def iter_files(self) -> Iterator[tuple[str, str]]:
        """Yield (relative_path, content) for every scannable file under root."""
        for path in self._root.rglob("*"):
            if not path.is_file():
                continue
            if self._should_skip(path):
                continue
            if path.suffix not in _SCAN_EXTENSIONS and path.name not in _SCAN_FILENAMES:
                continue
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                rel = str(path.relative_to(self._root)).replace("\\", "/")
                yield rel, content
            except Exception:
                continue

    def _should_skip(self, path: Path) -> bool:
        # Skip if any directory component is a known vendor dir
        parts = {p.lower() for p in path.parts}
        if parts & _SKIP_DIRS:
            return True

        # Skip minified/bundled files by filename suffix
        name_lower = path.name.lower()
        if any(name_lower.endswith(s) for s in _SKIP_FILENAME_SUFFIXES):
            return True

        # Skip well-known third-party library filenames
        stem_lower = path.stem.lower()
        if any(stem_lower.startswith(lib) for lib in _SKIP_PATH_SEGMENTS):
            return True

        return False
