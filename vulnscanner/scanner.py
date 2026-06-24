from __future__ import annotations

import fnmatch
import re
import time

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from vulnscanner.analyzers import ALL_ANALYZERS, BaseAnalyzer
from vulnscanner.analyzers.file_context import (
    INCLUDE_TEST_FILES,
    INCLUDE_VENDOR_FILES,
    classify_file_context,
)
from vulnscanner.fetcher.github import GitHubFetcher
from vulnscanner.fetcher.local import LocalFetcher
from vulnscanner.models import Finding, ScanResult

# Matches:  # vulnscanner: ignore  or  // vulnscanner: ignore[XSS-001,SQL-001]
_SUPPRESS_RE = re.compile(
    r"(?:#|//|<!--)\s*vulnscanner\s*:\s*ignore(?:\[([A-Z0-9,\s_-]+)\])?",
    re.IGNORECASE,
)


def _parse_ignore_file(content: str) -> list[str]:
    """Parse a .vulnscannerignore file - one glob pattern per line, # for comments."""
    patterns = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _is_excluded(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Return True if *path* matches any of the given glob patterns."""
    norm = path.replace("\\", "/")
    for pat in patterns:
        # Bare pattern without path separator matches against filename only
        if "/" not in pat and "\\" not in pat:
            if fnmatch.fnmatch(norm.rsplit("/", 1)[-1], pat):
                return True
        else:
            if fnmatch.fnmatch(norm, pat):
                return True
            # Allow directory-style pattern: "tests/" matches "tests/foo.py"
            pat_norm = pat.rstrip("/")
            for part in norm.split("/"):
                if fnmatch.fnmatch(part, pat_norm):
                    return True
    return False


class VulnScanner:
    def __init__(
        self,
        github_token: str | None = None,
        analyzers: list[BaseAnalyzer] | None = None,
        exclude: tuple[str, ...] | list[str] = (),
    ) -> None:
        self._github_token = github_token
        self._analyzers = analyzers or ALL_ANALYZERS
        self._cli_excludes = tuple(exclude)

    def scan(self, target: str) -> ScanResult:
        """Scan a GitHub repo URL/slug or a local directory path."""
        import os
        if os.path.isdir(target):
            return self._scan_local(target)
        return self._scan_github(target)

    def _scan_github(self, repo_url: str) -> ScanResult:
        result = ScanResult(repo_url=repo_url)
        fetcher = GitHubFetcher(token=self._github_token)

        try:
            repo = fetcher.get_repo(repo_url)
        except Exception as exc:
            result.errors.append(str(exc))
            return result

        # Load project-level exclusions from .vulnscannerignore
        ignore_content = fetcher.fetch_file(repo, ".vulnscannerignore")
        excludes = list(self._cli_excludes) + (
            _parse_ignore_file(ignore_content) if ignore_content else []
        )

        start = time.perf_counter()
        with Progress(
            SpinnerColumn("line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            redirect_stderr=False,
        ) as progress:
            task = progress.add_task(f"Scanning {repo.full_name}...", total=None)
            for file_path, content in fetcher.iter_files(repo):
                if _is_excluded(file_path, excludes):
                    continue
                progress.update(task, description=f"[cyan]{file_path}")
                self._analyze_file(file_path, content, repo_url, result)

        result.elapsed_seconds = time.perf_counter() - start
        return result

    def _scan_local(self, directory: str) -> ScanResult:
        result = ScanResult(repo_url=directory)
        fetcher = LocalFetcher(directory)

        # Load project-level exclusions from .vulnscannerignore
        ignore_path = fetcher.ignore_file_path()
        if ignore_path and ignore_path.exists():
            ignore_content = ignore_path.read_text(encoding="utf-8", errors="replace")
            excludes = list(self._cli_excludes) + _parse_ignore_file(ignore_content)
        else:
            excludes = list(self._cli_excludes)

        start = time.perf_counter()
        with Progress(
            SpinnerColumn("line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            redirect_stderr=False,
        ) as progress:
            task = progress.add_task(f"Scanning {directory}...", total=None)
            for file_path, content in fetcher.iter_files():
                if _is_excluded(file_path, excludes):
                    continue
                progress.update(task, description=f"[cyan]{file_path}")
                self._analyze_file(file_path, content, directory, result)

        result.elapsed_seconds = time.perf_counter() - start
        return result

    def _analyze_file(
        self, file_path: str, content: str, source: str, result: ScanResult
    ) -> None:
        result.scanned_files += 1
        result.scanned_lines += content.count("\n") + 1
        lines = content.splitlines()

        raw: list = []
        for analyzer in self._analyzers:
            if not analyzer.supports(file_path):
                continue
            try:
                raw.extend(analyzer.analyze(file_path, content, source))
            except Exception as exc:
                result.errors.append(f"{file_path}: {exc}")

        # Inline-comment suppression (# vulnscanner: ignore)
        inline_suppressed = [f for f in raw if _is_suppressed(f, lines)]
        result.suppressed_count += len(inline_suppressed)
        raw = [f for f in raw if not _is_suppressed(f, lines)]

        # File-context suppression (test / fixture / vendor paths)
        ctx_reason = _context_suppression_reason(file_path)
        if ctx_reason:
            for f in raw:
                f.suppression_reason = ctx_reason
            result.suppressed_count += len(raw)
            return  # none of these findings reach result.findings

        result.findings.extend(_deduplicate(raw))


def _context_suppression_reason(file_path: str) -> str | None:
    """Return the suppression reason for *file_path*, or None if not suppressed."""
    ctx = classify_file_context(file_path)
    if not INCLUDE_TEST_FILES and (ctx["is_test"] or ctx["is_fixture"]):
        return ctx["reason"]
    if not INCLUDE_VENDOR_FILES and ctx["is_vendor"]:
        return ctx["reason"]
    return None


def _is_suppressed(finding: Finding, lines: list[str]) -> bool:
    """Return True if the finding's line (or the line above) carries a suppression comment."""
    lineno = finding.line_number  # 1-based
    for i in (lineno - 1, lineno - 2):
        if 0 <= i < len(lines):
            m = _SUPPRESS_RE.search(lines[i])
            if m:
                rule_ids_str = m.group(1)
                if rule_ids_str is None:
                    return True  # bare ignore - suppress all rules
                rules = {r.strip() for r in re.split(r"[,\s]+", rule_ids_str) if r.strip()}
                if finding.rule_id in rules:
                    return True
    return False


def _deduplicate(findings: list) -> list:
    """When AST and regex both report the same (file, line, vuln_type),
    keep the AST finding - it is more precise and context-aware."""
    seen: dict[tuple, object] = {}
    for f in findings:
        key = (f.file_path, f.line_number, f.vuln_type)
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
        elif f.rule_id.startswith("AST-") and not existing.rule_id.startswith("AST-"):
            seen[key] = f  # prefer AST finding over regex finding
    return list(seen.values())
