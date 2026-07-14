from __future__ import annotations

import fnmatch
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from vulnscanner.analyzers import ALL_ANALYZERS, BaseAnalyzer
from vulnscanner.analyzers.file_context import (
    INCLUDE_TEST_FILES,
    INCLUDE_VENDOR_FILES,
    classify_file_context,
)
from vulnscanner.fetcher.github import GitHubFetcher
from vulnscanner.fetcher.local import LocalFetcher
from vulnscanner.cwe_map import get_cwe_id
from vulnscanner.models import Finding, ScanResult, VulnType

# Matches:  # vulnscanner: ignore  or  // vulnscanner: ignore[XSS-001,SQL-001]
_SUPPRESS_RE = re.compile(
    r"(?:#|//|<!--)\s*vulnscanner\s*:\s*ignore(?:\[([A-Z0-9,\s_-]+)\])?",
    re.IGNORECASE,
)

DEFAULT_WORKERS = min((os.cpu_count() or 1) * 2, 16)


@dataclass
class _FileResult:
    """Accumulated analysis output for a single file (no shared-state mutation)."""
    findings: list[Finding] = field(default_factory=list)
    suppression_breakdown: dict[str, int] = field(default_factory=dict)
    scanned_lines: int = 0
    errors: list[str] = field(default_factory=list)


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
        workers: int = 0,
    ) -> None:
        self._github_token = github_token
        self._analyzers = analyzers or ALL_ANALYZERS
        self._cli_excludes = tuple(exclude)
        self._workers = workers if workers > 0 else DEFAULT_WORKERS

    def scan(self, target: str, changed_files: set[str] | None = None) -> ScanResult:
        """Scan a GitHub repo URL/slug or a local directory path.

        *changed_files* — when provided (incremental mode), only files whose
        relative path is in this set are analysed; other files are skipped.
        Only honoured for local-directory scans; ignored for GitHub targets.
        """
        if os.path.isdir(target):
            return self._scan_local(target, changed_files=changed_files)
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

            with ThreadPoolExecutor(max_workers=self._workers) as pool:
                futures: dict = {}
                # Submit analysis jobs while fetching - overlaps network I/O with CPU work
                for file_path, content in fetcher.iter_files(repo):
                    if _is_excluded(file_path, excludes):
                        continue
                    progress.update(task, description=f"[cyan]{file_path}")
                    f = pool.submit(self._analyze_file_pure, file_path, content, repo_url)
                    futures[f] = file_path

                # Collect results as workers complete
                progress.update(task, total=len(futures), completed=0)
                for future in as_completed(futures):
                    fp = futures[future]
                    progress.update(task, description=f"[cyan]{fp}", advance=1)
                    try:
                        partial = future.result()
                    except Exception as exc:
                        result.errors.append(f"{fp}: {exc}")
                        continue
                    _merge_into(result, partial)

        result.elapsed_seconds = time.perf_counter() - start
        return result

    def _scan_local(self, directory: str, changed_files: set[str] | None = None) -> ScanResult:
        result = ScanResult(repo_url=directory)
        fetcher = LocalFetcher(directory)

        # Load project-level exclusions from .vulnscannerignore
        ignore_path = fetcher.ignore_file_path()
        if ignore_path and ignore_path.exists():
            ignore_content = ignore_path.read_text(encoding="utf-8", errors="replace")
            excludes = list(self._cli_excludes) + _parse_ignore_file(ignore_content)
        else:
            excludes = list(self._cli_excludes)

        # Collect all files upfront so the progress bar knows the total
        files = [
            (fp, content)
            for fp, content in fetcher.iter_files()
            if not _is_excluded(fp, excludes)
            and (changed_files is None or fp in changed_files)
        ]

        start = time.perf_counter()
        with Progress(
            SpinnerColumn("line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            redirect_stderr=False,
        ) as progress:
            task = progress.add_task(f"Scanning {directory}...", total=len(files))

            with ThreadPoolExecutor(max_workers=self._workers) as pool:
                futures = {
                    pool.submit(self._analyze_file_pure, fp, content, directory): fp
                    for fp, content in files
                }
                for future in as_completed(futures):
                    fp = futures[future]
                    progress.update(task, description=f"[cyan]{fp}", advance=1)
                    try:
                        partial = future.result()
                    except Exception as exc:
                        result.errors.append(f"{fp}: {exc}")
                        continue
                    _merge_into(result, partial)

        result.elapsed_seconds = time.perf_counter() - start
        return result

    def _analyze_file_pure(
        self, file_path: str, content: str, source: str
    ) -> _FileResult:
        """Analyze a single file; returns results without mutating shared state."""
        partial = _FileResult(scanned_lines=content.count("\n") + 1)
        lines = content.splitlines()

        raw: list[Finding] = []
        for analyzer in self._analyzers:
            if not analyzer.supports(file_path):
                continue
            try:
                raw.extend(analyzer.analyze(file_path, content, source))
            except Exception as exc:
                partial.errors.append(f"{file_path}: {exc}")

        # 1. Inline-comment suppression (# vulnscanner: ignore)
        inline_suppressed = [f for f in raw if _is_suppressed(f, lines)]
        if inline_suppressed:
            partial.suppression_breakdown["inline_comment"] = len(inline_suppressed)
        raw = [f for f in raw if not _is_suppressed(f, lines)]

        # 2. CLEAN taint suppression (AST analyzer marked these as provably safe)
        clean_taint = [f for f in raw if f.suppression_reason == "clean_taint_source"]
        if clean_taint:
            partial.suppression_breakdown["clean_taint_source"] = len(clean_taint)
        raw = [f for f in raw if f.suppression_reason != "clean_taint_source"]

        # 3. File-context suppression (test / fixture / vendor paths)
        #    MALWARE findings are always surfaced regardless of file context —
        #    malicious code hidden in test/ or vendor/ directories is still malware.
        ctx_reason = _context_suppression_reason(file_path)
        if ctx_reason:
            malware = [f for f in raw if f.vuln_type == VulnType.MALWARE]
            suppressed = [f for f in raw if f.vuln_type != VulnType.MALWARE]
            for f in suppressed:
                f.suppression_reason = ctx_reason
            if suppressed:
                partial.suppression_breakdown[ctx_reason] = len(suppressed)
            raw = malware
            if not raw:
                return partial

        deduped = _deduplicate(raw)
        for f in deduped:
            if f.cwe_id is None:
                f.cwe_id = get_cwe_id(f.rule_id)
        partial.findings = deduped
        return partial


def _merge_into(result: ScanResult, partial: _FileResult) -> None:
    """Merge a per-file result into the shared accumulator (called from the main thread only)."""
    result.scanned_files += 1
    result.scanned_lines += partial.scanned_lines
    result.findings.extend(partial.findings)
    result.errors.extend(partial.errors)
    for reason, count in partial.suppression_breakdown.items():
        _add_breakdown(result, reason, count)


def _add_breakdown(result: ScanResult, reason: str, count: int) -> None:
    if count:
        result.suppressed_count += count
        result.suppression_breakdown[reason] = (
            result.suppression_breakdown.get(reason, 0) + count
        )


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
