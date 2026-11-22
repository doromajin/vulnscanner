from __future__ import annotations

import fnmatch
import multiprocessing
import os
import re
import time
import pickle
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field

from rich.console import Console as _RichConsole
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

_progress_console = _RichConsole(stderr=True)

from vulnscanner import pool_worker
from vulnscanner.analyzers import ALL_ANALYZERS, BaseAnalyzer
from vulnscanner.analyzers.ast_python import (
    build_cross_file_summary,
    set_cross_file_context,
)
from vulnscanner.analyzers.ast_java import (
    build_java_cross_file_context,
    set_java_cross_file_context,
)
from vulnscanner.analyzers.ast_go import (
    build_go_cross_file_context,
    set_go_cross_file_context,
)
from vulnscanner.analyzers.ast_js import (
    JS_TS_EXTS,
    build_js_cross_file_context,
    collect_js_file,
    merge_js_cross_file_parts,
    set_js_cross_file_context,
)
from vulnscanner.analyzers.ast_ruby import (
    build_ruby_cross_file_context,
    collect_ruby_file,
    merge_ruby_cross_file_parts,
    set_ruby_cross_file_context,
)
from vulnscanner.analyzers.ast_php import (
    build_php_cross_file_context,
    collect_php_file,
    merge_php_cross_file_parts,
    set_php_cross_file_context,
)
from vulnscanner.analyzers.file_context import (
    INCLUDE_TEST_FILES,
    INCLUDE_VENDOR_FILES,
    classify_file_context,
    is_minified_line,
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

# Analysis is pure-Python CPU work, so threads serialise on the GIL.  Local scans run in worker
# processes when there is enough work to pay for starting them (each worker re-imports the
# analyzers: ~1s, and process creation is slow on Windows/macOS spawn).  The work is estimated
# from the content size with a per-language cost, and a worker is only added for every
# _SECONDS_PER_WORKER of it.  VULNSCANNER_PARALLEL=thread|process|auto overrides the choice;
# an explicit -w N overrides the worker count.
_SECONDS_PER_WORKER = 4.0

# Analysis CPU seconds per MB of source, measured single-threaded on real repositories (Python
# varied 16-41 across projects; the middle is used).  Languages not measured use the tree-sitter
# figure; everything else (json, html, yaml, ...) is nearly free.
_SECONDS_PER_MB = {
    ".py": 25.0, ".java": 15.0, ".c": 13.0, ".cc": 12.0, ".cpp": 12.0, ".cxx": 12.0,
    ".h": 5.0, ".hpp": 8.0, ".php": 2.5, ".js": 4.5, ".jsx": 4.5, ".mjs": 4.5, ".cjs": 4.5,
    ".ts": 4.5, ".tsx": 4.5, ".go": 10.0, ".rb": 10.0, ".cs": 10.0, ".rs": 10.0,
}
_DEFAULT_SECONDS_PER_MB = 0.4


def _estimated_seconds(files) -> float:
    """Rough single-thread analysis time of *files* (path, content) pairs."""
    total = 0.0
    for fp, content in files:
        ext = os.path.splitext(fp)[1].lower()
        total += len(content) * _SECONDS_PER_MB.get(ext, _DEFAULT_SECONDS_PER_MB) / 1e6
    return total


# Cross-file pre-passes that look at each file on its own (no whole-program fixed point), so they
# can be spread over the worker pool: kind -> (per-file collector, file extensions).
_PRESCAN_COLLECTORS = {
    "php": (collect_php_file, (".php",)),
    "ruby": (collect_ruby_file, (".rb",)),
    "js": (collect_js_file, tuple(JS_TS_EXTS)),
}


def _prescan_on_pool(pool, all_contents: dict, workers: int) -> dict[str, list]:
    """Per-file cross-file pre-passes (PHP/Ruby/JS) on the worker pool: kind -> collected parts."""
    # Starting the workers is what the first submit() does (slow with spawn), so make that
    # happen now even when no PHP/Ruby/JS file needs scanning.
    pool.submit(abs, 0)
    futures = {}
    for kind, (_, exts) in _PRESCAN_COLLECTORS.items():
        subset = [(fp, c) for fp, c in all_contents.items() if fp.endswith(exts)]
        futures[kind] = [pool.submit(pool_worker._prescan_chunk_in_worker, kind, chunk)
                         for chunk in _balanced_chunks(subset, workers)]
    return {kind: [p for f in fs for p in f.result()] for kind, fs in futures.items()}


# Tasks handed to each worker.  Submitting one file at a time made the parent the bottleneck
# (~10ms per submit(), 9s for ~900 files); a handful of byte-balanced batches per worker keeps
# the IPC cheap while still evening out uneven file sizes.
_TASKS_PER_WORKER = 6


def _balanced_chunks(files, workers: int) -> list[list[str]]:
    """Group file paths into batches of similar total size, largest files first."""
    ordered = sorted(files, key=lambda f: len(f[1]), reverse=True)
    target = max(1, sum(len(c) for _, c in ordered) // (workers * _TASKS_PER_WORKER))
    chunks: list[list[str]] = []
    current: list[str] = []
    size = 0
    for fp, content in ordered:
        current.append(fp)
        size += len(content)
        if size >= target:
            chunks.append(current)
            current, size = [], 0
    if current:
        chunks.append(current)
    return chunks


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
        custom_rules: list | None = None,
        fast: bool = False,
        include_dotenv: bool = False,
    ) -> None:
        # fast: don't run content analyzers on test / fixture / vendor files (their findings
        # are suppressed anyway).  Off by default because it also drops the "N findings
        # suppressed" count for those paths.
        self._fast = fast
        self._include_dotenv = include_dotenv  # scan .env files (customer repositories)
        self._github_token = github_token
        self._cli_excludes = tuple(exclude)
        self._workers = workers if workers > 0 else DEFAULT_WORKERS
        self._workers_explicit = workers > 0

        base_analyzers = analyzers or ALL_ANALYZERS
        if custom_rules:
            from vulnscanner.analyzers.custom_rule_analyzer import CustomRuleAnalyzer
            self._analyzers = list(base_analyzers) + [CustomRuleAnalyzer(custom_rules)]
        else:
            self._analyzers = list(base_analyzers)

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
            console=_progress_console,
        ) as progress:
            task = progress.add_task(f"Scanning {repo.full_name}...", total=None)

            with ThreadPoolExecutor(max_workers=self._workers) as pool:
                futures: dict = {}
                # Submit analysis jobs while fetching - overlaps network I/O with CPU work
                for file_path, content in fetcher.iter_files(
                    repo, is_excluded=lambda p: _is_excluded(p, excludes)
                ):
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

        # Directories/files that could not be fetched: surface them so an
        # incomplete scan (rate limit, API error) is not mistaken for a clean one.
        result.errors.extend(f"Skipped (scan incomplete): {s}" for s in fetcher.skipped)

        result.elapsed_seconds = time.perf_counter() - start
        result.findings = _deduplicate_global(result.findings)
        return result

    def _scan_local(self, directory: str, changed_files: set[str] | None = None) -> ScanResult:
        result = ScanResult(repo_url=directory)
        fetcher = LocalFetcher(directory, include_dotenv=self._include_dotenv)

        # Load project-level exclusions from .vulnscannerignore
        ignore_path = fetcher.ignore_file_path()
        if ignore_path and ignore_path.exists():  # vulnscanner: ignore[AST-PATH-004]
            ignore_content = ignore_path.read_text(encoding="utf-8", errors="replace")  # vulnscanner: ignore[AST-PATH-004]
            excludes = list(self._cli_excludes) + _parse_ignore_file(ignore_content)
        else:
            excludes = list(self._cli_excludes)

        # Re-create the fetcher with the final exclude list so excluded directories
        # are pruned during the walk and excluded files are never read.
        fetcher = LocalFetcher(directory, is_excluded=lambda p: _is_excluded(p, excludes),
                               include_dotenv=self._include_dotenv)

        # Collect all files upfront so the progress bar knows the total
        files = [
            (fp, content)
            for fp, content in fetcher.iter_files()
            if not _is_excluded(fp, excludes)
            and (changed_files is None or fp in changed_files)
        ]

        # Build cross-file content map for interprocedural taint tracking across files.
        # Only Python files are needed; others are included harmlessly and ignored.
        all_contents = {fp: content for fp, content in files}

        # Start the worker processes first: they take seconds to come up, which overlaps with
        # the whole-program pre-passes below, and the per-file pre-passes run on them too.
        workers = self._process_workers(files)
        pool = None
        if workers:
            # spawn on every OS: fork()ing while the progress-bar thread runs can deadlock,
            # and it keeps Linux, macOS and Windows behaving the same.
            blob = pickle.dumps((self._analyzers, self._fast, directory, all_contents),
                                protocol=pickle.HIGHEST_PROTOCOL)
            pool = ProcessPoolExecutor(
                max_workers=workers, mp_context=multiprocessing.get_context("spawn"),
                initializer=pool_worker._init_worker, initargs=(blob,),
            )
        try:
            contexts, pool_ok = self._build_contexts(all_contents, pool, workers)
            if not pool_ok and pool is not None:
                pool.shutdown(wait=False, cancel_futures=True)
                pool = None

            start = time.perf_counter()
            with Progress(
                SpinnerColumn("line"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                redirect_stderr=False,
                console=_progress_console,
            ) as progress:
                task = progress.add_task(f"Scanning {directory}...", total=len(files))

                for fp, partial, exc in self._analyze_all(
                        files, directory, all_contents, contexts, pool, workers):
                    progress.update(task, description=f"[cyan]{fp}", advance=1)
                    if exc is not None:
                        result.errors.append(f"{fp}: {exc}")
                        continue
                    _merge_into(result, partial)
        finally:
            if pool is not None:
                pool.shutdown(wait=True, cancel_futures=True)

        result.elapsed_seconds = time.perf_counter() - start

        # Global dedup: cross-file analysis may attribute a finding to a callee file
        # while both the callee and the caller are scanned independently, producing
        # exact duplicates of (file_path, line_number, vuln_type, rule_id).
        result.findings = _deduplicate_global(result.findings)
        return result

    def _process_workers(self, files) -> int:
        """Number of worker processes to use, or 0 to analyse on threads."""
        mode = os.environ.get("VULNSCANNER_PARALLEL", "auto").lower()
        cpus = os.cpu_count() or 1
        if mode == "thread" or cpus < 2 or self._workers < 2:
            return 0
        if self._workers_explicit:
            workers = self._workers
        else:
            workers = min(cpus, int(_estimated_seconds(files) / _SECONDS_PER_WORKER))
            if mode == "process":
                workers = max(workers, 2)
            if workers < 2:
                return 0
        try:
            pickle.dumps(self._analyzers)  # workers receive their own copy of the analyzers
        except Exception:
            return 0
        return min(workers, 61)  # ProcessPoolExecutor's limit on Windows

    def _build_contexts(self, all_contents: dict, pool, workers: int) -> tuple[tuple, bool]:
        """Cross-file pre-passes: returns (contexts for _analyze_file_pure, whether *pool* is still usable)."""
        job = helper = None
        if pool is not None:
            # Submitting is what starts the workers, so do it off this thread while the
            # whole-program contexts below (which cannot be split per file) are built here.
            helper = ThreadPoolExecutor(max_workers=1)
            job = helper.submit(_prescan_on_pool, pool, all_contents, workers)

        # Phase C pre-scan: build global taint summary BEFORE parallel per-file analysis.
        # This seeds _interprocedural_taint_sources with globally-known taint sources so
        # Phase B (module-global scanning) correctly resolves function-call chains like
        # ``config.ALLOWED_HOST = get_host()`` where get_host is in a transitive import.
        cf_summary = build_cross_file_summary(all_contents)
        java_cf_ctx = build_java_cross_file_context(all_contents)
        go_cf_ctx = build_go_cross_file_context(all_contents)

        parts = None
        if job is not None:
            try:
                parts = job.result()
            except Exception:
                parts = None  # a worker died or a result could not be returned: do it here
            finally:
                helper.shutdown()
        if parts is not None:
            js_cf_ctx = merge_js_cross_file_parts(parts["js"], all_contents)
            ruby_cf_ctx = merge_ruby_cross_file_parts(parts["ruby"])
            php_cf_ctx = merge_php_cross_file_parts(parts["php"])
        else:
            js_cf_ctx = build_js_cross_file_context(all_contents)
            ruby_cf_ctx = build_ruby_cross_file_context(all_contents)
            php_cf_ctx = build_php_cross_file_context(all_contents)
        contexts = (cf_summary, java_cf_ctx, go_cf_ctx, js_cf_ctx, ruby_cf_ctx, php_cf_ctx)
        return contexts, parts is not None

    def _analyze_all(self, files, directory: str, all_contents: dict, contexts: tuple,
                     pool=None, workers: int = 0):
        """Yield (file_path, result, error) as files finish: on *pool* if given, else on threads."""
        done: set[str] = set()
        if pool is not None:
            try:
                futures = [pool.submit(pool_worker._analyze_chunk_in_worker, chunk, contexts)
                           for chunk in _balanced_chunks(files, workers)]
                for future in as_completed(futures):
                    for fp, partial, error in future.result():  # BrokenProcessPool propagates
                        done.add(fp)
                        yield fp, partial, error
                return
            except BrokenProcessPool:
                pass  # a worker died (e.g. out of memory): redo the unfinished files on threads
        pending = [(fp, content) for fp, content in files if fp not in done]
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            futures = {
                pool.submit(self._analyze_file_pure, fp, content, directory, all_contents, *contexts): fp
                for fp, content in pending
            }
            for future in as_completed(futures):
                fp = futures[future]
                try:
                    yield fp, future.result(), None
                except Exception as exc:
                    yield fp, None, exc

    def _analyze_file_pure(
        self, file_path: str, content: str, source: str,
        all_contents: dict[str, str] | None = None,
        cf_summary=None,
        java_cf_ctx=None,
        go_cf_ctx=None,
        js_cf_ctx=None,
        ruby_cf_ctx=None,
        php_cf_ctx=None,
    ) -> _FileResult:
        """Analyze a single file; returns results without mutating shared state."""
        # Provide cross-file content map and Phase C summary via thread-local storage.
        # cf_summary is built once before the pool and shared (read-only) across workers.
        if all_contents is not None:
            set_cross_file_context(all_contents, cf_summary)
        set_java_cross_file_context(java_cf_ctx)
        set_go_cross_file_context(go_cf_ctx)
        set_js_cross_file_context(js_cf_ctx)
        set_ruby_cross_file_context(ruby_cf_ctx)
        set_php_cross_file_context(php_cf_ctx)

        partial = _FileResult(scanned_lines=content.count("\n") + 1)
        lines = content.splitlines()

        # Findings in test / fixture / vendor files are dropped below (MALWARE excepted),
        # so skip the analyzers that could only produce droppable findings.
        ctx_reason = _context_suppression_reason(file_path)

        raw: list[Finding] = []
        for analyzer in self._analyzers:
            if self._fast and ctx_reason and not analyzer.runs_on_suppressed_paths:
                continue
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

        # 2b. Findings on minified lines are vendored / bundled build output, not reviewed source.
        #     Decided per line so hand-written code in the same bundle stays reportable; MALWARE
        #     findings are never dropped.
        if not INCLUDE_VENDOR_FILES:
            minified = [
                f for f in raw
                if f.vuln_type != VulnType.MALWARE and 0 < f.line_number <= len(lines)
                and is_minified_line(file_path, lines[f.line_number - 1])
            ]
            if minified:
                partial.suppression_breakdown["vendor_path"] = (
                    partial.suppression_breakdown.get("vendor_path", 0) + len(minified))
                dropped = {id(f) for f in minified}
                raw = [f for f in raw if id(f) not in dropped]

        # 3. File-context suppression (test / fixture / vendor paths)
        #    MALWARE findings are always surfaced regardless of file context —
        #    malicious code hidden in test/ or vendor/ directories is still malware.
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
        # Strip internal suppression sentinels (JAST-*-SAFE) used by dedup
        deduped = [f for f in deduped if not f.rule_id.endswith("-SAFE")]
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


_AST_PREFIXES = ("JAST-", "AST-", "JSAST-", "GOAST-", "RBAST-", "PHAST-", "TSAST-")


def _deduplicate_global(findings: list) -> list:
    """Global deduplication pass run after all files are merged.

    Cross-file taint analysis can produce the same finding twice:
    once when the callee file is analysed standalone (parameter UNKNOWN → flagged),
    and once when the caller file is analysed with cross-file context (tainted arg
    confirmed → callee finding re-attributed to callee file path).

    Both produce identical (file_path, line_number, rule_id) tuples; keep only one: the most
    significant (severity, then confirmed taint, then confidence).  Which copy arrives first
    depends on which worker finishes first, so keeping "the first" made the severity of the
    same finding vary from run to run (a --fail-on gate could flip on identical code).  The
    result is sorted so that identical input gives identical output.
    """
    best: dict[tuple, object] = {}
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        cur = best.get(key)
        if cur is None or _significance(f) > _significance(cur):
            best[key] = f
    return [best[k] for k in sorted(best)]


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_TAINT_RANK = {"tainted": 2, "unknown": 1, "clean": 0}


def _significance(f) -> tuple:
    """Ordering used to pick among duplicate findings; the description makes ties deterministic."""
    return (_SEVERITY_RANK.get(getattr(f.severity, "value", f.severity), 0),
            _TAINT_RANK.get(f.taint_status or "", 1), f.confidence, f.description)


def _deduplicate(findings: list) -> list:
    """When AST and regex both report the same (file, line, vuln_type),
    keep the AST finding(s) - they are more precise and context-aware.
    Multiple distinct AST rules at the same location are all preserved."""
    groups: dict[tuple, list] = {}
    for f in findings:
        groups.setdefault((f.file_path, f.line_number, f.vuln_type), []).append(f)

    result = []
    for group in groups.values():
        ast_findings = [f for f in group if f.rule_id.startswith(_AST_PREFIXES)]
        if ast_findings:
            seen_rules: set[str] = set()
            for f in ast_findings:
                if f.rule_id not in seen_rules:
                    result.append(f)
                    seen_rules.add(f.rule_id)
        else:
            result.append(group[0])
    return result
