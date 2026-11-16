"""Process-pool scanning must give the same results as the threaded path."""
import os
from concurrent.futures import Future
from concurrent.futures.process import BrokenProcessPool

import pytest

from vulnscanner import scanner as S
from vulnscanner.analyzers import ALL_ANALYZERS
from vulnscanner.analyzers.base import BaseAnalyzer

_VULN = 'import os\ndef view(request):\n    os.system("ls " + request.args.get("d"))\n'


def _make_repo(root, n=12):
    for i in range(n):
        (root / f"mod{i}.py").write_text(_VULN + f"# file {i}\n" * i, encoding="utf-8")
    (root / "notes.txt").write_text("nothing here\n", encoding="utf-8")


def _keys(result):
    return sorted((f.file_path, f.line_number, f.rule_id, f.severity.value) for f in result.findings)


def _scan(root, mode, workers=2):
    old = os.environ.get("VULNSCANNER_PARALLEL")
    os.environ["VULNSCANNER_PARALLEL"] = mode
    try:
        return S.VulnScanner(workers=workers).scan(str(root))
    finally:
        if old is None:
            del os.environ["VULNSCANNER_PARALLEL"]
        else:
            os.environ["VULNSCANNER_PARALLEL"] = old


def _files(sizes):
    return [(f"f{i}.py", "x" * n) for i, n in enumerate(sizes)]


# ── chunking ──────────────────────────────────────────────────────────────────

def test_chunks_cover_every_file_once_and_start_with_the_largest():
    files = _files([10, 5000, 30, 700, 2, 2500, 90, 1200])
    chunks = S._balanced_chunks(files, workers=2)
    flat = [fp for c in chunks for fp in c]
    assert sorted(flat) == sorted(fp for fp, _ in files)
    assert flat[0] == "f1.py"  # 5000 bytes


def test_chunks_are_roughly_byte_balanced():
    files = _files([1000] * 120)
    chunks = S._balanced_chunks(files, workers=4)
    sizes = [len(c) for c in chunks]
    assert len(chunks) >= 4
    assert max(sizes) - min(sizes) <= 1


# ── choosing processes or threads ─────────────────────────────────────────────

@pytest.fixture
def many_cpus(monkeypatch):
    monkeypatch.setattr(S.os, "cpu_count", lambda: 16)
    monkeypatch.delenv("VULNSCANNER_PARALLEL", raising=False)


def test_small_scans_stay_on_threads(many_cpus):
    assert S.VulnScanner()._process_workers(_files([1000] * 10)) == 0


def test_large_scans_use_processes_scaled_to_the_work(many_cpus):
    sc = S.VulnScanner()
    mid = sc._process_workers(_files([100_000] * 20))     # ~2MB -> ~30s of work
    huge = sc._process_workers(_files([1_000_000] * 100))  # ~100MB
    assert 2 <= mid < 16
    assert huge == 16


def test_explicit_worker_count_is_honoured(many_cpus):
    assert S.VulnScanner(workers=5)._process_workers(_files([10])) == 5


def test_thread_mode_and_single_worker_disable_processes(many_cpus, monkeypatch):
    monkeypatch.setenv("VULNSCANNER_PARALLEL", "thread")
    assert S.VulnScanner(workers=8)._process_workers(_files([10**7])) == 0
    monkeypatch.delenv("VULNSCANNER_PARALLEL")
    assert S.VulnScanner(workers=1)._process_workers(_files([10**7])) == 0


def test_unpicklable_analyzer_falls_back_to_threads(many_cpus):
    class Odd(BaseAnalyzer):
        def __init__(self):
            self.cb = lambda: None  # lambdas cannot be pickled

        def supports(self, file_path):
            return False

        def analyze(self, file_path, content, repo_url=""):
            return []

    sc = S.VulnScanner(analyzers=[Odd()], workers=4)
    assert sc._process_workers(_files([10**6] * 10)) == 0


# ── equivalence ───────────────────────────────────────────────────────────────

def test_process_scan_matches_thread_scan(tmp_path):
    _make_repo(tmp_path)
    threaded = _scan(tmp_path, "thread")
    pooled = _scan(tmp_path, "process")
    assert threaded.findings, "fixture should produce findings"
    assert _keys(pooled) == _keys(threaded)
    assert pooled.scanned_files == threaded.scanned_files
    assert pooled.scanned_lines == threaded.scanned_lines
    assert pooled.suppression_breakdown == threaded.suppression_breakdown
    assert pooled.errors == threaded.errors == []


# ── failure handling ──────────────────────────────────────────────────────────

class _BrokenAfterFirstChunk:
    """Stands in for ProcessPoolExecutor: first batch runs, then a worker 'dies'."""

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, chunk):
        f = Future()
        if not getattr(_BrokenAfterFirstChunk, "used", False):
            _BrokenAfterFirstChunk.used = True
            S._init_worker(*_BrokenAfterFirstChunk.initargs)
            f.set_result(fn(chunk))
        else:
            f.set_exception(BrokenProcessPool("worker died"))
        return f


def test_broken_pool_finishes_remaining_files_on_threads(tmp_path, monkeypatch):
    _make_repo(tmp_path)
    expected = _scan(tmp_path, "thread")

    class Pool(_BrokenAfterFirstChunk):
        def __init__(self, *a, initargs=(), **k):
            _BrokenAfterFirstChunk.initargs = initargs

    _BrokenAfterFirstChunk.used = False
    monkeypatch.setattr(S, "ProcessPoolExecutor", Pool)
    monkeypatch.setenv("VULNSCANNER_PARALLEL", "process")
    # one task per chunk so that the second chunk is the one that "breaks"
    monkeypatch.setattr(S, "_TASKS_PER_WORKER", 1000)
    result = S.VulnScanner(workers=2).scan(str(tmp_path))

    assert _BrokenAfterFirstChunk.used
    assert result.scanned_files == expected.scanned_files  # nothing skipped, nothing doubled
    assert _keys(result) == _keys(expected)
