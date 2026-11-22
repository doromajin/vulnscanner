"""Process-pool scanning must give the same results as the threaded path."""
import dataclasses
import multiprocessing
import os
from concurrent.futures import Future, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool

import pytest

import pickle

from vulnscanner import pool_worker as PW
from vulnscanner import scanner as S
from vulnscanner.analyzers import ALL_ANALYZERS
from vulnscanner.analyzers.ast_js import build_js_cross_file_context
from vulnscanner.analyzers.ast_php import build_php_cross_file_context
from vulnscanner.analyzers.ast_ruby import build_ruby_cross_file_context
from vulnscanner.analyzers.base import BaseAnalyzer

_VULN = 'import os\ndef view(request):\n    os.system("ls " + request.args.get("d"))\n'


def _make_repo(root, n=12):
    for i in range(n):
        (root / f"mod{i}.py").write_text(_VULN + f"# file {i}\n" * i, encoding="utf-8")
    (root / "notes.txt").write_text("nothing here\n", encoding="utf-8")
    # cross-file PHP / JS / Ruby, so the per-file pre-passes have something to find
    (root / "lib.php").write_text("<?php function getq() { return $_GET['q']; }\n", encoding="utf-8")
    (root / "page.php").write_text("<?php echo getq();\n", encoding="utf-8")
    (root / "util.js").write_text(
        "function getq(req) { return req.query.q; }\nmodule.exports = { getq };\n", encoding="utf-8")
    (root / "use.js").write_text(
        "const { getq } = require('./util');\nfunction h(req, res) { res.send(getq(req)); }\n",
        encoding="utf-8")
    (root / "m.rb").write_text("def read_q\n  params[:q]\nend\n", encoding="utf-8")


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
    monkeypatch.setenv("VULNSCANNER_MEMORY_BUDGET_MB", "1000000")  # the choice must not depend on this PC's free RAM


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


# ── per-file pre-passes on the pool ───────────────────────────────────────────

_PRESCAN_SAMPLE = {
    "a.php": "<?php function getq() { return $_GET['q']; }\nfunction safe() { return 1; }\n",
    "b.php": "<?php function other() { $x = $_POST['a']; return $x; }\n",
    "c.rb": "def read_q\n  params[:q]\nend\ndef use(x)\n  y = params[:z]\n  system(y)\nend\n",
    "d.js": "function getq(req) { return req.query.q; }\nmodule.exports = { getq };\n",
    "e.ts": "export function getq(req: any) { return req.query.q; }\n",
    "f.py": "x = 1\n",
}


def test_pool_prescan_matches_serial_builders():
    pool = ProcessPoolExecutor(
        max_workers=2, mp_context=multiprocessing.get_context("spawn"), initializer=PW._init_worker,
        initargs=(pickle.dumps((list(ALL_ANALYZERS), False, ".", _PRESCAN_SAMPLE)),))
    try:
        parts = S._prescan_on_pool(pool, _PRESCAN_SAMPLE, workers=2)
    finally:
        pool.shutdown(wait=True)

    got = (S.merge_php_cross_file_parts(parts["php"]),
           S.merge_ruby_cross_file_parts(parts["ruby"]),
           S.merge_js_cross_file_parts(parts["js"], _PRESCAN_SAMPLE))
    want = (build_php_cross_file_context(_PRESCAN_SAMPLE),
            build_ruby_cross_file_context(_PRESCAN_SAMPLE),
            build_js_cross_file_context(_PRESCAN_SAMPLE))
    assert [dataclasses.asdict(g) for g in got] == [dataclasses.asdict(w) for w in want]
    assert want[0].tainted_func_names and want[1].tainted_method_names and want[2].tainted_exports


# ── failure handling ──────────────────────────────────────────────────────────

class _InlinePool:
    """Stands in for ProcessPoolExecutor: runs tasks in this process and can 'kill a worker'."""

    break_on = None  # "prescan" | "analysis-after-first"

    def __init__(self, *a, initializer=None, initargs=(), **k):
        self.initializer, self.initargs = initializer, initargs
        self.analysis_calls = 0
        self.ready = False

    def shutdown(self, *a, **k):
        pass

    def submit(self, fn, *args):
        if not self.ready:
            self.initializer(*self.initargs)
            self.ready = True
        f = Future()
        if fn is PW._prescan_chunk_in_worker and self.break_on == "prescan":
            f.set_exception(BrokenProcessPool("worker died"))
            return f
        if fn is PW._analyze_chunk_in_worker:
            self.analysis_calls += 1
            if self.break_on == "analysis-after-first" and self.analysis_calls > 1:
                f.set_exception(BrokenProcessPool("worker died"))
                return f
        f.set_result(fn(*args))
        return f


@pytest.mark.parametrize("break_on", ["analysis-after-first", "prescan"])
def test_broken_pool_still_scans_every_file_once(tmp_path, monkeypatch, break_on):
    _make_repo(tmp_path)
    expected = _scan(tmp_path, "thread")

    monkeypatch.setattr(PW, "_worker_state", None)  # restored afterwards
    monkeypatch.setattr(_InlinePool, "break_on", break_on)
    monkeypatch.setattr(S, "ProcessPoolExecutor", _InlinePool)
    monkeypatch.setenv("VULNSCANNER_PARALLEL", "process")
    # one file per task so that the second analysis task is the one that "breaks"
    monkeypatch.setattr(S, "_TASKS_PER_WORKER", 1000)
    result = S.VulnScanner(workers=2).scan(str(tmp_path))

    assert result.scanned_files == expected.scanned_files  # nothing skipped, nothing doubled
    assert _keys(result) == _keys(expected)
    assert result.errors == expected.errors
