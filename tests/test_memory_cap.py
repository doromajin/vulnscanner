import os
import pytest

from vulnscanner import memory as M
from vulnscanner import scanner as S

MB = M.MB


def _files(sizes):
    return [(f"f{i}.php", "x" * n) for i, n in enumerate(sizes)]


def test_cap_is_free_memory_divided_by_one_workers_peak():
    text = 100 * MB
    one = M.worker_memory_bytes(text)
    avail = int((M.PARENT_BASE_BYTES + M.PARENT_TEXT_FACTOR * text + 8 * one) / M.USABLE_FRACTION) + 1
    assert M.max_workers_for_memory(text, avail) == 8


def test_a_bigger_repository_allows_fewer_workers():
    avail = 8000 * MB
    assert M.max_workers_for_memory(10 * MB, avail) > M.max_workers_for_memory(400 * MB, avail)


def test_too_little_memory_means_no_workers_and_unknown_memory_means_no_cap():
    assert M.max_workers_for_memory(50 * MB, 100 * MB) == 0
    assert M.max_workers_for_memory(50 * MB, None) is None


def test_budget_override_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("VULNSCANNER_MEMORY_BUDGET_MB", "2048")
    assert M.available_memory_bytes() == 2048 * MB


def test_real_free_memory_is_detected_here(monkeypatch):
    monkeypatch.delenv("VULNSCANNER_MEMORY_BUDGET_MB", raising=False)
    avail = M.available_memory_bytes()
    assert avail is None or avail > 64 * MB


@pytest.fixture
def many_cpus(monkeypatch):
    monkeypatch.setattr(S.os, "cpu_count", lambda: 16)
    monkeypatch.delenv("VULNSCANNER_PARALLEL", raising=False)


def test_scanner_plans_fewer_processes_when_memory_is_short(many_cpus, monkeypatch):
    files = _files([1_000_000] * 100)  # ~100 MB of source: enough work for the full 16 workers
    monkeypatch.setenv("VULNSCANNER_MEMORY_BUDGET_MB", "1000000")
    roomy = S.VulnScanner()._process_workers(files)
    monkeypatch.setenv("VULNSCANNER_MEMORY_BUDGET_MB", "2500")
    tight = S.VulnScanner()._process_workers(files)
    assert roomy == 16
    assert 0 <= tight < roomy


def test_an_explicit_worker_count_is_not_capped(many_cpus, monkeypatch):
    monkeypatch.setenv("VULNSCANNER_MEMORY_BUDGET_MB", "100")
    assert S.VulnScanner(workers=5)._process_workers(_files([10])) == 5


def test_pool_initializer_empties_the_blob_holder(monkeypatch):
    import pickle

    from vulnscanner import pool_worker
    monkeypatch.setattr(pool_worker, "_worker_state", None)  # restored afterwards
    holder = [pickle.dumps(([], False, "d", {"a.py": "x = 1\n"}))]
    pool_worker._init_worker(holder)
    assert holder == []
    assert pool_worker._worker_state[2] == {"a.py": "x = 1\n"}


def test_worker_state_file_round_trip_and_cleanup(monkeypatch):
    import os

    from vulnscanner import pool_worker
    monkeypatch.setattr(pool_worker, "_worker_state", None)
    path = S._write_worker_state(([], False, "d", {"a.py": "x = 1\n"}))
    try:
        assert os.path.exists(path)
        pool_worker._init_worker(path)
        assert pool_worker._worker_state[2] == {"a.py": "x = 1\n"}
    finally:
        S._remove_quietly(path)
    assert not os.path.exists(path)
    S._remove_quietly(path)  # removing twice must not raise


def test_a_process_scan_leaves_no_state_file_behind(many_cpus, monkeypatch, tmp_path):
    import glob
    import tempfile
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "vulnscan-state-*.pkl")))
    monkeypatch.setenv("VULNSCANNER_PARALLEL", "process")
    S.VulnScanner(workers=2).scan(str(tmp_path))
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "vulnscan-state-*.pkl")))
    assert after - before == set()
