"""Worker-side code for the scanner's process pool.

Kept free of heavy imports on purpose.  With the spawn start method the parent pickles the
initializer and its arguments to each child in turn and waits while the child reads them; a
child that has to import the analyzers to *unpickle* those blocks the parent, so N workers
came up one second apart.  Here the arguments are an opaque bytes blob and the imports
happen inside _init_worker, after the parent has been released to start the next worker.
"""
from __future__ import annotations

import pickle

# Per-process state set by _init_worker: (scanner, directory, all_contents).
_worker_state: tuple | None = None


def _init_worker(blob: bytes) -> None:
    """Process-pool initializer: *blob* is pickle((analyzers, fast, directory, all_contents))."""
    global _worker_state
    from vulnscanner.scanner import VulnScanner

    # The blob is built by the parent scanner process itself and handed over the
    # multiprocessing pipe (which is pickle too); no external data reaches it.
    analyzers, fast, directory, all_contents = pickle.loads(blob)  # vulnscanner: ignore[AST-DESER-001]
    _worker_state = (VulnScanner(analyzers=analyzers, fast=fast), directory, all_contents)


def _prescan_chunk_in_worker(kind: str, file_paths: list[str]) -> list:
    """Run one per-file pre-pass collector over a batch of files; returns the non-empty parts."""
    from vulnscanner.scanner import _PRESCAN_COLLECTORS

    _, _, all_contents = _worker_state  # type: ignore[misc]
    collect = _PRESCAN_COLLECTORS[kind][0]
    parts = (collect(fp, all_contents[fp]) for fp in file_paths)
    return [p for p in parts if p is not None]


def _analyze_chunk_in_worker(file_paths: list[str], contexts: tuple) -> list:
    """Analyse a batch of files; one (path, result, error) triple per file."""
    scanner, directory, all_contents = _worker_state  # type: ignore[misc]
    out = []
    for fp in file_paths:
        try:
            out.append((fp, scanner._analyze_file_pure(
                fp, all_contents[fp], directory, all_contents, *contexts), None))
        except Exception as exc:
            out.append((fp, None, str(exc)))
    return out
