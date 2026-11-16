"""The package must stay importable when the optional parsers are not installed.

`pip install .` only pulls pyproject's dependencies (no tree-sitter / javalang); an
unguarded module-level use of a parser-only name made `import vulnscanner.analyzers`
raise NameError there, and broke CI test collection.
"""
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

_PROBE = """
import sys, importlib.abc
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name.split(".")[0] in ("tree_sitter", "javalang") or name.startswith("tree_sitter"):
            raise ImportError("blocked: " + name)
sys.meta_path.insert(0, Block())
import vulnscanner.analyzers as a, vulnscanner.scanner
print(len(a.ALL_ANALYZERS))
"""


def test_analyzers_import_without_tree_sitter():
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE], cwd=_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-800:]
    assert int(proc.stdout.strip()) > 0
