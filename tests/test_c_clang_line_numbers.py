"""C/C++ finding line numbers must not shift when clang preprocesses the source.

`clang -E -P` collapses blank lines, so with clang installed (GitHub's ubuntu runners,
Xcode on macOS) every finding below the first directive was reported on the wrong line.
clang itself is faked here so the tests run without it.
"""
from types import SimpleNamespace

import pytest

from vulnscanner.analyzers import ast_c
from vulnscanner.analyzers.ast_c import CASTAnalyzer, _realign_clang_output

_CODE = """
#include <stdio.h>
void f(const unsigned char *ch) {
    char ok[64];
    char tiny[8];
    sprintf(ok, "%d.%d.%d.%d", ch[3], ch[2], ch[1], ch[0]);
    sprintf(tiny, "%d.%d.%d.%d", ch[3], ch[2], ch[1], ch[0]);
}
"""

_HEADER = (
    '# 1 "<stdin>"\n# 1 "<built-in>" 1\n# 1 "<built-in>" 3\n# 400 "<built-in>" 3\n'
    '# 1 "<command line>" 1\n# 1 "<built-in>" 2\n# 1 "<stdin>" 2\n'
)


def _fake_clang(monkeypatch, stdout: str, seen: list | None = None):
    def run(cmd, **kw):
        if seen is not None:
            seen.append(cmd)
        return SimpleNamespace(stdout=stdout.encode(), returncode=0)
    monkeypatch.setattr(ast_c.subprocess, "run", run)
    monkeypatch.setattr(ast_c, "_CLANG_AVAIL", None)


def _lines(code=_CODE):
    return [f.line_number for f in CASTAnalyzer().analyze("t.c", code)
            if f.rule_id == "CAST-BUF-001"]


def test_clang_is_not_asked_to_collapse_blank_lines(monkeypatch):
    seen: list = []
    _fake_clang(monkeypatch, _HEADER + "\n\n" + "\n".join(_CODE.split("\n")[2:]), seen)
    _lines()
    assert seen and "-P" not in seen[0]


def test_finding_line_survives_clang_header_and_blank_lines(monkeypatch):
    # source lines 1-2 (empty + stripped #include) come back as two blank lines
    body = "\n".join(_CODE.split("\n")[2:])
    _fake_clang(monkeypatch, _HEADER + "\n\n" + body)
    assert _lines() == [7]


def test_finding_line_survives_clang_gap_marker(monkeypatch):
    # clang replaces long runs of blank lines with a linemarker instead of newlines
    padded = "\n" * 12 + _CODE
    body = "\n".join(padded.split("\n")[14:])
    _fake_clang(monkeypatch, _HEADER + '# 15 "<stdin>"\n' + body)
    assert _lines(padded) == [19]


def test_unmappable_clang_output_falls_back_to_source_lines(monkeypatch):
    # output with more lines than the source cannot be aligned -> regex expansion instead
    _fake_clang(monkeypatch, "\n".join(["int x;"] * 50))
    assert _lines() == [7]


def test_no_clang_uses_source_lines(monkeypatch):
    def run(cmd, **kw):
        raise FileNotFoundError
    monkeypatch.setattr(ast_c.subprocess, "run", run)
    monkeypatch.setattr(ast_c, "_CLANG_AVAIL", None)
    assert _lines() == [7]


@pytest.mark.parametrize("text,count,expected", [
    ('# 1 "<stdin>"\nint a;\nint b;\n', 5, "int a;\nint b;"),
    ('# 1 "<stdin>" 2\n\n\nint a;\n', 5, "\n\nint a;"),
    ('# 4 "<stdin>"\nint a;\n', 5, "\n\n\nint a;"),
    ('# 1 "<built-in>" 3\n# 9 "<built-in>" 3\nint a;\n', 5, "int a;"),
])
def test_realign_clang_output(text, count, expected):
    assert _realign_clang_output(text, count) == expected


def test_realign_rejects_output_longer_than_source():
    assert _realign_clang_output("a\nb\nc\n", 2) is None
