"""Regression tests for the interprocedural constant propagation in ast_c.

Bug: param_const_ints was overwritten whenever a call site passed a different value, so a function
called with two different literal constants made the alloc-summary fixpoint flip forever
(analysis never returned).  Now the (low, high) range of passed constants only widens.
"""
import threading

import pytest

ast_c = pytest.importorskip("vulnscanner.analyzers.ast_c")
if not ast_c._TS_C_AVAILABLE:
    pytest.skip("tree-sitter-c not installed", allow_module_level=True)


def _analyze(code, path="t.c", timeout=20.0):
    """Run the analyzer in a thread so a regression fails the test instead of hanging the suite."""
    out: dict = {}

    def work():
        out["findings"] = ast_c.CASTAnalyzer().analyze(path, code)

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "analysis did not finish: the constant fixpoint is not converging"
    return out["findings"]


def _ids(code, path="t.c"):
    return {f.rule_id for f in _analyze(code, path)}


SINK = "static void sink(int idx)\n{\n    int buf[10];\n    buf[idx] = 1;\n}\n"


class TestConstantFixpointTerminates:
    def test_two_callers_with_different_constants_terminate(self):
        code = SINK + "void a(void) { sink(10); }\nvoid b(void) { sink(2); }\n"
        before = ast_c.LAST_ALLOC_FIXPOINT_ITERS
        _analyze(code)
        assert ast_c.LAST_ALLOC_FIXPOINT_ITERS < ast_c._MAX_ALLOC_FIXPOINT_ITERS

    def test_many_callers_terminate(self):
        calls = "".join(f"void c{i}(void) {{ sink({i}); }}\n" for i in range(30))
        _analyze(SINK + calls)
        assert ast_c.LAST_ALLOC_FIXPOINT_ITERS < ast_c._MAX_ALLOC_FIXPOINT_ITERS

    def test_cpp_class_variants_with_same_method_name_terminate(self):
        code = (
            "namespace A { class Bad { public: void action(int idx) { int buf[10]; buf[idx] = 1; } }; }\n"
            "namespace B { class Good { public: void action(int idx) { int buf[10]; buf[idx] = 1; } }; }\n"
            "void run1(void) { A::Bad x; x.action(10); }\n"
            "void run2(void) { B::Good y; y.action(2); }\n"
        )
        _analyze(code, "t.cpp")
        assert ast_c.LAST_ALLOC_FIXPOINT_ITERS < ast_c._MAX_ALLOC_FIXPOINT_ITERS


class TestConstantPropagationStillDetects:
    def test_bad_constant_among_good_ones_is_reported(self):
        code = SINK + "void a(void) { sink(10); }\nvoid b(void) { sink(2); }\n"
        assert "CAST-BUF-001" in _ids(code)

    def test_reported_whichever_call_site_comes_first(self):
        code = SINK + "void b(void) { sink(2); }\nvoid a(void) { sink(10); }\n"
        assert "CAST-BUF-001" in _ids(code)

    def test_negative_constant_among_good_ones_is_reported(self):
        code = SINK + "void a(void) { sink(3); }\nvoid b(void) { sink(-5); }\n"
        assert "CAST-BUF-001" in _ids(code)

    def test_all_in_range_constants_are_not_reported(self):
        code = SINK + "void a(void) { sink(2); }\nvoid b(void) { sink(7); }\nvoid c(void) { sink(0); }\n"
        assert "CAST-BUF-001" not in _ids(code)

    def test_single_bad_constant_is_reported(self):
        assert "CAST-BUF-001" in _ids(SINK + "void a(void) { sink(10); }\n")


class TestNoteConst:
    def test_range_only_widens(self):
        s = ast_c._FuncSummary()
        assert ast_c._note_const(s, 0, 5) is True
        assert ast_c._note_const(s, 0, 5) is False           # same value: no change
        assert ast_c._note_const(s, 0, 9) is True            # widens
        assert ast_c._note_const(s, 0, 7) is False           # inside the range
        assert ast_c._note_const(s, 0, 2) is True            # widens the other way
        assert s.param_const_range[0] == (2, 9)
        assert s.param_const_ints[0] == 5                    # first value kept as representative
