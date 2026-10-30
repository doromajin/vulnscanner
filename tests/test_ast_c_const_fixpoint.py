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


class TestBytesBasedLoopOverflow:
    """CWE-131: buffer sized in bytes without sizeof, then written element by element."""

    LOOP = "    for (i = 0; i < 10; i++)\n    {\n        data[i] = source[i];\n    }\n"

    def _fn(self, alloc, decl="int * data;", src="int source[10] = {0};"):
        return (
            "#include <stdlib.h>\nvoid f()\n{\n"
            f"    {decl}\n    {alloc}\n    {{\n        {src}\n        size_t i;\n"
            + self.LOOP + "    }\n}\n"
        )

    def test_malloc_without_sizeof_int_loop_is_reported(self):
        code = self._fn("data = (int *)malloc(10);")
        assert "CAST-BUF-001" in _ids(code)

    def test_message_names_the_byte_comparison(self):
        f = [x for x in _analyze(self._fn("data = (int *)malloc(10);")) if x.rule_id == "CAST-BUF-001"]
        assert f and "CWE-131" in f[0].description and "40 bytes" in f[0].description

    def test_malloc_with_sizeof_is_clean(self):
        assert "CAST-BUF-001" not in _ids(self._fn("data = (int *)malloc(10*sizeof(int));"))

    def test_char_buffer_of_matching_size_is_clean(self):
        code = self._fn("data = (char *)malloc(10);", decl="char * data;", src="char source[10] = {0};")
        assert "CAST-BUF-001" not in _ids(code)

    def test_stack_alloca_without_sizeof_is_reported(self):
        assert "CAST-BUF-001" in _ids(self._fn("data = (int *)alloca(10);"))

    def test_struct_elements_are_not_guessed(self):
        code = self._fn("data = (twoIntsStruct *)malloc(10);", decl="twoIntsStruct * data;",
                        src="twoIntsStruct source[10];")
        assert "CAST-BUF-001" not in _ids(code)

    def test_pointer_to_pointer_is_not_sized_as_its_base_type(self):
        code = self._fn("data = (char **)malloc(10 * sizeof(char *));", decl="char ** data;",
                        src="char * source[10];")
        assert "CAST-BUF-001" not in _ids(code)

    def test_wchar_t_with_matching_bytes_is_clean(self):
        code = self._fn("data = (wchar_t *)malloc(10*sizeof(wchar_t));", decl="wchar_t * data;",
                        src="wchar_t source[10];")
        assert "CAST-BUF-001" not in _ids(code)


class TestKnownSizeofType:
    @pytest.mark.parametrize("text,size", [
        ("int", 4), ("unsigned char", 1), ("const char", 1), ("wchar_t", 2), ("long long", 8),
        ("short int", 2), ("size_t", 8), ("int64_t", 8), ("unsigned", 4),
    ])
    def test_basic_types(self, text, size):
        assert ast_c._known_sizeof_type(text) == size

    @pytest.mark.parametrize("text", ["twoIntsStruct", "struct _charVoid", "charVoid", "MyInt", ""])
    def test_unknown_types_are_none(self, text):
        assert ast_c._known_sizeof_type(text) is None


class TestBytesAcrossCalls:
    """CWE-131 where the buffer is allocated in one function and written in another."""

    SINK = (
        "static void sink(int * data)\n{\n    {\n        int source[10] = {0};\n        size_t i;\n"
        "        for (i = 0; i < 10; i++)\n        {\n            data[i] = source[i];\n        }\n    }\n}\n"
    )

    def _caller(self, alloc):
        return f"void f(void)\n{{\n    int * data;\n    data = NULL;\n    data = {alloc};\n    sink(data);\n}}\n"

    def test_undersized_buffer_passed_to_writer_is_reported(self):
        assert "CAST-BUF-001" in _ids(self.SINK + self._caller("(int *)malloc(10)"))

    def test_correctly_sized_buffer_passed_to_writer_is_clean(self):
        assert "CAST-BUF-001" not in _ids(self.SINK + self._caller("(int *)malloc(10*sizeof(int))"))

    def test_two_levels_deep_is_reported(self):
        code = (
            self.SINK
            + "static void mid(int * data) { sink(data); }\n"
            + "void f(void)\n{\n    int * data;\n    data = (int *)malloc(10);\n    mid(data);\n}\n"
        )
        assert "CAST-BUF-001" in _ids(code)

    def test_smallest_caller_wins(self):
        code = (
            self.SINK
            + "void good(void) { int * d = (int *)malloc(10*sizeof(int)); sink(d); }\n"
            + "void bad(void) { int * d = (int *)malloc(10); sink(d); }\n"
        )
        assert "CAST-BUF-001" in _ids(code)

    def test_alias_of_a_counted_parameter_is_not_mistaken_for_bytes(self):
        """x = data copies an element COUNT (10) into x's alloc size; it must not be read as 10 bytes."""
        code = (
            "static void sink(int * data)\n{\n    int * x = data;\n    size_t i;\n"
            "    for (i = 0; i < 10; i++)\n    {\n        x[i] = 0;\n    }\n}\n"
            "void f(void)\n{\n    int * data = (int *)malloc(10*sizeof(int));\n    sink(data);\n}\n"
        )
        assert "CAST-BUF-001" not in _ids(code)

    def test_unknown_element_type_is_not_guessed_across_calls(self):
        code = (
            "static void sink(twoIntsStruct * data)\n{\n    size_t i;\n"
            "    for (i = 0; i < 10; i++)\n    {\n        data[i].intOne = 0;\n    }\n}\n"
            "void f(void)\n{\n    twoIntsStruct * data = (twoIntsStruct *)malloc(10);\n    sink(data);\n}\n"
        )
        assert "CAST-BUF-001" not in _ids(code)


class TestBytesReturnedFromCallee:
    """`data = source(data)` where `source` allocates and returns the buffer (Juliet _21/_42/_61)."""

    LOOP = "    size_t i;\n    for (i = 0; i < 10; i++)\n    {\n        data[i] = 0;\n    }\n"

    def _code(self, alloc):
        return (
            f"static int * source(int * data)\n{{\n    data = (int *){alloc};\n    return data;\n}}\n"
            "void f(void)\n{\n    int * data;\n    data = NULL;\n    data = source(data);\n" + self.LOOP + "}\n"
        )

    def test_undersized_returned_buffer_is_reported(self):
        assert "CAST-BUF-001" in _ids(self._code("malloc(10)"))

    def test_correctly_sized_returned_buffer_is_clean(self):
        assert "CAST-BUF-001" not in _ids(self._code("malloc(10*sizeof(int))"))

    def test_returned_buffer_through_a_second_level(self):
        code = (
            "static int * inner(void)\n{\n    int * d = (int *)malloc(10);\n    return d;\n}\n"
            "static int * outer(void)\n{\n    int * d = inner();\n    return d;\n}\n"
            "void f(void)\n{\n    int * data = outer();\n" + self.LOOP + "}\n"
        )
        assert "CAST-BUF-001" in _ids(code)

    def test_function_returning_unknown_size_is_not_guessed(self):
        code = (
            "static int * source(int n)\n{\n    int * d = (int *)malloc(n);\n    return d;\n}\n"
            "void f(void)\n{\n    int * data = source(3);\n" + self.LOOP + "}\n"
        )
        assert "CAST-BUF-001" not in _ids(code)


class TestSizeofPointerAllocation:
    """CWE-467: allocating with the size of the pointer instead of the pointee."""

    def _fn(self, stmt, decl="double * data;"):
        return f"#include <stdlib.h>\nvoid f(void)\n{{\n    {decl}\n    {stmt}\n}}\n"

    @pytest.mark.parametrize("decl,stmt", [
        ("double * data;", "data = (double *)malloc(sizeof(data));"),
        ("twoIntsStruct * data;", "data = (twoIntsStruct *)malloc(sizeof(data));"),
        ("int64_t * data;", "data = (int64_t *)malloc(sizeof(data));"),
        ("char * data;", "data = (char *)alloca(sizeof(data));"),
        ("double * data = NULL;", "data = (double *)malloc(sizeof((data)));"),
    ])
    def test_sizeof_of_the_receiving_pointer_is_reported(self, decl, stmt):
        assert "CAST-BUF-001" in _ids(self._fn(stmt, decl))

    def test_initializer_form_is_reported(self):
        assert "CAST-BUF-001" in _ids(
            "#include <stdlib.h>\nvoid f(void)\n{\n    double * data = (double *)malloc(sizeof(data));\n}\n")

    @pytest.mark.parametrize("stmt", [
        "data = (double *)malloc(sizeof(*data));",
        "data = (double *)malloc(sizeof(double));",
        "data = (double *)malloc(10 * sizeof(*data));",
    ])
    def test_correct_sizeofs_are_clean(self, stmt):
        assert "CAST-BUF-001" not in _ids(self._fn(stmt))

    def test_array_sizeof_is_clean(self):
        code = "#include <stdlib.h>\nvoid f(void)\n{\n    char buf[8];\n    char * data;\n    data = (char *)malloc(sizeof(buf));\n}\n"
        assert "CAST-BUF-001" not in _ids(code)

    def test_sizeof_of_a_different_pointer_is_clean(self):
        code = self._fn("data = (double *)malloc(sizeof(other));", "double * data; double * other;")
        assert "CAST-BUF-001" not in _ids(code)


class TestParameterBytesAreBytes:
    """The callee must see the caller's BYTE size, not an element count mistaken for bytes."""

    def test_wide_buffer_copied_within_its_size_is_clean(self):
        code = (
            "#include <wchar.h>\n#include <string.h>\n"
            "static void sink(wchar_t * data)\n{\n    wchar_t dest[100];\n"
            "    memcpy(dest, data, 99*sizeof(wchar_t));\n}\n"
            "void f(void)\n{\n    wchar_t buf[100];\n    sink(buf);\n}\n"
        )
        assert "CAST-BUF-001" not in _ids(code)

    def test_wide_buffer_copied_into_a_smaller_one_is_reported(self):
        code = (
            "#include <wchar.h>\n#include <string.h>\n"
            "static void sink(wchar_t * data)\n{\n    wchar_t dest[50];\n"
            "    memcpy(dest, data, 99*sizeof(wchar_t));\n}\n"
            "void f(void)\n{\n    wchar_t buf[100];\n    sink(buf);\n}\n"
        )
        assert "CAST-BUF-001" in _ids(code)


class TestCallerBytesReachTheCopySink:
    """memcpy in a callee is judged against the BYTES the caller allocated (malloc(10) has no count)."""

    SINK = ("#include <string.h>\nstatic void sink(int * data)\n{\n    int source[10] = {0};\n"
            "    memcpy(data, source, 10*sizeof(int));\n}\n")

    def test_undersized_caller_buffer_is_reported_at_the_sink(self):
        code = self.SINK + "void f(void)\n{\n    int * data = (int *)malloc(10);\n    sink(data);\n}\n"
        f = [x for x in _analyze(code) if x.rule_id == "CAST-BUF-001"]
        assert f and f[0].line_number == 5

    def test_correctly_sized_caller_buffer_is_clean(self):
        code = self.SINK + "void f(void)\n{\n    int * data = (int *)malloc(10*sizeof(int));\n    sink(data);\n}\n"
        assert "CAST-BUF-001" not in _ids(code)

    def test_good_and_bad_callers_report_only_the_bad_sink(self):
        code = (
            "#include <string.h>\n"
            "static void badSink(int * data) { int s[10] = {0}; memcpy(data, s, 10*sizeof(int)); }\n"
            "static void goodSink(int * data) { int s[10] = {0}; memcpy(data, s, 10*sizeof(int)); }\n"
            "void bad(void) { int * d = (int *)malloc(10); badSink(d); }\n"
            "void good(void) { int * d = (int *)malloc(10*sizeof(int)); goodSink(d); }\n"
        )
        lines = sorted({x.line_number for x in _analyze(code) if x.rule_id == "CAST-BUF-001"})
        assert lines == [2]            # badSink only; goodSink (line 3) is correctly sized


class TestUnderpointedThroughPassThrough:
    """data = buf - 8 passed down two functions (52a -> 52b -> 52c) still underwrites in the last one."""

    def _code(self, assign):
        return (
            "#include <wchar.h>\n"
            "static void c_sink(wchar_t * data)\n{\n    wchar_t source[100];\n    wcsncpy(data, source, 100-1);\n}\n"
            "static void b_sink(wchar_t * data)\n{\n    c_sink(data);\n}\n"
            f"void a(void)\n{{\n    wchar_t * data;\n    wchar_t dataBuffer[100];\n    {assign}\n    b_sink(data);\n}}\n"
        )

    def test_two_hops_reports_the_underwrite_at_the_sink(self):
        f = [x for x in _analyze(self._code("data = dataBuffer - 8;")) if x.rule_id == "CAST-BUF-001"]
        assert f and 5 in {x.line_number for x in f}

    def test_properly_derived_pointer_is_clean(self):
        assert "CAST-BUF-001" not in _ids(self._code("data = dataBuffer;"))


class TestReturnedBufferReachesCopySink:
    """data = source(data) where source returns malloc(10) (bytes, no element count) is judged by memmove."""

    def _code(self, alloc):
        return (
            "#include <string.h>\n"
            f"static int * source(int * data)\n{{\n    data = (int *){alloc};\n    return data;\n}}\n"
            "void f(void)\n{\n    int * data = NULL;\n    int src[10] = {0};\n    data = source(data);\n"
            "    memmove(data, src, 10*sizeof(int));\n}\n"
        )

    def test_undersized_returned_buffer_is_reported_at_memmove(self):
        f = [x for x in _analyze(self._code("malloc(10)")) if x.rule_id == "CAST-BUF-001"]
        assert f and 12 in {x.line_number for x in f}      # the memmove line

    def test_correctly_sized_returned_buffer_is_clean(self):
        assert "CAST-BUF-001" not in _ids(self._code("malloc(10*sizeof(int))"))
