import pytest

from vulnscanner.analyzers.ast_c import CASTAnalyzer, _TS_C_AVAILABLE
from vulnscanner.models import Severity

pytestmark = pytest.mark.skipif(not _TS_C_AVAILABLE, reason="tree-sitter-c not installed")


def _scan(src: str):
    return CASTAnalyzer().analyze("prog.c", src)


def test_union_array_element_size_is_not_guessed():
    src = (
        "#include <string.h>\n"
        "typedef union { unsigned char c[64]; unsigned int l[16]; } Block;\n"
        "void f(const unsigned char *buffer) {\n"
        "    Block block[1];\n"
        "    memcpy(block, buffer, 64);\n"
        "}\n"
    )
    assert [f for f in _scan(src) if f.rule_id == "CAST-BUF-001"] == []


def test_plain_array_overflow_still_reported():
    src = (
        "#include <string.h>\n"
        "void f(const char *src) {\n"
        "    char dst[4];\n"
        "    memcpy(dst, src, 64);\n"
        "}\n"
    )
    assert [f for f in _scan(src) if f.rule_id == "CAST-BUF-001"]


def test_argv_only_allocation_is_demoted():
    src = (
        "#include <stdlib.h>\n"
        "int main(int argc, char **argv) {\n"
        "    unsigned n = (unsigned)atoi(argv[1]);\n"
        "    char *p = malloc(n * 4);\n"
        "    free(p);\n"
        "    return 0;\n"
        "}\n"
    )
    hits = [f for f in _scan(src) if f.rule_id == "CAST-INT-001"]
    assert hits and all(f.severity == Severity.LOW for f in hits)


def test_network_fed_allocation_keeps_severity():
    src = (
        "#include <stdlib.h>\n"
        "#include <sys/socket.h>\n"
        "int main(int argc, char **argv) {\n"
        "    unsigned n = 0;\n"
        "    recv(3, &n, sizeof(n), 0);\n"
        "    char *p = malloc(n * 4);\n"
        "    free(p);\n"
        "    return 0;\n"
        "}\n"
    )
    hits = [f for f in _scan(src) if f.rule_id == "CAST-INT-001"]
    assert hits and any(f.severity == Severity.HIGH for f in hits)
