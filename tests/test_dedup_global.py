"""_deduplicate_global must not depend on the order findings arrive in."""
import itertools
import random

from vulnscanner.models import Finding, Severity, VulnType
from vulnscanner.scanner import _deduplicate_global


def _f(sev, taint="unknown", conf=0.5, line=10, rule="AST-SQL-005", path="a.py", desc="d"):
    return Finding(vuln_type=VulnType.SQL_INJECTION, severity=sev, file_path=path, line_number=line,
                   line_content="x", description=desc, rule_id=rule, taint_status=taint, confidence=conf)


def test_keeps_the_higher_severity_whichever_arrives_first():
    low, high = _f(Severity.MEDIUM), _f(Severity.HIGH, taint="tainted", conf=0.9)
    for order in ([low, high], [high, low]):
        out = _deduplicate_global(order)
        assert len(out) == 1 and out[0].severity == Severity.HIGH


def test_same_severity_prefers_confirmed_taint_then_confidence():
    a = _f(Severity.MEDIUM, taint="unknown", conf=0.9)
    b = _f(Severity.MEDIUM, taint="tainted", conf=0.3)
    c = _f(Severity.MEDIUM, taint="tainted", conf=0.8)
    for order in itertools.permutations([a, b, c]):
        out = _deduplicate_global(list(order))
        assert len(out) == 1 and out[0] is c


def test_exact_ties_are_resolved_the_same_way_every_time():
    x, y = _f(Severity.LOW, desc="aaa"), _f(Severity.LOW, desc="bbb")
    assert {_deduplicate_global([x, y])[0].description, _deduplicate_global([y, x])[0].description} == {"bbb"}


def test_distinct_findings_are_all_kept():
    fs = [_f(Severity.HIGH, line=1), _f(Severity.HIGH, line=2), _f(Severity.HIGH, line=1, rule="AST-CMD-001"),
          _f(Severity.HIGH, line=1, path="b.py")]
    assert len(_deduplicate_global(fs)) == 4


def test_output_order_does_not_depend_on_input_order():
    fs = [_f(Severity.HIGH, line=n, path=p) for p in ("b.py", "a.py") for n in (30, 5, 12)]
    expected = [(f.file_path, f.line_number) for f in _deduplicate_global(fs)]
    assert expected == sorted(expected)
    rng = random.Random(7)
    for _ in range(5):
        shuffled = fs[:]
        rng.shuffle(shuffled)
        assert [(f.file_path, f.line_number) for f in _deduplicate_global(shuffled)] == expected


def test_missing_taint_status_does_not_break_the_comparison():
    a, b = _f(Severity.LOW, taint=None), _f(Severity.LOW, taint="tainted")
    assert _deduplicate_global([a, b])[0] is b
