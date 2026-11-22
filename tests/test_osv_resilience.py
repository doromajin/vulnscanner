from unittest.mock import MagicMock, patch

from vulnscanner.analyzers import dependencies as dep
from vulnscanner.analyzers.dependencies import DependencyAnalyzer

_MANIFEST = '{"dependencies": {"lib": "1.2.3"}}'


def _ok(payload):
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = payload
    return r


def _status(code):
    r = MagicMock()
    r.status_code = code
    r.raise_for_status.side_effect = RuntimeError(f"HTTP {code}")
    return r


def _scan():
    return DependencyAnalyzer().analyze("package.json", _MANIFEST, "")


def setup_function(_):
    dep._osv_detail_cache.clear()


def test_transient_rate_limit_is_retried_and_the_finding_is_kept():
    batch = _ok({"results": [{"vulns": [{"id": "A", "database_specific": {"severity": "HIGH"}, "aliases": ["CVE-1"]}]}]})
    with patch.object(dep.time, "sleep"), patch("requests.post", side_effect=[_status(429), batch]) as post:
        findings = _scan()
    assert post.call_count == 2
    assert [f.rule_id for f in findings] == ["DEP-001"]
    assert findings[0].severity.value == "HIGH"


def test_unreachable_osv_is_reported_not_silently_clean():
    with patch.object(dep.time, "sleep"), patch("requests.post", side_effect=OSError("down")) as post:
        findings = _scan()
    assert post.call_count == dep._OSV_ATTEMPTS
    assert [(f.rule_id, f.severity.value) for f in findings] == [("DEP-002", "INFO")]
    assert "check_incomplete" in findings[0].description


def test_missing_advisory_records_are_marked_partial():
    batch = _ok({"results": [{"vulns": [{"id": "X-1"}]}]})
    with patch.object(dep.time, "sleep"), patch("requests.post", return_value=batch), \
            patch("requests.get", side_effect=OSError("down")):
        findings = _scan()
    assert findings[0].rule_id == "DEP-001"
    assert "[partial" in findings[0].description


def test_complete_records_are_not_marked_partial():
    batch = _ok({"results": [{"vulns": [{"id": "X-1"}]}]})
    record = _ok({"id": "X-1", "aliases": ["CVE-9"], "database_specific": {"severity": "LOW"}})
    with patch("requests.post", return_value=batch), patch("requests.get", return_value=record):
        findings = _scan()
    assert "[partial" not in findings[0].description
