"""Tests for YAML custom rule system."""
from __future__ import annotations

import textwrap
import tempfile
from pathlib import Path

import pytest

from vulnscanner.rules.loader import load_rules_from_file, load_rules, CustomRule
from vulnscanner.analyzers.custom_rule_analyzer import CustomRuleAnalyzer
from vulnscanner.models import Severity, VulnType


# ── helpers ───────────────────────────────────────────────────────────────────

def _write_yaml(content: str) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(textwrap.dedent(content))
        return fh.name


SIMPLE_RULE_YAML = """
- id: TEST-001
  message: "Dangerous function call"
  severity: HIGH
  vuln_type: COMMAND_INJECTION
  languages: [python]
  pattern: "dangerous($X)"
"""

REGEX_RULE_YAML = """
- id: TEST-002
  message: "MD5 hash detected"
  severity: MEDIUM
  vuln_type: WEAK_CRYPTOGRAPHY
  cwe: 328
  languages: [python]
  regex: "hashlib\\\\.md5\\\\s*\\\\("
"""

MULTI_LANG_YAML = """
- id: TEST-003
  message: "XSS via innerHTML"
  severity: HIGH
  vuln_type: XSS
  languages: [javascript, typescript]
  regex: "\\\\.innerHTML\\\\s*="
"""


# ── loader tests ──────────────────────────────────────────────────────────────

class TestRuleLoader:
    def test_load_pattern_rule(self):
        path = _write_yaml(SIMPLE_RULE_YAML)
        rules = load_rules_from_file(path)
        assert len(rules) == 1
        r = rules[0]
        assert r.id == "TEST-001"
        assert r.severity == Severity.HIGH
        assert r.vuln_type == VulnType.COMMAND_INJECTION
        assert "python" in r.languages
        assert ".py" in r.extensions

    def test_load_regex_rule(self):
        path = _write_yaml(REGEX_RULE_YAML)
        rules = load_rules_from_file(path)
        assert len(rules) == 1
        r = rules[0]
        assert r.id == "TEST-002"
        assert r.cwe == 328

    def test_load_multi_language_rule(self):
        path = _write_yaml(MULTI_LANG_YAML)
        rules = load_rules_from_file(path)
        assert len(rules) == 1
        r = rules[0]
        assert ".js" in r.extensions
        assert ".ts" in r.extensions

    def test_empty_file_returns_empty(self):
        path = _write_yaml("")
        rules = load_rules_from_file(path)
        assert rules == []

    def test_rules_key_at_top_level(self):
        yaml = """
rules:
  - id: TEST-004
    message: "Test"
    severity: LOW
    vuln_type: XSS
    languages: [python]
    pattern: "bad($X)"
"""
        path = _write_yaml(yaml)
        rules = load_rules_from_file(path)
        assert len(rules) == 1
        assert rules[0].id == "TEST-004"

    def test_invalid_severity_warns(self):
        yaml = """
- id: TEST-BAD
  message: "Bad severity"
  severity: EXTREME
  vuln_type: XSS
  languages: [python]
  pattern: "bad($X)"
"""
        path = _write_yaml(yaml)
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            rules = load_rules_from_file(path)
        assert len(rules) == 0
        assert any("severity" in str(warning.message).lower() or
                   "EXTREME" in str(warning.message) for warning in w)

    def test_missing_pattern_and_regex_warns(self):
        yaml = """
- id: TEST-NOPAT
  message: "No pattern"
  severity: HIGH
  vuln_type: XSS
  languages: [python]
"""
        path = _write_yaml(yaml)
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            rules = load_rules_from_file(path)
        assert len(rules) == 0
        assert len(w) > 0


# ── pattern matching tests ────────────────────────────────────────────────────

class TestPatternMatching:
    def _rule(self, pattern: str, lang: str = "python") -> CustomRule:
        yaml = f"""
- id: PAT-TEST
  message: "test"
  severity: HIGH
  vuln_type: COMMAND_INJECTION
  languages: [{lang}]
  pattern: "{pattern}"
"""
        return load_rules_from_file(_write_yaml(yaml))[0]

    def test_simple_pattern_matches(self):
        r = self._rule("dangerous($X)")
        assert r.matches("result = dangerous(user_input)")

    def test_simple_pattern_no_match(self):
        r = self._rule("dangerous($X)")
        assert not r.matches("result = safe(user_input)")

    def test_wildcard_matches_complex_expression(self):
        r = self._rule("os.system($X)")
        assert r.matches('os.system(cmd + " " + arg)')

    def test_wildcard_matches_nothing(self):
        r = self._rule("os.system($X)")
        assert r.matches("os.system()")

    def test_multiple_wildcards(self):
        r = self._rule("conn.execute($SQL, $PARAMS)")
        assert r.matches('conn.execute("SELECT * FROM t WHERE id=" + x, params)')


# ── analyzer tests ────────────────────────────────────────────────────────────

class TestCustomRuleAnalyzer:
    def _analyzer(self) -> CustomRuleAnalyzer:
        path = _write_yaml(SIMPLE_RULE_YAML)
        rules = load_rules_from_file(path)
        return CustomRuleAnalyzer(rules)

    def test_detects_match_in_python_file(self):
        analyzer = self._analyzer()
        code = "result = dangerous(user_input)\n"
        findings = analyzer.analyze("app.py", code)
        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-001"
        assert findings[0].line_number == 1

    def test_no_match_on_wrong_extension(self):
        analyzer = self._analyzer()
        code = "result = dangerous(user_input)\n"
        findings = analyzer.analyze("app.java", code)
        assert findings == []

    def test_inline_ignore_suppresses(self):
        analyzer = self._analyzer()
        code = "result = dangerous(user_input)  # vulnscanner: ignore\n"
        findings = analyzer.analyze("app.py", code)
        assert findings == []

    def test_comment_line_skipped(self):
        analyzer = self._analyzer()
        code = "# dangerous(user_input)\n"
        findings = analyzer.analyze("app.py", code)
        assert findings == []

    def test_multiple_matches_reported(self):
        analyzer = self._analyzer()
        code = "dangerous(a)\ndangerous(b)\n"
        findings = analyzer.analyze("app.py", code)
        assert len(findings) == 2

    def test_dedup_same_line_same_rule(self):
        analyzer = self._analyzer()
        # Two patterns on one line shouldn't duplicate if same rule
        code = "x = dangerous(dangerous(a))\n"
        findings = analyzer.analyze("app.py", code)
        assert len(findings) == 1


# ── built-in rules tests ──────────────────────────────────────────────────────

class TestBuiltinRules:
    @pytest.fixture(scope="class")
    def builtin_rules(self):
        builtin_dir = Path(__file__).parent.parent / "vulnscanner" / "rules" / "builtin"
        return load_rules(([str(builtin_dir)]))

    def test_builtin_rules_load(self, builtin_rules):
        assert len(builtin_rules) >= 15

    def test_yaml_load_detected(self, builtin_rules):
        py_rules = [r for r in builtin_rules if "python" in r.languages]
        matches = [r.id for r in py_rules if r.matches("data = yaml.load(stream)")]
        assert "PY-DESER-001" in matches

    def test_yaml_safe_load_not_detected(self, builtin_rules):
        py_rules = [r for r in builtin_rules if "python" in r.languages]
        matches = [r.id for r in py_rules if r.matches("data = yaml.safe_load(stream)")]
        assert "PY-DESER-001" not in matches

    def test_md5_detected(self, builtin_rules):
        py_rules = [r for r in builtin_rules if "python" in r.languages]
        matches = [r.id for r in py_rules if r.matches("h = hashlib.md5()")]
        assert "PY-HASH-001" in matches

    def test_innerHTML_detected_for_js(self, builtin_rules):
        js_rules = [r for r in builtin_rules if "javascript" in r.languages]
        matches = [r.id for r in js_rules if r.matches("el.innerHTML = userInput")]
        assert "JS-XSS-001" in matches

    def test_java_readobject_detected(self, builtin_rules):
        java_rules = [r for r in builtin_rules if "java" in r.languages]
        matches = [r.id for r in java_rules if r.matches("Object obj = ois.readObject()")]
        assert "JAVA-SERIAL-001" in matches

    def test_load_rules_from_directory(self, builtin_rules):
        # All rule IDs should be unique
        ids = [r.id for r in builtin_rules]
        assert len(ids) == len(set(ids))
