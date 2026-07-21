"""Tests for HTML reporter, baseline comparison, vulnscanner init, and --stdout-json."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from vulnscanner.reporters.baseline import load_baseline, split_findings
from vulnscanner.reporters.html_reporter import write_html
from vulnscanner.models import ScanResult, Finding, Severity, VulnType


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_finding(rule_id="AST-SQL-001", file_path="app.py", line=10,
                  severity=Severity.HIGH, vuln_type=VulnType.SQL_INJECTION):
    return Finding(
        rule_id=rule_id,
        vuln_type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_number=line,
        line_content="conn.execute(query)",
        description="Test finding",
        confidence=0.8,
        snippet="conn.execute(query)",
    )


def _make_result(findings=None):
    return ScanResult(
        repo_url="test/repo",
        findings=findings or [],
        errors=[],
        scanned_files=5,
        scanned_lines=200,
        elapsed_seconds=1.0,
    )


# ── HTML reporter ─────────────────────────────────────────────────────────────

class TestHtmlReporter:
    def test_writes_valid_html_file(self):
        result = _make_result([_make_finding()])
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
            path = fh.name
        write_html(result, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "AST-SQL-001" in content
        assert "app.py" in content

    def test_empty_findings_shows_no_findings_message(self):
        result = _make_result([])
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
            path = fh.name
        write_html(result, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "No findings" in content

    def test_new_badge_when_baseline_active(self):
        f = _make_finding()
        result = _make_result([f])
        new_keys = {(f.file_path, f.line_number, f.rule_id)}
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
            path = fh.name
        write_html(result, path, new_finding_keys=new_keys)
        content = Path(path).read_text(encoding="utf-8")
        assert "NEW" in content
        assert "Baseline comparison active" in content

    def test_no_new_badge_when_no_baseline(self):
        result = _make_result([_make_finding()])
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
            path = fh.name
        write_html(result, path, new_finding_keys=None)
        content = Path(path).read_text(encoding="utf-8")
        # new-badge span elements should not be rendered (class may appear in CSS only)
        assert '<span class="new-badge">' not in content

    def test_fix_suggestion_included(self):
        result = _make_result([_make_finding(vuln_type=VulnType.SQL_INJECTION)])
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
            path = fh.name
        write_html(result, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "Suggested Fix" in content

    def test_self_contained_no_external_resources(self):
        result = _make_result([_make_finding()])
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
            path = fh.name
        write_html(result, path)
        content = Path(path).read_text(encoding="utf-8")
        # No external stylesheet or script references
        assert 'href="http' not in content
        assert 'src="http' not in content


# ── baseline comparison ───────────────────────────────────────────────────────

class TestBaseline:
    def _write_baseline_json(self, findings: list) -> str:
        data = {
            "repo_url": "test/repo",
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "vuln_type": f.vuln_type.value,
                    "severity": f.severity.value,
                    "description": "test",
                    "confidence": 0.8,
                }
                for f in findings
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            return fh.name

    def test_load_baseline_returns_correct_keys(self):
        f = _make_finding(file_path="a.py", line=5, rule_id="AST-SQL-001")
        path = self._write_baseline_json([f])
        keys = load_baseline(path)
        assert ("a.py", 5, "AST-SQL-001") in keys

    def test_known_finding_excluded_from_new(self):
        known = _make_finding(file_path="a.py", line=5)
        new   = _make_finding(file_path="b.py", line=9, rule_id="AST-CMD-001",
                              vuln_type=VulnType.COMMAND_INJECTION)
        path = self._write_baseline_json([known])
        baseline_keys = load_baseline(path)
        new_f, known_f = split_findings([known, new], baseline_keys)
        assert len(new_f) == 1
        assert new_f[0].rule_id == "AST-CMD-001"
        assert len(known_f) == 1
        assert known_f[0].rule_id == known.rule_id

    def test_empty_baseline_all_findings_are_new(self):
        path = self._write_baseline_json([])
        baseline_keys = load_baseline(path)
        f = _make_finding()
        new_f, known_f = split_findings([f], baseline_keys)
        assert len(new_f) == 1
        assert len(known_f) == 0

    def test_load_baseline_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            fh.write("not json")
            path = fh.name
        with pytest.raises(Exception):
            load_baseline(path)


# ── vulnscanner init ──────────────────────────────────────────────────────────

class TestVulnscannerInit:
    def test_creates_gha_workflow_and_config(self):
        from click.testing import CliRunner
        from vulnscanner.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 0, result.output
            assert Path(".github/workflows/vulnscanner.yml").exists()
            assert Path("vulnscanner.yml").exists()

    def test_workflow_contains_sarif_upload(self):
        from click.testing import CliRunner
        from vulnscanner.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem():
            runner.invoke(main, ["init"])
            content = Path(".github/workflows/vulnscanner.yml").read_text()
            assert "upload-sarif" in content
            assert "vulnscanner.sarif" in content

    def test_skip_existing_without_force(self):
        from click.testing import CliRunner
        from vulnscanner.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem():
            runner.invoke(main, ["init"])
            # Run again — should skip existing files
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 0
            assert "Skipped" in result.output

    def test_force_overwrites_existing(self):
        from click.testing import CliRunner
        from vulnscanner.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem():
            runner.invoke(main, ["init"])
            # Corrupt the config
            Path("vulnscanner.yml").write_text("broken")
            runner.invoke(main, ["init", "--force"])
            content = Path("vulnscanner.yml").read_text(encoding="utf-8")
            assert "min_severity" in content  # restored to valid content


# ── --stdout-json ─────────────────────────────────────────────────────────────

class TestStdoutJson:
    def test_stdout_json_outputs_valid_json(self, tmp_path):
        from click.testing import CliRunner
        from vulnscanner.cli import main

        # Write a trivially safe Python file so scan has something to process
        (tmp_path / "safe.py").write_text("x = 1\n")
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ["scan", str(tmp_path), "--stdout-json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "findings" in data
        assert "summary" in data

    def test_stdout_json_contains_findings_for_vuln_code(self, tmp_path):
        from click.testing import CliRunner
        from vulnscanner.cli import main

        (tmp_path / "vuln.py").write_text(
            "import os\ndef f(x): os.system(x)\n"
        )
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ["scan", str(tmp_path), "--stdout-json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert any("CMD" in r for r in rule_ids)

    def test_stdout_json_no_rich_table_in_output(self, tmp_path):
        from click.testing import CliRunner
        from vulnscanner.cli import main

        (tmp_path / "safe.py").write_text("x = 1\n")
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ["scan", str(tmp_path), "--stdout-json"])
        # Rich table characters should not appear in stdout
        assert "─" not in result.output
        assert "Summary" not in result.output
