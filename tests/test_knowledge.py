"""Tests for the knowledge base store."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from vulnscanner.knowledge.store import KnowledgeStore


@pytest.fixture
def store(tmp_path):
    return KnowledgeStore(path=tmp_path / "knowledge.json")


class TestKnowledgeStoreConfirmed:
    def test_add_confirmed_returns_id(self, store):
        eid = store.add_confirmed("myrepo", "worker.py", 103, "AST-CMD-002")
        assert eid == "CONF-0001"

    def test_add_confirmed_increments_id(self, store):
        store.add_confirmed("r", "a.py", 1, "AST-CMD-002")
        eid = store.add_confirmed("r", "b.py", 2, "AST-SQL-001")
        assert eid == "CONF-0002"

    def test_add_confirmed_fills_meta_from_rule(self, store):
        store.add_confirmed("r", "w.py", 103, "AST-CMD-002")
        entries = store.list_confirmed()
        assert entries[0]["vuln_type"] == "Command Injection"
        assert entries[0]["severity"] == "HIGH"

    def test_add_confirmed_persists_to_disk(self, store):
        store.add_confirmed("r", "w.py", 103, "AST-CMD-002", notes="shell=True")
        data = json.loads(store.path.read_text(encoding="utf-8"))
        assert len(data["confirmed_vulns"]) == 1
        assert data["confirmed_vulns"][0]["notes"] == "shell=True"

    def test_add_confirmed_with_snippet(self, store):
        store.add_confirmed("r", "w.py", 103, "AST-CMD-002", code_snippet="Popen(cmd, shell=True)")
        assert store.list_confirmed()[0]["code_snippet"] == "Popen(cmd, shell=True)"

    def test_reload_from_disk(self, store):
        store.add_confirmed("r", "w.py", 103, "AST-CMD-002")
        store2 = KnowledgeStore(path=store.path)
        assert len(store2.list_confirmed()) == 1


class TestKnowledgeStoreFalsePositives:
    def test_add_false_positive_returns_id(self, store):
        eid = store.add_false_positive("r", "ui.py", 104, "AST-PATH-001",
                                        reason="server-side dict")
        assert eid == "FP-0001"

    def test_add_false_positive_increments_id(self, store):
        store.add_false_positive("r", "a.py", 1, "AST-PATH-001", reason="x")
        eid = store.add_false_positive("r", "b.py", 2, "AST-CMD-002", reason="y")
        assert eid == "FP-0002"

    def test_list_false_positives(self, store):
        store.add_false_positive("r", "ui.py", 104, "AST-PATH-001",
                                  reason="server dict", fix_applied="removed data")
        fps = store.list_false_positives()
        assert len(fps) == 1
        assert fps[0]["reason"] == "server dict"
        assert fps[0]["fix_applied"] == "removed data"


class TestKnowledgeStoreStats:
    def test_stats_empty(self, store):
        s = store.stats()
        assert s["confirmed_count"] == 0
        assert s["false_positive_count"] == 0
        assert s["precision"] == 1.0

    def test_stats_with_entries(self, store):
        store.add_confirmed("r", "w.py", 103, "AST-CMD-002")
        store.add_confirmed("r", "w.py", 121, "AST-CMD-002")
        store.add_false_positive("r", "ui.py", 104, "AST-PATH-001", reason="x")
        s = store.stats()
        assert s["confirmed_count"] == 2
        assert s["false_positive_count"] == 1
        assert abs(s["precision"] - 2 / 3) < 0.001
        assert s["by_severity"]["HIGH"] == 2
        assert s["by_rule"]["AST-CMD-002"] == 2


class TestKnowledgeStoreLookup:
    def test_lookup_rule_history_no_entries(self, store):
        hist = store.lookup_rule_history("AST-CMD-002")
        assert hist["confirmed"] == 0
        assert hist["false_positives"] == 0
        assert hist["precision"] == 1.0

    def test_lookup_rule_history_with_entries(self, store):
        store.add_confirmed("r", "w.py", 103, "AST-CMD-002")
        store.add_false_positive("r", "u.py", 1, "AST-CMD-002", reason="x")
        hist = store.lookup_rule_history("AST-CMD-002")
        assert hist["confirmed"] == 1
        assert hist["false_positives"] == 1
        assert hist["precision"] == 0.5

    def test_get_confirmed_pattern_keys(self, store):
        store.add_confirmed("r", "worker/worker.py", 103, "AST-CMD-002")
        keys = store.get_confirmed_pattern_keys()
        assert ("AST-CMD-002", "worker.py") in keys

    def test_no_false_negative_in_pattern_keys(self, store):
        # Only confirmed vulns, not FPs, go into pattern keys
        store.add_false_positive("r", "ui.py", 104, "AST-PATH-001", reason="x")
        keys = store.get_confirmed_pattern_keys()
        assert len(keys) == 0


class TestKnowledgeStoreSuggestions:
    def test_suggest_when_multiple_fps_no_tp(self, store):
        store.add_false_positive("r", "a.py", 1, "AST-PATH-001", reason="x")
        store.add_false_positive("r", "b.py", 2, "AST-PATH-001", reason="y")
        s = store.suggest_rule_improvement("AST-PATH-001")
        assert s is not None
        assert "AST-PATH-001" in s

    def test_no_suggestion_for_high_precision(self, store):
        store.add_confirmed("r", "w.py", 1, "AST-CMD-002")
        store.add_confirmed("r", "w.py", 2, "AST-CMD-002")
        s = store.suggest_rule_improvement("AST-CMD-002")
        assert s is None

    def test_suggest_when_precision_below_50pct(self, store):
        store.add_confirmed("r", "w.py", 1, "AST-CMD-002")
        store.add_false_positive("r", "a.py", 1, "AST-CMD-002", reason="x")
        store.add_false_positive("r", "b.py", 2, "AST-CMD-002", reason="y")
        s = store.suggest_rule_improvement("AST-CMD-002")
        assert s is not None
        assert "33%" in s


class TestKnowledgeStoreRuleImprovements:
    def test_add_rule_improvement(self, store):
        store.add_rule_improvement("AST-PATH-001", "Removed 'data' from USER_INPUT_NAMES",
                                    triggered_by="FP-0001")
        imps = store.list_rule_improvements()
        assert len(imps) == 1
        assert imps[0]["change"] == "Removed 'data' from USER_INPUT_NAMES"
        assert imps[0]["triggered_by"] == "FP-0001"
        assert imps[0]["rule_id"] == "AST-PATH-001"
