"""
Persistent knowledge base for confirmed vulnerabilities and false positives.

Every confirmed real vulnerability is recorded here so that:
1. Future scans can annotate matching patterns as "confirmed pattern"
2. Claude can review the knowledge base and improve detection rules
3. Statistics show which rules are most effective at catching real vulns

Store path: ~/.vulnscanner/knowledge.json
"""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

DEFAULT_KNOWLEDGE_PATH = Path.home() / ".vulnscanner" / "knowledge.json"

# Rule ID -> (vuln_type, default_severity) for auto-filling confirm entries
_RULE_META: dict[str, tuple[str, str]] = {
    "AST-CMD-001": ("Command Injection", "HIGH"),
    "AST-CMD-002": ("Command Injection", "HIGH"),
    "AST-CMD-003": ("Command Injection", "HIGH"),
    "AST-CMD-004": ("Command Injection", "CRITICAL"),
    "AST-SQL-001": ("SQL Injection", "HIGH"),
    "AST-SQL-002": ("SQL Injection", "HIGH"),
    "AST-SQL-003": ("SQL Injection", "HIGH"),
    "AST-SQL-004": ("SQL Injection", "HIGH"),
    "AST-PATH-001": ("Path Traversal", "HIGH"),
    "AST-PATH-002": ("Path Traversal", "MEDIUM"),
    "AST-PATH-003": ("Path Traversal", "LOW"),
    "AST-SSRF-001": ("SSRF", "HIGH"),
    "AST-SSRF-002": ("SSRF", "MEDIUM"),
    "AST-REDIR-001": ("Open Redirect", "MEDIUM"),
    "XSS-001": ("Cross-Site Scripting (XSS)", "HIGH"),
    "XSS-002": ("Cross-Site Scripting (XSS)", "HIGH"),
    "XSS-004": ("Cross-Site Scripting (XSS)", "MEDIUM"),
    "CLIENT-CRED-001": ("Credential Storage", "MEDIUM"),
    "CLIENT-SRI-001": ("Supply Chain Risk", "LOW"),
    "CLIENT-SRI-002": ("Supply Chain Risk", "LOW"),
    "CLIENT-FETCH-001": ("SSRF", "MEDIUM"),
    "CLIENT-MSG-001": ("Cross-Site Scripting (XSS)", "MEDIUM"),
    "SEC-001": ("Hardcoded Secret", "HIGH"),
    "SEC-004": ("Hardcoded Secret", "HIGH"),
    "SEC-005": ("Hardcoded Secret", "CRITICAL"),
    "DESER-005": ("Insecure Deserialization", "CRITICAL"),
    "SQL-001": ("SQL Injection", "HIGH"),
    "SSRF-003": ("SSRF", "MEDIUM"),
    "CMD-007": ("Command Injection", "HIGH"),
}

_EMPTY_DB: dict[str, Any] = {
    "version": 1,
    "confirmed_vulns": [],
    "false_positives": [],
    "rule_improvements": [],
}


class KnowledgeStore:
    def __init__(self, path: Path | str = DEFAULT_KNOWLEDGE_PATH) -> None:
        self.path = Path(path)
        self._data = self._load()

    # ── persistence ────────────────────────────────────────────────────────────

    def _load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {k: list(v) if isinstance(v, list) else v for k, v in _EMPTY_DB.items()}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # ── confirmed vulnerabilities ──────────────────────────────────────────────

    def add_confirmed(
        self,
        repo: str,
        file: str,
        line: int,
        rule_id: str,
        *,
        code_snippet: str = "",
        notes: str = "",
        vuln_type: str = "",
        severity: str = "",
    ) -> str:
        """Record a confirmed real vulnerability. Returns the assigned ID."""
        meta = _RULE_META.get(rule_id, ("Unknown", "UNKNOWN"))
        n = len(self._data["confirmed_vulns"]) + 1
        entry = {
            "id": f"CONF-{n:04d}",
            "repo": repo,
            "file": file,
            "line": line,
            "rule_id": rule_id,
            "vuln_type": vuln_type or meta[0],
            "severity": severity or meta[1],
            "code_snippet": code_snippet,
            "notes": notes,
            "confirmed_at": str(date.today()),
        }
        self._data["confirmed_vulns"].append(entry)
        self._save()
        return entry["id"]

    def add_false_positive(
        self,
        repo: str,
        file: str,
        line: int,
        rule_id: str,
        *,
        reason: str,
        fix_applied: str = "",
    ) -> str:
        """Record a false positive finding. Returns the assigned ID."""
        n = len(self._data["false_positives"]) + 1
        entry = {
            "id": f"FP-{n:04d}",
            "repo": repo,
            "file": file,
            "line": line,
            "rule_id": rule_id,
            "reason": reason,
            "fix_applied": fix_applied,
            "confirmed_at": str(date.today()),
        }
        self._data["false_positives"].append(entry)
        self._save()
        return entry["id"]

    def add_rule_improvement(
        self,
        rule_id: str,
        change: str,
        triggered_by: str = "",
    ) -> None:
        """Log a rule improvement that was implemented in response to a finding."""
        self._data.setdefault("rule_improvements", []).append({
            "rule_id": rule_id,
            "change": change,
            "triggered_by": triggered_by,
            "implemented_at": str(date.today()),
        })
        self._save()

    # ── queries ────────────────────────────────────────────────────────────────

    def list_confirmed(self) -> list[dict]:
        return self._data["confirmed_vulns"]

    def list_false_positives(self) -> list[dict]:
        return self._data.get("false_positives", [])

    def list_rule_improvements(self) -> list[dict]:
        return self._data.get("rule_improvements", [])

    def confirmed_by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self._data["confirmed_vulns"]:
            counts[v["rule_id"]] = counts.get(v["rule_id"], 0) + 1
        return counts

    def stats(self) -> dict[str, Any]:
        confirmed = self._data["confirmed_vulns"]
        fps = self._data.get("false_positives", [])
        improvements = self._data.get("rule_improvements", [])
        total = len(confirmed) + len(fps)
        precision = len(confirmed) / total if total else 1.0

        sev_counts: dict[str, int] = {}
        for v in confirmed:
            sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1

        return {
            "confirmed_count": len(confirmed),
            "false_positive_count": len(fps),
            "rule_improvement_count": len(improvements),
            "precision": precision,
            "by_severity": sev_counts,
            "by_rule": self.confirmed_by_rule(),
        }

    # ── learning helpers ───────────────────────────────────────────────────────

    def get_confirmed_pattern_keys(self) -> set[tuple[str, str]]:
        """Return (rule_id, file_basename) pairs for all confirmed vulns.

        Used during scan to annotate findings that match known patterns.
        """
        return {
            (v["rule_id"], Path(v["file"]).name)
            for v in self._data["confirmed_vulns"]
        }

    def lookup_rule_history(self, rule_id: str) -> dict[str, Any]:
        """Return confirmed + FP counts for a rule, useful for learning reports."""
        confirmed = [v for v in self._data["confirmed_vulns"] if v["rule_id"] == rule_id]
        fps = [v for v in self._data.get("false_positives", []) if v["rule_id"] == rule_id]
        improvements = [
            i for i in self._data.get("rule_improvements", []) if i["rule_id"] == rule_id
        ]
        total = len(confirmed) + len(fps)
        return {
            "rule_id": rule_id,
            "confirmed": len(confirmed),
            "false_positives": len(fps),
            "precision": len(confirmed) / total if total else 1.0,
            "improvements": improvements,
            "latest_confirmed": confirmed[-1] if confirmed else None,
        }

    def suggest_rule_improvement(self, rule_id: str) -> str | None:
        """If a rule has multiple FPs but few confirmed, suggest tightening it."""
        hist = self.lookup_rule_history(rule_id)
        if hist["false_positives"] >= 2 and hist["confirmed"] == 0:
            return (
                f"Rule {rule_id} has {hist['false_positives']} recorded false positive(s) "
                f"and no confirmed true positives - consider raising its severity threshold "
                f"or narrowing the detection pattern."
            )
        if hist["false_positives"] >= 1 and hist["confirmed"] >= 1:
            precision = hist["precision"]
            if precision < 0.5:
                return (
                    f"Rule {rule_id} precision is {precision:.0%} "
                    f"({hist['confirmed']} TP / {hist['false_positives']} FP) - "
                    f"review and tighten the detection pattern."
                )
        return None
