"""
SARIF 2.1.0 reporter for GitHub Actions / Code Scanning integration.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from vulnscanner.models import ScanResult, Severity
from vulnscanner.reporters.fix_suggestions import get_fix, get_cwe

_VERSION = "0.2.0"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def write_sarif(result: ScanResult, output_path: str) -> None:
    """Serialize *result* to a SARIF 2.1.0 JSON file at *output_path*."""
    rule_registry: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for f in result.findings:
        if f.rule_id not in rule_registry:
            fix = get_fix(f.vuln_type)
            cwe = f.cwe_id or get_cwe(f.vuln_type)
            tags = [f.vuln_type.value]
            if cwe:
                tags.append(f"external/cwe/cwe-{cwe}")
            rule_registry[f.rule_id] = {
                "id": f.rule_id,
                "name": _pascal(f.vuln_type.value),
                "shortDescription": {"text": f.vuln_type.value},
                "fullDescription": {"text": fix["text"]},
                "help": {
                    "text": fix["text"],
                    "markdown": fix["markdown"],
                },
                "defaultConfiguration": {
                    "level": _LEVEL.get(f.severity, "warning")
                },
                "helpUri": "https://github.com/doromajin/VulnScanner",
                "properties": {
                    "tags": tags,
                    **({"security-severity": _cvss(f.severity)} if f.severity in (Severity.CRITICAL, Severity.HIGH) else {}),
                },
            }

        uri = f.file_path.replace("\\", "/").lstrip("/")

        result_props: dict = {}
        if f.confidence < 1.0:
            result_props["confidence"] = round(f.confidence, 3)
        if f.taint_status:
            result_props["taint_status"] = f.taint_status
        if f.taint_source:
            result_props["taint_source"] = f.taint_source

        sarif_result: dict = {
            "ruleId": f.rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            # rank: 0–100 (higher = more urgent). Derived from confidence so that
            # [low_reach] UNKNOWN findings (confidence=0.3) sort below confirmed
            # TAINTED findings (confidence=0.9) in IDE triage views.
            "rank": round(f.confidence * 100, 1),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(f.line_number, 1),
                        **({"snippet": {"text": f.line_content}} if f.line_content else {}),
                    },
                }
            }],
        }
        if result_props:
            sarif_result["properties"] = result_props
        sarif_results.append(sarif_result)

    doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VulnScanner",
                    "version": _VERSION,
                    "informationUri": "https://github.com/doromajin/VulnScanner",
                    "rules": list(rule_registry.values()),
                }
            },
            "results": sarif_results,
        }],
    }

    Path(output_path).write_text(
        json.dumps(doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _cvss(severity: Severity) -> str:
    """Return a CVSS-like numeric string for GitHub's severity filter."""
    return "9.0" if severity == Severity.CRITICAL else "7.5"


def _pascal(text: str) -> str:
    """'SQL Injection' → 'SqlInjection'"""
    return "".join(
        w.capitalize()
        for w in re.sub(r"[^a-zA-Z0-9]+", " ", text).split()
    )
