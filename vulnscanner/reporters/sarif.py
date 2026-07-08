"""
SARIF 2.1.0 reporter for GitHub Actions / Code Scanning integration.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from vulnscanner.models import ScanResult, Severity

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
            tags = [f.vuln_type.value]
            if f.cwe_id:
                tags.append(f"external/cwe/cwe-{f.cwe_id}")
            rule_registry[f.rule_id] = {
                "id": f.rule_id,
                "name": _pascal(f.vuln_type.value),
                "shortDescription": {"text": f.description[:200]},
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

        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(f.line_number, 1)},
                }
            }],
        })

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
