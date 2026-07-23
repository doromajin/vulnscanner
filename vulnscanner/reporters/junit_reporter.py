"""JUnit XML reporter — CI integration (Jenkins, GitHub Actions, GitLab CI).

Each finding becomes a failing test case.  A scan with no findings produces
a single passing test so the CI suite remains valid.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from vulnscanner.models import ScanResult


def write_junit_xml(result: ScanResult, output_path: str) -> None:
    """Write scan findings as JUnit-compatible XML."""
    root = ET.Element("testsuites")
    n_fail = len(result.findings)
    suite = ET.SubElement(
        root, "testsuite",
        name="VulnScanner",
        tests=str(max(n_fail, 1)),
        failures=str(n_fail),
        errors="0",
        time=f"{result.elapsed_seconds:.3f}",
    )

    if result.findings:
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            vt  = f.vuln_type.value if hasattr(f.vuln_type, "value") else str(f.vuln_type)
            tc = ET.SubElement(
                suite, "testcase",
                classname=f"security.{sev}",
                name=f"{f.file_path}:{f.line_number} [{f.rule_id}]",
            )
            body_lines = [
                f"Rule:     {f.rule_id}",
                f"Severity: {sev}",
                f"Type:     {vt}",
                f"File:     {f.file_path}:{f.line_number}",
                "",
                f.description,
            ]
            if f.snippet:
                body_lines += ["", "Code:", f.snippet]
            failure = ET.SubElement(
                tc, "failure",
                type=sev,
                message=f.description[:200],
            )
            failure.text = "\n".join(body_lines)
    else:
        ET.SubElement(
            suite, "testcase",
            classname="security.CLEAN",
            name="no security findings",
        )

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    xml_str = ET.tostring(root, encoding="unicode")
    Path(output_path).write_text(  # vulnscanner: ignore[AST-PATH-004]
        '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str,
        encoding="utf-8",
    )
