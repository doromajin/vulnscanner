import json
from dataclasses import asdict

from vulnscanner.models import ScanResult


def to_dict(result: ScanResult) -> dict:
    from vulnscanner.models import Severity
    return {
        "repo_url": result.repo_url,
        "summary": {
            "total_findings": result.finding_count,
            "suppressed_count": result.suppressed_count,
            "suppression_breakdown": result.suppression_breakdown,
            "scanned_files": result.scanned_files,
            "scanned_lines": result.scanned_lines,
            "elapsed_seconds": round(result.elapsed_seconds, 2),
            "by_severity": {
                s.value: len(result.by_severity(s)) for s in Severity
            },
        },
        "findings": [asdict(f) for f in result.findings],
        "errors": result.errors,
    }


def write_json(result: ScanResult, output_path: str) -> None:
    data = to_dict(result)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
