"""
Dependency vulnerability scanner.

Reads dependency manifest files and checks declared packages against the
OSV (Open Source Vulnerabilities) database: https://api.osv.dev/v1/querybatch

Supported manifests:
  requirements.txt / requirements-dev.txt / requirements-test.txt  (PyPI)
  package.json                                                       (npm)
  Gemfile.lock                                                       (RubyGems)
  go.mod                                                             (Go)
  Pipfile / Pipfile.lock                                             (PyPI)
"""
from __future__ import annotations

import json
import os
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_DEPENDENCY_FILENAMES = frozenset({
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "Pipfile",
    "Pipfile.lock",
    "package.json",
    "Gemfile.lock",
    "go.mod",
})

_OSV_API = "https://api.osv.dev/v1/querybatch"
_OSV_TIMEOUT = 15  # seconds

# (name, version, ecosystem, lineno)
_Package = tuple[str, str, str, int]


class DependencyAnalyzer(BaseAnalyzer):
    """Check dependency files for packages with known CVEs via OSV.dev."""

    def supports(self, file_path: str) -> bool:
        name = os.path.basename(file_path.replace("\\", "/"))
        return name in _DEPENDENCY_FILENAMES

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        filename = os.path.basename(file_path.replace("\\", "/"))
        packages = self._parse(filename, content)
        if not packages:
            return []
        return self._check_osv(packages, file_path, repo_url)

    # ── parsers ───────────────────────────────────────────────────────────────

    def _parse(self, filename: str, content: str) -> list[_Package]:
        """Dispatch to the correct parser by filename."""
        if filename in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
            return _parse_requirements(content)
        if filename == "package.json":
            return _parse_package_json(content)
        if filename == "Gemfile.lock":
            return _parse_gemfile_lock(content)
        if filename == "go.mod":
            return _parse_go_mod(content)
        if filename in ("Pipfile", "Pipfile.lock"):
            return _parse_pipfile(content)
        return []

    # ── OSV query ─────────────────────────────────────────────────────────────

    def _check_osv(
        self,
        packages: list[_Package],
        file_path: str,
        repo_url: str,
    ) -> list[Finding]:
        try:
            import requests as req_lib
        except ImportError:
            return []

        queries = [
            {"package": {"name": name, "ecosystem": eco}, "version": ver}
            for name, ver, eco, _ in packages
        ]

        try:
            resp = req_lib.post(
                _OSV_API,
                json={"queries": queries},
                timeout=_OSV_TIMEOUT,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except Exception:
            return []  # don't crash the scan when OSV is unreachable

        findings: list[Finding] = []
        for (name, ver, _eco, lineno), result in zip(packages, results):
            vulns = result.get("vulns", [])
            if not vulns:
                continue

            cve_ids = [
                a
                for v in vulns
                for a in v.get("aliases", [])
                if a.startswith("CVE-")
            ]
            sev = _osv_severity(vulns[0])

            count = len(vulns)
            desc = f"{name} {ver} has {count} known vulnerability" + ("s" if count > 1 else "")
            if cve_ids:
                desc += f" ({', '.join(cve_ids[:3])})"

            findings.append(Finding(
                vuln_type=VulnType.VULNERABLE_DEPENDENCY,
                severity=sev,
                file_path=file_path,
                line_number=lineno,
                line_content=f"{name}=={ver}",
                description=desc,
                rule_id="DEP-001",
                repo_url=repo_url,
            ))

        return findings


# ── file parsers ───────────────────────────────────────────────────────────────

_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"\s*==\s*"                                           # == (exact pin only)
    r"([A-Za-z0-9._-]+)"                                 # version
)


def _parse_requirements(content: str) -> list[_Package]:
    packages: list[_Package] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            packages.append((m.group(1), m.group(2), "PyPI", lineno))
    return packages


def _parse_package_json(content: str) -> list[_Package]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    packages: list[_Package] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver_spec in data.get(section, {}).items():
            ver = re.sub(r"^[^0-9]*", "", str(ver_spec))
            if ver and re.match(r"^\d", ver):
                packages.append((name, ver, "npm", 1))
    return packages


def _parse_gemfile_lock(content: str) -> list[_Package]:
    packages: list[_Package] = []
    in_gems = False
    for lineno, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped in ("GEM", "GEM:"):
            in_gems = True
            continue
        if in_gems and not line.startswith(" "):
            in_gems = False
        if in_gems:
            m = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([0-9][^)]*)\)", line)
            if m:
                packages.append((m.group(1), m.group(2), "RubyGems", lineno))
    return packages


def _parse_go_mod(content: str) -> list[_Package]:
    packages: list[_Package] = []
    in_require = False
    for lineno, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if "require (" in stripped:
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require:
            m = re.match(r"^\s+([^\s]+)\s+v([^\s/]+)", line)
            if m:
                packages.append((m.group(1), m.group(2), "Go", lineno))
        else:
            m = re.match(r"^require\s+([^\s]+)\s+v([^\s/]+)", stripped)
            if m:
                packages.append((m.group(1), m.group(2), "Go", lineno))
    return packages


def _parse_pipfile(content: str) -> list[_Package]:
    """Parse [packages] / [dev-packages] sections of a Pipfile."""
    packages: list[_Package] = []
    in_packages = False
    for lineno, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped in ("[packages]", "[dev-packages]"):
            in_packages = True
            continue
        if stripped.startswith("["):
            in_packages = False
            continue
        if in_packages:
            m = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*"==([^"]+)"', stripped)
            if m:
                packages.append((m.group(1), m.group(2), "PyPI", lineno))
    return packages


# ── severity mapping ───────────────────────────────────────────────────────────

def _osv_severity(vuln: dict) -> Severity:
    """Best-effort severity extraction from an OSV vulnerability record."""
    for sev in vuln.get("severity", []):
        score = sev.get("score")
        if isinstance(score, (int, float)):
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW

    db = vuln.get("database_specific", {})
    label = db.get("severity", "").upper()
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(label, Severity.MEDIUM)
