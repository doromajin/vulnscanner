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

PHP runtime version check:
  .php-version                                                       (phpenv/phpbrew)
  composer.lock  (platform section)                                  (Composer)
"""
from __future__ import annotations

import json
import os
import re

from vulnscanner.analyzers.ast_python import get_cross_file_contents
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
    ".php-version",
    "composer.lock",
})

# CVE-2026-109618 / CVE-2026-109619 (php2shell): first patched version per branch.
# PHP 8.1 and below are EOL — no patch released.
_PHP_PATCHED: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
_PHP_CVE_IDS = "CVE-2026-109618, CVE-2026-109619"


def _php_vuln_reason(version_str: str) -> str | None:
    """Return a human-readable reason if *version_str* is vulnerable, else None."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str.strip())
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    branch = (major, minor)
    ver = (major, minor, patch)

    if major < 8 or (major == 8 and minor < 2):
        return (
            f"PHP {version_str} is EOL; no official patch for {_PHP_CVE_IDS} (php2shell RCE, CVSS 9.2). "
            "Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later."
        )
    if branch in _PHP_PATCHED:
        patched = _PHP_PATCHED[branch]
        if ver < patched:
            fixed = ".".join(str(x) for x in patched)
            return (
                f"PHP {version_str} is vulnerable to {_PHP_CVE_IDS} (php2shell unauthenticated RCE, CVSS 9.2). "
                f"Upgrade to PHP {fixed} or later."
            )
    return None

_OSV_API = "https://api.osv.dev/v1/querybatch"
_OSV_TIMEOUT = 15  # seconds
_OSV_VULN_API = "https://api.osv.dev/v1/vulns/"
_OSV_DETAIL_LIMIT = 20  # advisories fetched per package
_osv_detail_cache: dict[str, dict] = {}


def _osv_vuln_detail(req_lib, stub: dict) -> dict:
    """Return the full OSV record for a querybatch stub; the stub itself if unavailable."""
    vid = stub.get("id", "")
    if not vid or "database_specific" in stub or "severity" in stub:
        return stub
    if vid not in _osv_detail_cache:
        try:
            resp = req_lib.get(_OSV_VULN_API + vid, timeout=_OSV_TIMEOUT)
            resp.raise_for_status()
            _osv_detail_cache[vid] = resp.json()
        except Exception:
            return stub  # not cached: a later package may retry
    return _osv_detail_cache[vid]


_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# (name, version, ecosystem, lineno)
_Package = tuple[str, str, str, int]


class DependencyAnalyzer(BaseAnalyzer):
    """Check dependency files for packages with known CVEs via OSV.dev."""

    def supports(self, file_path: str) -> bool:
        name = os.path.basename(file_path.replace("\\", "/"))
        return name in _DEPENDENCY_FILENAMES

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        filename = os.path.basename(file_path.replace("\\", "/"))

        if filename in (".php-version", "composer.lock"):
            return self._check_php_runtime(filename, content, file_path, repo_url)

        packages = self._parse(filename, content)
        if not packages:
            return []
        floor_names: frozenset[str] = frozenset()
        if filename == "package.json":
            packages, floor_names = _resolve_npm_ranges(file_path, content, packages)
        return self._check_osv(packages, file_path, repo_url, floor_names)

    def _check_php_runtime(
        self,
        filename: str,
        content: str,
        file_path: str,
        repo_url: str,
    ) -> list[Finding]:
        """Detect a PHP runtime version and warn if vulnerable to php2shell."""
        entries: list[tuple[str, int]] = []  # (version_string, lineno)

        if filename == ".php-version":
            ver = content.strip().splitlines()[0].strip() if content.strip() else ""
            if ver:
                entries.append((ver, 1))

        elif filename == "composer.lock":
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return []
            for section in ("platform-overrides", "platform"):
                php_ver = data.get(section, {}).get("php", "")
                if php_ver:
                    entries.append((php_ver, 1))
                    break

        findings: list[Finding] = []
        for ver_str, lineno in entries:
            reason = _php_vuln_reason(ver_str)
            if reason:
                findings.append(Finding(
                    vuln_type=VulnType.VULNERABLE_DEPENDENCY,
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=lineno,
                    line_content=ver_str,
                    description=reason,
                    rule_id="PHP-ENV-001",
                    repo_url=repo_url,
                ))
        return findings

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
        floor_names: frozenset[str] = frozenset(),
    ) -> list[Finding]:
        """*floor_names*: packages queried at a range's lowest version (installed version unknown)."""
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
            # querybatch returns only {id, modified}: fetch records for severity and aliases
            vulns = [_osv_vuln_detail(req_lib, v) for v in vulns[:_OSV_DETAIL_LIMIT]] + vulns[_OSV_DETAIL_LIMIT:]

            cve_ids = [
                a
                for v in vulns
                for a in v.get("aliases", [])
                if a.startswith("CVE-")
            ]
            # OSV returns advisories in arbitrary order: report the highest severity
            sev = min((_osv_severity(v) for v in vulns), key=_SEVERITY_ORDER.index)

            count = len(vulns)
            desc = f"{name} {ver} has {count} known " + ("vulnerabilities" if count > 1 else "vulnerability")
            if cve_ids:
                desc += f" ({', '.join(cve_ids[:3])})"
            if name in floor_names:
                # the range resolves to the newest matching release at install time, which is
                # usually past the floor: without a lock file this is only a possible exposure
                if _SEVERITY_ORDER.index(sev) < _SEVERITY_ORDER.index(Severity.LOW):
                    sev = Severity.LOW
                desc += (
                    "; queried at the lowest version of the declared range because no lock file "
                    "was found, so the installed version may be newer and unaffected (severity capped at LOW)"
                )
            elif count > 1:
                desc += (
                    f"; severity is the highest of {count} advisories. "
                    "Exploitability depends on how the library is used (some advisories need non-default options)"
                )

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


_EXACT_VER_RE = re.compile(r"=?v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?")
_RANGE_SPEC_RE = re.compile(r"[\s0-9A-Za-z.*^~<>=|-]+")
_NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


def _npm_range_specs(content: str) -> dict[str, str]:
    """Return {name: declared spec} for package.json deps given as a version range, not an exact pin."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {}
    specs: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        for name, spec in data.get(section, {}).items():
            spec = str(spec).strip()
            if (
                not _EXACT_VER_RE.fullmatch(spec)
                and _RANGE_SPEC_RE.fullmatch(spec)
                and re.search(r"\d", spec)
            ):
                specs[name] = spec
    return specs


def _lock_version_npm(text: str, name: str, spec: str) -> str | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    entry = (data.get("packages") or {}).get(f"node_modules/{name}")  # lockfileVersion 2/3
    if not isinstance(entry, dict):
        entry = (data.get("dependencies") or {}).get(name)  # lockfileVersion 1
    ver = entry.get("version") if isinstance(entry, dict) else None
    return ver if isinstance(ver, str) and re.match(r"\d", ver) else None


def _lock_version_yarn(text: str, name: str, spec: str) -> str | None:
    wanted = {f"{name}@{spec}", f"{name}@npm:{spec}"}  # classic / berry header forms
    matched = False
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and line.rstrip().endswith(":"):
            entries = {e.strip().strip('"') for e in line.rstrip()[:-1].split(",")}
            matched = bool(wanted & entries)
        elif matched:
            m = re.match(r'\s+version:?\s+"?(\d[^"\s]*)"?', line)
            if m:
                return m.group(1)
    return None


def _lock_version_pnpm(text: str, name: str, spec: str) -> str | None:
    esc = re.escape(name)
    m = re.search(
        r"^\s+['\"]?" + esc + r"['\"]?:\s*\n\s+specifier:[^\n]*\n\s+version:\s*['\"]?(\d[^\s'\"(]*)",
        text, re.M,
    )
    if m:
        return m.group(1)
    # older lockfile layouts: usable only when this package is locked at a single version
    versions = set(re.findall(r"^  /?['\"]?" + esc + r"[@/](\d[^:'\"()\s]*)", text, re.M))
    return next(iter(versions)) if len(versions) == 1 else None


_LOCK_RESOLVERS = {
    "package-lock.json": _lock_version_npm,
    "npm-shrinkwrap.json": _lock_version_npm,
    "yarn.lock": _lock_version_yarn,
    "pnpm-lock.yaml": _lock_version_pnpm,
}


def _resolve_npm_ranges(
    file_path: str, content: str, packages: list[_Package],
) -> tuple[list[_Package], frozenset[str]]:
    """Replace range-spec deps by the version a sibling lock file resolved them to.

    Deps with no resolvable lock entry keep their range floor and are returned in the
    second element so the caller can mark the finding as lower confidence.
    """
    specs = _npm_range_specs(content)
    if not specs:
        return packages, frozenset()
    all_contents = get_cross_file_contents()
    base = os.path.dirname(file_path.replace("\\", "/"))

    def _lock_text(lock: str) -> str | None:
        key = f"{base}/{lock}" if base else lock
        text = all_contents.get(key)
        return text if text is not None else all_contents.get(key.replace("/", "\\"))

    resolved: list[_Package] = []
    floor: set[str] = set()
    for name, ver, eco, lineno in packages:
        spec = specs.get(name)
        locked = None
        if spec is not None:
            for lock in _NPM_LOCKFILES:
                text = _lock_text(lock)
                if text is not None:
                    locked = _LOCK_RESOLVERS[lock](text, name, spec)
                    if locked:
                        break
        if locked:
            resolved.append((name, locked, eco, lineno))
        else:
            resolved.append((name, ver, eco, lineno))
            if spec is not None:
                floor.add(name)
    return resolved, frozenset(floor)


def _parse_gemfile_lock(content: str) -> list[_Package]:
    packages: list[_Package] = []
    seen: set[tuple[str, str]] = set()
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
                # RubyGems versions never contain "-": anything after it is the platform
                # (1.19.4-x86_64-linux-gnu, 1.0.0-java) and the same version is listed once per platform.
                version = m.group(2).split("-", 1)[0]
                if (m.group(1), version) in seen:
                    continue
                seen.add((m.group(1), version))
                packages.append((m.group(1), version, "RubyGems", lineno))
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
