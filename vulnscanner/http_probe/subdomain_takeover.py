"""PROBE-010: Subdomain takeover detection.

Approach:
  1. Static — extract cloud-service subdomains from HTML/JS source findings
  2. Dynamic — HTTP GET the candidate subdomain; check for unclaimed-service fingerprints
     (e.g. GitHub Pages 404, Heroku "no such app", Fastly 404 error page, etc.)

Only tests domains within the declared Scope or explicitly found in static analysis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from vulnscanner.models import Finding, Severity, VulnType

# Cloud service patterns and their "unclaimed" response fingerprints
# Format: (domain_suffix_regex, [fingerprint_strings_in_body], service_name)
_CLOUD_SERVICES: list[tuple[re.Pattern, list[str], str]] = [
    (
        re.compile(r'[\w-]+\.github\.io', re.IGNORECASE),
        ["There isn't a GitHub Pages site here.", "404 There is no GitHub Pages site here"],
        "GitHub Pages",
    ),
    (
        re.compile(r'[\w-]+\.s3(?:-website[.-][\w-]+)?\.amazonaws\.com', re.IGNORECASE),
        ["NoSuchBucket", "The specified bucket does not exist"],
        "AWS S3",
    ),
    (
        re.compile(r'[\w-]+\.herokuapp\.com', re.IGNORECASE),
        ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "Heroku",
    ),
    (
        re.compile(r'[\w-]+\.netlify\.app', re.IGNORECASE),
        ["Not Found - Request ID"],
        "Netlify",
    ),
    (
        re.compile(r'[\w-]+\.azurewebsites\.net', re.IGNORECASE),
        ["404 Web Site not found", "does not exist"],
        "Azure Web Apps",
    ),
    (
        re.compile(r'[\w-]+\.surge\.sh', re.IGNORECASE),
        ["project not found"],
        "Surge.sh",
    ),
    (
        re.compile(r'[\w-]+\.pantheonsite\.io', re.IGNORECASE),
        ["The gods are wise", "404 error unknown site"],
        "Pantheon",
    ),
    (
        re.compile(r'[\w-]+\.readme\.io', re.IGNORECASE),
        ["Project doesnt exist", "We couldn't find what you're looking for"],
        "ReadMe",
    ),
    (
        re.compile(r'[\w-]+\.ghost\.io', re.IGNORECASE),
        ["The thing you were looking for is no longer here"],
        "Ghost",
    ),
    (
        re.compile(r'[\w-]+\.myshopify\.com', re.IGNORECASE),
        ["Sorry, this shop is currently unavailable"],
        "Shopify",
    ),
    (
        re.compile(r'[\w-]+\.webflow\.io', re.IGNORECASE),
        ["The page you are looking for doesn't exist"],
        "Webflow",
    ),
    (
        re.compile(r'[\w-]+\.fastly\.net', re.IGNORECASE),
        ["Fastly error: unknown domain"],
        "Fastly",
    ),
    (
        re.compile(r'[\w-]+\.zendesk\.com', re.IGNORECASE),
        ["Help Center Closed"],
        "Zendesk",
    ),
    (
        re.compile(r'cname\.vercel-dns\.com|[\w-]+\.vercel\.app', re.IGNORECASE),
        ["The deployment could not be found"],
        "Vercel",
    ),
]


@dataclass
class SubdomainCandidate:
    """A cloud subdomain found in source code, pending live verification."""
    subdomain: str
    service: str
    source_file: str
    source_line: int


def extract_cloud_subdomains(file_path: str, content: str) -> list[SubdomainCandidate]:
    """Extract candidate cloud subdomains from HTML/JS/config source content."""
    candidates: list[SubdomainCandidate] = []
    seen: set[str] = set()

    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pattern, _fingerprints, service in _CLOUD_SERVICES:
            for m in pattern.finditer(line):
                subdomain = m.group(0).lower()
                if subdomain not in seen:
                    seen.add(subdomain)
                    candidates.append(SubdomainCandidate(
                        subdomain=subdomain,
                        service=service,
                        source_file=file_path,
                        source_line=lineno,
                    ))
    return candidates


def check_subdomain_takeover(
    candidate: SubdomainCandidate,
    response_status: int,
    response_body: str,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-010: check if a cloud subdomain shows an unclaimed-service fingerprint."""
    # Find the matching service fingerprints
    fingerprints: list[str] = []
    for _pattern, fps, service in _CLOUD_SERVICES:
        if service == candidate.service:
            fingerprints = fps
            break

    if not fingerprints:
        return None

    matched_fp = next(
        (fp for fp in fingerprints if fp.lower() in response_body.lower()),
        None,
    )
    if not matched_fp:
        return None

    url = f"https://{candidate.subdomain}"
    return Finding(
        vuln_type=VulnType.MISSING_AUTHORIZATION,
        severity=Severity.HIGH,
        file_path=candidate.source_file,
        line_number=candidate.source_line,
        line_content=candidate.subdomain,
        description=(
            f"Subdomain takeover candidate: {candidate.subdomain!r} points to {candidate.service} "
            f"but the service is unclaimed (fingerprint: {matched_fp!r}) — "
            f"an attacker can register this {candidate.service} resource and serve content "
            f"from your subdomain"
        ),
        rule_id="PROBE-010",
        repo_url=source_finding.repo_url if source_finding else None,
    )
