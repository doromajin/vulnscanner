"""Bug bounty report generator.

Formats probe + static-analysis findings into a professional report
suitable for submission to HackerOne, Bugcrowd, or direct disclosure.

Supported formats:
  markdown   — GitHub-flavoured Markdown (default)
  hackerone  — HackerOne report structure
  bugcrowd   — Bugcrowd VRT-aligned structure
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from typing import Literal

from vulnscanner.models import Finding, Severity

ReportFormat = Literal["markdown", "hackerone", "bugcrowd"]

_CVSS_BY_SEVERITY: dict[str, str] = {
    "CRITICAL": "9.0–10.0",
    "HIGH":     "7.0–8.9",
    "MEDIUM":   "4.0–6.9",
    "LOW":      "0.1–3.9",
    "INFO":     "0.0",
}

_PRIORITY_BY_SEVERITY: dict[str, str] = {
    "CRITICAL": "P1",
    "HIGH":     "P2",
    "MEDIUM":   "P3",
    "LOW":      "P4",
    "INFO":     "P5",
}

# Remediation advice per rule
_REMEDIATION: dict[str, str] = {
    "PROBE-001": "Implement authentication middleware on all non-public routes. Verify every endpoint checks session/token validity before returning data.",
    "PROBE-002": "Configure your framework to suppress stack traces and verbose errors in production. Use a generic error message with a reference ID.",
    "PROBE-003": "Remove sensitive fields (passwords, keys, tokens) from API responses. Apply field-level serialization filters.",
    "PROBE-004": "Explicitly restrict HTTP methods per endpoint. Return 405 Method Not Allowed for unsupported verbs.",
    "PROBE-005": "Add object-level authorization checks: verify the authenticated user owns the requested resource before returning it.",
    "PROBE-006": "Never trust client-supplied IP headers (X-Forwarded-For, X-Real-IP) for authorization decisions. Use network-level controls instead.",
    "PROBE-007": "Set Access-Control-Allow-Origin to a specific trusted origin. Never reflect the request Origin header directly.",
    "JSEP-002":  "Ensure admin and internal endpoints require authentication and are not accessible from the internet without VPN/allowlist.",
    "JSEP-003":  "Remove credentials from URLs immediately. Use environment variables or a secrets manager. Rotate the exposed credential.",
    "SEC-011":   "Revoke the token at api.slack.com/apps and rotate all secrets. Store tokens in environment variables, not source code.",
    "SEC-012":   "Revoke the key at dashboard.stripe.com/apikeys and rotate. Never commit payment processor keys to source control.",
    "SEC-013":   "Revoke at app.sendgrid.com/settings/api_keys. Audit all emails sent with the key for abuse.",
    "SEC-014":   "Revoke at npmjs.com/settings/tokens. Audit published packages for tampering.",
    "PHP-ENV-001": "Upgrade PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later. Apply vendor patches immediately.",
    "PROBE-008":  "Implement rate limiting on authentication and sensitive endpoints (e.g., express-rate-limit, rack-throttle, Django ratelimit). Return HTTP 429 after threshold.",
    "PROBE-009":  "Use an allowlist of permitted redirect destinations. Never redirect to a URL supplied directly by the user. If dynamic redirects are required, validate against a server-side allowlist.",
    "PROBE-010":  "Remove or update the DNS CNAME record pointing to the unclaimed cloud service. If the service is still needed, reclaim the resource immediately. Use DNS monitoring to alert on dangling CNAMEs.",
}

_DEFAULT_REMEDIATION = "Review the finding and apply the principle of least privilege. Consult OWASP guidelines for this vulnerability class."


@dataclass
class BugBountyReport:
    target: str
    findings: list[Finding]
    repo_url: str = ""
    researcher: str = ""
    program: str = ""
    report_date: str = ""

    def __post_init__(self):
        if not self.report_date:
            self.report_date = date.today().isoformat()

    def render(self, fmt: ReportFormat = "markdown") -> str:
        if fmt == "hackerone":
            return self._render_hackerone()
        if fmt == "bugcrowd":
            return self._render_bugcrowd()
        return self._render_markdown()

    # ── Markdown (default) ────────────────────────────────────────────────────

    def _render_markdown(self) -> str:
        sev_order = [s.value for s in Severity]
        sorted_findings = sorted(self.findings, key=lambda f: sev_order.index(f.severity.value))

        lines = [
            f"# Security Vulnerability Report",
            f"",
            f"**Target**: {self.target}",
            f"**Date**: {self.report_date}",
        ]
        if self.researcher:
            lines.append(f"**Researcher**: {self.researcher}")
        if self.program:
            lines.append(f"**Program**: {self.program}")

        lines += [
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            n = sum(1 for f in self.findings if f.severity.value == sev)
            if n:
                lines.append(f"| {sev} | {n} |")

        for i, f in enumerate(sorted_findings, 1):
            sev = f.severity.value
            lines += [
                f"",
                f"---",
                f"",
                f"## Finding #{i}: {f.vuln_type.value}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Rule ID** | `{f.rule_id}` |",
                f"| **Severity** | {sev} (CVSS {_CVSS_BY_SEVERITY.get(sev, '?')}) |",
                f"| **Location** | `{f.file_path}:{f.line_number}` |",
                f"",
                f"### Description",
                f"",
                f"{f.description}",
                f"",
                f"### Affected Code / Endpoint",
                f"",
                f"```",
                f"{f.line_content}",
                f"```",
                f"",
                f"### Steps to Reproduce",
                f"",
                f"1. Identify the affected endpoint/code: `{f.line_content[:80]}`",
                f"2. Send a request without authentication or with the crafted payload.",
                f"3. Observe the response — the vulnerability is confirmed if the server returns sensitive data or executes the injected command.",
                f"",
                f"### Impact",
                f"",
                _impact_text(f),
                f"",
                f"### Remediation",
                f"",
                _REMEDIATION.get(f.rule_id, _DEFAULT_REMEDIATION),
            ]
            if f.repo_url:
                lines += [f"", f"**Reference**: {f.repo_url}"]

        return "\n".join(lines) + "\n"

    # ── HackerOne ─────────────────────────────────────────────────────────────

    def _render_hackerone(self) -> str:
        sev_order = [s.value for s in Severity]
        sorted_findings = sorted(self.findings, key=lambda f: sev_order.index(f.severity.value))

        sections: list[str] = []
        for i, f in enumerate(sorted_findings, 1):
            sev = f.severity.value
            sections.append("\n".join([
                f"### #{i} — {f.vuln_type.value} ({sev})",
                f"",
                f"**Summary**: {f.description[:200]}",
                f"",
                f"**Severity**: {sev} | **CVSS**: {_CVSS_BY_SEVERITY.get(sev, '?')} | **Rule**: `{f.rule_id}`",
                f"",
                f"**Vulnerability Details**",
                f"",
                f"Location: `{f.file_path}:{f.line_number}`",
                f"",
                f"```",
                f"{f.line_content}",
                f"```",
                f"",
                f"**Steps To Reproduce**",
                f"",
                f"1. Navigate to `{f.line_content[:80]}`",
                f"2. {_steps_to_reproduce(f)}",
                f"3. Observe the vulnerable behavior.",
                f"",
                f"**Impact**",
                f"",
                _impact_text(f),
                f"",
                f"**Remediation**",
                f"",
                _REMEDIATION.get(f.rule_id, _DEFAULT_REMEDIATION),
            ]))

        header = "\n".join([
            f"## Vulnerability Report — {self.target}",
            f"",
            f"**Reported**: {self.report_date}",
            f"**Findings**: {len(self.findings)}",
            f"",
        ])
        return header + "\n\n".join(sections) + "\n"

    # ── Bugcrowd ──────────────────────────────────────────────────────────────

    def _render_bugcrowd(self) -> str:
        sev_order = [s.value for s in Severity]
        sorted_findings = sorted(self.findings, key=lambda f: sev_order.index(f.severity.value))

        lines = [
            f"# Bug Report — {self.target}",
            f"Date: {self.report_date}",
            f"",
        ]
        for i, f in enumerate(sorted_findings, 1):
            sev = f.severity.value
            priority = _PRIORITY_BY_SEVERITY.get(sev, "P5")
            lines += [
                f"## [{priority}] {f.vuln_type.value}",
                f"",
                f"**Title**: {f.vuln_type.value} in `{f.file_path}`",
                f"**Priority**: {priority} ({sev})",
                f"**CWE**: {f.cwe_id or 'N/A'}",
                f"",
                f"### Description",
                f"{f.description}",
                f"",
                f"### Proof of Concept",
                f"```",
                f"Location: {f.file_path}:{f.line_number}",
                f"Code:     {f.line_content}",
                f"```",
                f"",
                f"### Expected vs Actual Behavior",
                f"- **Expected**: Access control / safe handling enforced",
                f"- **Actual**: {f.description[:120]}",
                f"",
                f"### Suggested Fix",
                f"{_REMEDIATION.get(f.rule_id, _DEFAULT_REMEDIATION)}",
                f"",
            ]
        return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _impact_text(f: Finding) -> str:
    vt = f.vuln_type.value
    sev = f.severity.value
    impacts = {
        "Command Injection":           "An attacker can execute arbitrary OS commands on the server, leading to full system compromise.",
        "SQL Injection":               "An attacker can read, modify, or delete database contents, bypassing authentication.",
        "Cross-Site Scripting (XSS)":  "An attacker can steal session cookies, redirect users, or perform actions on their behalf.",
        "Exposed API Endpoint":        "Sensitive functionality is accessible without authorization, potentially exposing user data.",
        "Missing Authorization":       "Any user (or unauthenticated party) can access resources that should be restricted.",
        "CORS Misconfiguration":       "A malicious website can make credentialed requests on behalf of logged-in users.",
        "Hardcoded Secret":            "Exposed credentials allow an attacker to impersonate the service or access protected resources.",
        "Vulnerable Dependency":       "Known exploits exist for this version — attackers can leverage public PoCs.",
        "Path Traversal":              "An attacker can read arbitrary files on the server, including secrets and configuration.",
        "Server-Side Request Forgery (SSRF)": "An attacker can probe internal services and cloud metadata endpoints.",
        "Open Redirect":                       "An attacker can redirect authenticated users to phishing pages, enabling credential theft.",
    }
    base = impacts.get(vt, f"This {sev.lower()}-severity vulnerability may allow unauthorized access or data exposure.")
    return base


def _steps_to_reproduce(f: Finding) -> str:
    from vulnscanner.models import VulnType
    steps = {
        VulnType.MISSING_AUTHORIZATION: f"Send a GET request to `{f.line_content[:60]}` without an Authorization header.",
        VulnType.CORS_MISCONFIGURATION: f"Send a GET request to `{f.line_content[:60]}` with `Origin: https://evil.com` and observe the ACAO response header.",
        VulnType.HARDCODED_SECRET:      f"Locate the credential at `{f.file_path}:{f.line_number}` and attempt authentication with the exposed value.",
    }
    return steps.get(f.vuln_type, f"Trigger the vulnerable code path at `{f.file_path}:{f.line_number}`.")


def from_json_report(path: str) -> list[Finding]:
    """Load findings from a vulnscan JSON report for report generation."""
    from vulnscanner.models import VulnType, Severity
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = []
    for raw in data.get("findings", []):
        try:
            findings.append(Finding(
                vuln_type=VulnType(raw["vuln_type"]),
                severity=Severity(raw["severity"] if isinstance(raw["severity"], str)
                                  else raw["severity"].get("value", "MEDIUM")),
                file_path=raw.get("file_path", ""),
                line_number=raw.get("line_number", 0),
                line_content=raw.get("line_content", ""),
                description=raw.get("description", ""),
                rule_id=raw.get("rule_id", ""),
                repo_url=raw.get("repo_url"),
                cwe_id=raw.get("cwe_id"),
            ))
        except Exception:
            continue
    return findings
