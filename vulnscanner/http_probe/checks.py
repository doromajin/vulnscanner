"""Individual HTTP security checks run against probe responses.

Each check receives a URL, HTTP response, and optional source finding,
and returns a Finding if a vulnerability is detected, or None otherwise.

Rule IDs:
  PROBE-001  Unauthenticated access to sensitive endpoint (HIGH/MEDIUM)
  PROBE-002  Error message / stack trace disclosure (MEDIUM)
  PROBE-003  Sensitive data pattern in response body (HIGH)
  PROBE-004  HTTP method confusion — GET succeeds on write-only endpoint (MEDIUM)
"""
from __future__ import annotations

import re

from vulnscanner.models import Finding, Severity, VulnType

# Error patterns that indicate verbose error disclosure
_ERROR_PATTERNS = re.compile(
    r'(?:Traceback \(most recent call last\)|'
    r'at [\w.$<>]+\([\w.]+\.java:\d+\)|'  # Java stack frame
    r'System\.(?:Web|Data)\.|'             # ASP.NET
    r'ORA-\d{5}|'                          # Oracle DB error
    r'You have an error in your SQL syntax|'
    r'SQLSTATE\[|'
    r'PDOException|'
    r'ActiveRecord::StatementInvalid|'
    r'Doctrine\\DBAL\\Exception|'
    r'Warning: (?:mysql|mysqli|pg)_|'     # PHP DB warnings
    r'Fatal error:|Parse error:)',         # PHP fatal
    re.IGNORECASE,
)

# Sensitive data patterns in response bodies
_SENSITIVE_DATA_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("private_key", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "Private key material in response"),
    ("aws_key",     re.compile(r'\bAKIA[0-9A-Z]{16}\b'),                              "AWS access key ID in response"),
    ("jwt_token",   re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'), "JWT token in response"),
    ("password",    re.compile(r'"password"\s*:\s*"[^"]{4,}"', re.IGNORECASE),        "Password field in JSON response"),
    ("secret",      re.compile(r'"(?:secret|api_key|token)"\s*:\s*"[A-Za-z0-9._\-]{16,}"', re.IGNORECASE), "Secret/API key in JSON response"),
]

# Sensitive endpoint keywords (used by PROBE-001 severity escalation)
_SENSITIVE_PATH_RE = re.compile(
    r'/(?:admin|administrator|internal|debug|config|secret|private|management|'
    r'console|panel|dashboard|superuser|system|setup|actuator|env|graphql|swagger)',
    re.IGNORECASE,
)


def check_unauth_access(
    url: str,
    status_code: int,
    response_body: str,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-001: endpoint accessible without authentication."""
    if status_code not in (200, 201, 202, 204):
        return None

    is_sensitive = bool(_SENSITIVE_PATH_RE.search(url))
    severity = Severity.HIGH if is_sensitive else Severity.MEDIUM

    return Finding(
        vuln_type=VulnType.MISSING_AUTHORIZATION,
        severity=severity,
        file_path=source_finding.file_path if source_finding else url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=url,
        description=(
            f"Endpoint {url!r} returned HTTP {status_code} without authentication — "
            f"{'sensitive path may be publicly accessible' if is_sensitive else 'verify access controls'}"
        ),
        rule_id="PROBE-001",
        repo_url=source_finding.repo_url if source_finding else None,
    )


def check_error_disclosure(
    url: str,
    status_code: int,
    response_body: str,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-002: verbose error or stack trace in response."""
    m = _ERROR_PATTERNS.search(response_body)
    if not m:
        return None

    snippet = m.group()[:120]
    return Finding(
        vuln_type=VulnType.HARDCODED_SECRET,   # closest type; ideally INFORMATION_DISCLOSURE
        severity=Severity.MEDIUM,
        file_path=source_finding.file_path if source_finding else url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=url,
        description=(
            f"Error/stack trace disclosed at {url!r} (HTTP {status_code}): "
            f"{snippet!r} — configure production error handlers"
        ),
        rule_id="PROBE-002",
        repo_url=source_finding.repo_url if source_finding else None,
    )


def check_sensitive_data(
    url: str,
    status_code: int,
    response_body: str,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-003: sensitive data (keys, passwords, JWTs) in response body."""
    for _name, pattern, description in _SENSITIVE_DATA_PATTERNS:
        if pattern.search(response_body):
            return Finding(
                vuln_type=VulnType.HARDCODED_SECRET,
                severity=Severity.HIGH,
                file_path=source_finding.file_path if source_finding else url,
                line_number=source_finding.line_number if source_finding else 0,
                line_content=url,
                description=f"{description} returned by {url!r} (HTTP {status_code})",
                rule_id="PROBE-003",
                repo_url=source_finding.repo_url if source_finding else None,
            )
    return None


def check_method_confusion(
    url: str,
    get_status: int,
    post_status: int,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-004: GET succeeds on an endpoint that should be write-only (POST route)."""
    if get_status not in (200, 201, 202):
        return None
    if post_status not in (200, 201, 202, 204, 400, 422):
        return None

    return Finding(
        vuln_type=VulnType.MISSING_AUTHORIZATION,
        severity=Severity.MEDIUM,
        file_path=source_finding.file_path if source_finding else url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=url,
        description=(
            f"HTTP method confusion: GET returned {get_status} on {url!r}, "
            f"which was defined as a write endpoint — verify verb-level access controls"
        ),
        rule_id="PROBE-004",
        repo_url=source_finding.repo_url if source_finding else None,
    )


def check_idor(
    base_url: str,
    original_body: str,
    variant_body: str,
    variant_url: str,
    original_status: int,
    variant_status: int,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-005: Insecure Direct Object Reference — different ID returns different data."""
    if original_status != 200 or variant_status != 200:
        return None
    if not original_body or not variant_body:
        return None

    # Bodies must be non-trivially different (different length or different key fields)
    if not _bodies_differ(original_body, variant_body):
        return None

    return Finding(
        vuln_type=VulnType.MISSING_AUTHORIZATION,
        severity=Severity.HIGH,
        file_path=source_finding.file_path if source_finding else base_url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=base_url,
        description=(
            f"Potential IDOR: {base_url!r} and {variant_url!r} both return HTTP 200 "
            f"with different response bodies — verify that object ownership is enforced"
        ),
        rule_id="PROBE-005",
        repo_url=source_finding.repo_url if source_finding else None,
    )


def check_auth_bypass(
    url: str,
    original_status: int,
    bypass_status: int,
    bypass_header: str,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-006: Authentication bypass via IP-spoofing / URL-override headers."""
    if original_status not in (401, 403):
        return None
    if bypass_status not in (200, 201, 202, 204):
        return None

    return Finding(
        vuln_type=VulnType.MISSING_AUTHORIZATION,
        severity=Severity.CRITICAL,
        file_path=source_finding.file_path if source_finding else url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=url,
        description=(
            f"Authentication bypass via header injection: "
            f"{url!r} returned {original_status} normally but {bypass_status} "
            f"with {bypass_header!r} — server trusts client-supplied proxy headers"
        ),
        rule_id="PROBE-006",
        repo_url=source_finding.repo_url if source_finding else None,
    )


def check_cors(
    url: str,
    acao_header: str,
    acac_header: str,
    origin_sent: str,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-007: CORS misconfiguration — reflected origin or wildcard with credentials."""
    if not acao_header:
        return None

    # Wildcard + credentials = critical (credentials never sent with wildcard, but still misconfigured)
    if acao_header.strip() == "*":
        if acac_header.strip().lower() == "true":
            severity = Severity.HIGH
            detail = "wildcard ACAO with Access-Control-Allow-Credentials: true (browsers block this, but misconfigured)"
        else:
            return None  # wildcard alone is intentional for public APIs

    # Origin reflected back = attacker can make credentialed cross-origin requests
    elif acao_header.strip() == origin_sent:
        severity = Severity.HIGH
        detail = f"origin {origin_sent!r} is reflected verbatim in Access-Control-Allow-Origin"
    else:
        return None

    return Finding(
        vuln_type=VulnType.CORS_MISCONFIGURATION,
        severity=severity,
        file_path=source_finding.file_path if source_finding else url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=url,
        description=(
            f"CORS misconfiguration at {url!r}: {detail} — "
            f"attackers on any origin can make credentialed requests if cookies are used"
        ),
        rule_id="PROBE-007",
        repo_url=source_finding.repo_url if source_finding else None,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def check_rate_limit(
    url: str,
    responses: list[tuple[int, dict]],
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-008: No rate limiting — N consecutive requests all succeed."""
    if not responses:
        return None

    # Pass if any response is 429, or has rate-limit headers
    _rl_headers = {"x-ratelimit-limit", "x-ratelimit-remaining", "retry-after",
                   "x-rate-limit-limit", "ratelimit-limit", "cf-ratelimit"}
    for status, headers in responses:
        if status == 429:
            return None
        lower = {k.lower() for k in headers}
        if lower & _rl_headers:
            return None

    # Only flag if all N requests succeeded
    success = sum(1 for s, _ in responses if s in (200, 201, 202, 204))
    if success < len(responses):
        return None

    is_auth = bool(_AUTH_PATH_RE.search(url))
    severity = Severity.HIGH if is_auth else Severity.MEDIUM

    return Finding(
        vuln_type=VulnType.MISSING_AUTHORIZATION,
        severity=severity,
        file_path=source_finding.file_path if source_finding else url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=url,
        description=(
            f"No rate limiting on {url!r} — {len(responses)} consecutive requests all returned "
            f"HTTP {responses[0][0]}; "
            f"{'authentication endpoint is brute-forceable' if is_auth else 'consider adding rate limiting'}"
        ),
        rule_id="PROBE-008",
        repo_url=source_finding.repo_url if source_finding else None,
    )


def check_open_redirect(
    url: str,
    param_name: str,
    injected_url: str,
    response_status: int,
    location_header: str,
    source_finding: Finding | None,
) -> Finding | None:
    """PROBE-009: Open redirect — server reflects attacker-controlled URL in Location."""
    if response_status not in (301, 302, 303, 307, 308):
        return None
    if not location_header:
        return None
    # Only flag if our injected URL appears verbatim in Location
    if injected_url not in location_header:
        return None

    return Finding(
        vuln_type=VulnType.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        file_path=source_finding.file_path if source_finding else url,
        line_number=source_finding.line_number if source_finding else 0,
        line_content=url,
        description=(
            f"Open redirect at {url!r}: parameter {param_name!r} caused "
            f"HTTP {response_status} redirect to {location_header!r} — "
            f"attackers can redirect users to phishing pages"
        ),
        rule_id="PROBE-009",
        repo_url=source_finding.repo_url if source_finding else None,
    )


_AUTH_PATH_RE = re.compile(
    r'/(?:login|signin|sign-in|auth|token|oauth|password|forgot|reset|'
    r'register|signup|sign-up|otp|verify|2fa|mfa|totp)',
    re.IGNORECASE,
)


def _bodies_differ(a: str, b: str) -> bool:
    """Return True if two response bodies are meaningfully different."""
    # Trivially empty or identical
    if a == b:
        return False
    # Size difference > 10% of the larger body
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return True
    ratio = abs(la - lb) / max(la, lb)
    if ratio > 0.10:
        return True
    # Different top-level JSON keys suggest different objects
    try:
        import json
        ja = set(json.loads(a).keys()) if a.strip().startswith("{") else set()
        jb = set(json.loads(b).keys()) if b.strip().startswith("{") else set()
        if ja and jb and ja != jb:
            return True
        # Same keys but different id/email/username values
        da = json.loads(a) if a.strip().startswith("{") else {}
        db = json.loads(b) if b.strip().startswith("{") else {}
        for key in ("id", "user_id", "email", "username", "name"):
            if da.get(key) and db.get(key) and da[key] != db[key]:
                return True
    except Exception:
        pass
    return False
