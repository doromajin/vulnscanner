"""HTTP probing engine.

Takes discovered endpoints (from JSEndpointAnalyzer static findings),
sends authorized HTTP requests within the declared scope, and applies
security checks to each response.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from vulnscanner.http_probe.scope import Scope, ScopeViolation
from vulnscanner.http_probe.subdomain_takeover import (
    extract_cloud_subdomains,
    check_subdomain_takeover,
    SubdomainCandidate,
)
from vulnscanner.http_probe.checks import (
    check_unauth_access,
    check_error_disclosure,
    check_sensitive_data,
    check_method_confusion,
    check_idor,
    check_auth_bypass,
    check_cors,
    check_rate_limit,
    check_open_redirect,
    _AUTH_PATH_RE,
)

_RATE_LIMIT_BURST = 12  # requests to send for rate-limit check

# Headers that proxy/load-balancer trust issues allow to bypass auth
_BYPASS_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("Forwarded", "for=127.0.0.1"),
]

# Fake origin used for CORS reflection test
_CORS_TEST_ORIGIN = "https://corsscan.vulnscanner.invalid"

# Test URL injected into redirect parameters to detect open redirect
_REDIRECT_TEST_URL = "https://open-redirect.vulnscanner.invalid"

# Common redirect parameter names (ordered by frequency in the wild)
_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_url", "return", "return_url",
    "goto", "target", "dest", "destination", "redir", "redirect_uri",
    "callback", "continue", "forward", "ref", "returnTo", "return_to",
]

import re as _re
_NUMERIC_ID_RE = _re.compile(r'(/\d{1,10})(?:/|$|\?)')
_UUID_RE = _re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)', _re.IGNORECASE)
from vulnscanner.models import Finding

_USER_AGENT = "VulnScanner-Probe/1.0 (authorized security testing)"


@dataclass
class ProbeResult:
    """Result of probing a single endpoint."""
    url: str
    method: str
    status_code: int
    response_size: int
    response_time_ms: float
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    skipped: bool = False
    skip_reason: str = ""


class HttpProber:
    """Authorized HTTP prober.

    All requests are validated against the declared Scope before sending.
    Out-of-scope URLs raise ScopeViolation and are never probed.
    """

    def __init__(
        self,
        scope: Scope,
        timeout: int = 10,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self._extra_headers = headers or {}

    def probe_all(
        self,
        base_url: str,
        endpoint_findings: list[Finding],
    ) -> list[ProbeResult]:
        """Probe all endpoints derived from static findings.

        Args:
            base_url:          Base URL to prepend to relative paths.
            endpoint_findings: List of JSEP-001/002 findings from JSEndpointAnalyzer.

        Returns:
            List of ProbeResult, one per unique URL probed.
        """
        try:
            import requests as _req
        except ImportError:
            return [ProbeResult(
                url=base_url,
                method="—",
                status_code=0,
                response_size=0,
                response_time_ms=0,
                error="requests library not installed — run: pip install requests",
                skipped=True,
                skip_reason="missing_dependency",
            )]

        session = _req.Session()
        session.headers.update({
            "User-Agent": _USER_AGENT,
            **self._extra_headers,
        })

        results: list[ProbeResult] = []
        seen_urls: set[str] = set()

        for finding in endpoint_findings:
            # Extract path from finding description: 'API endpoint reference: '/api/v1/users''
            path = _extract_path(finding.description)
            if not path:
                continue

            try:
                url = self.scope.build_url(base_url, path)
            except ScopeViolation as e:
                results.append(ProbeResult(
                    url=path,
                    method="—",
                    status_code=0,
                    response_size=0,
                    response_time_ms=0,
                    skipped=True,
                    skip_reason=str(e),
                ))
                continue

            if url in seen_urls:
                continue
            seen_urls.add(url)

            result = self._probe_url(session, url, finding)
            results.append(result)

        return results

    def _probe_url(
        self,
        session,
        url: str,
        source_finding: Finding,
    ) -> ProbeResult:
        """Send GET (and optionally POST) to *url* and run all checks."""
        import requests as _req

        # ── GET request ──────────────────────────────────────────────────────
        try:
            t0 = time.monotonic()
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            elapsed_ms = (time.monotonic() - t0) * 1000
        except _req.exceptions.Timeout:
            return ProbeResult(
                url=url, method="GET", status_code=0,
                response_size=0, response_time_ms=self.timeout * 1000,
                error="Request timed out",
            )
        except Exception as exc:
            return ProbeResult(
                url=url, method="GET", status_code=0,
                response_size=0, response_time_ms=0,
                error=str(exc),
            )

        body = resp.text[:65_536]  # cap at 64 KB
        findings: list[Finding] = []

        # ── Basic checks ─────────────────────────────────────────────────────
        for check_fn in (check_unauth_access, check_error_disclosure, check_sensitive_data):
            r = check_fn(url, resp.status_code, body, source_finding)
            if r:
                findings.append(r)

        # ── PROBE-004: HTTP method confusion ──────────────────────────────────
        if source_finding.rule_id == "JSEP-002":
            post_status = _quick_post_status(session, url, self.timeout)
            mc = check_method_confusion(url, resp.status_code, post_status, source_finding)
            if mc:
                findings.append(mc)

        # ── PROBE-005: IDOR ───────────────────────────────────────────────────
        idor_findings = self._check_idor(session, url, body, resp.status_code, source_finding)
        findings.extend(idor_findings)

        # ── PROBE-006: Auth bypass headers ────────────────────────────────────
        if resp.status_code in (401, 403):
            bypass = self._check_auth_bypass(session, url, resp.status_code, source_finding)
            findings.extend(bypass)

        # ── PROBE-007: CORS misconfiguration ──────────────────────────────────
        cors_finding = self._check_cors(session, url, source_finding)
        if cors_finding:
            findings.append(cors_finding)

        # ── PROBE-008: Rate limiting (auth endpoints + JSEP-002 sensitive) ───
        if _AUTH_PATH_RE.search(url) or source_finding.rule_id == "JSEP-002":
            rl = self._check_rate_limit(session, url, source_finding)
            if rl:
                findings.append(rl)

        # ── PROBE-009: Open redirect ───────────────────────────────────────────
        or_finding = self._check_open_redirect(session, url, source_finding)
        if or_finding:
            findings.append(or_finding)

        # ── PROBE-010: Subdomain takeover (from page body) ────────────────────
        st_findings = self._check_subdomain_takeover(session, body, source_finding)
        findings.extend(st_findings)

        return ProbeResult(
            url=url,
            method="GET",
            status_code=resp.status_code,
            response_size=len(resp.content),
            response_time_ms=elapsed_ms,
            findings=findings,
        )

    def _check_idor(
        self,
        session,
        url: str,
        original_body: str,
        original_status: int,
        source_finding,
    ) -> list:
        """PROBE-005: try adjacent numeric IDs and compare responses."""
        import requests as _req
        findings = []

        # Find a numeric segment in the URL path
        m = _NUMERIC_ID_RE.search(url)
        if not m:
            return findings

        original_id = int(m.group(1).lstrip("/"))
        variants = {original_id + 1, original_id - 1}
        variants.discard(0)

        for v_id in variants:
            variant_url = url[: m.start(1)] + "/" + str(v_id) + url[m.end(1):]
            try:
                r = session.get(variant_url, timeout=self.timeout, allow_redirects=True)
            except Exception:
                continue
            f = check_idor(
                url, original_body, r.text[:65_536],
                variant_url, original_status, r.status_code,
                source_finding,
            )
            if f:
                findings.append(f)
                break  # one finding per endpoint is enough

        return findings

    def _check_auth_bypass(
        self,
        session,
        url: str,
        original_status: int,
        source_finding,
    ) -> list:
        """PROBE-006: retry with IP-spoofing / URL-override headers."""
        import requests as _req
        findings = []

        for header_name, header_value in _BYPASS_HEADERS:
            try:
                r = session.get(
                    url,
                    headers={header_name: header_value},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
            except Exception:
                continue
            f = check_auth_bypass(
                url, original_status, r.status_code,
                f"{header_name}: {header_value}", source_finding,
            )
            if f:
                findings.append(f)
                break  # one bypass finding per endpoint

        return findings

    def _check_rate_limit(self, session, url: str, source_finding) -> object | None:
        """PROBE-008: send a burst of requests and check for rate limiting."""
        import requests as _req
        responses: list[tuple[int, dict]] = []
        for _ in range(_RATE_LIMIT_BURST):
            try:
                r = session.get(url, timeout=self.timeout, allow_redirects=True)
                responses.append((r.status_code, dict(r.headers)))
            except Exception:
                break
        return check_rate_limit(url, responses, source_finding)

    def _check_subdomain_takeover(
        self, session, page_body: str, source_finding
    ) -> list:
        """PROBE-010: extract cloud subdomains from page body and probe each."""
        import requests as _req
        findings = []
        seen: set[str] = set()

        candidates = extract_cloud_subdomains(
            source_finding.file_path if source_finding else "probe",
            page_body,
        )
        for candidate in candidates:
            if candidate.subdomain in seen:
                continue
            seen.add(candidate.subdomain)

            probe_url = f"https://{candidate.subdomain}"
            try:
                r = session.get(probe_url, timeout=self.timeout, allow_redirects=True)
                body = r.text[:32_768]
            except Exception:
                continue

            f = check_subdomain_takeover(candidate, r.status_code, body, source_finding)
            if f:
                findings.append(f)

        return findings

    def _check_open_redirect(self, session, url: str, source_finding) -> object | None:
        """PROBE-009: inject test URL into common redirect parameters."""
        import requests as _req
        for param in _REDIRECT_PARAMS:
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}{param}={_REDIRECT_TEST_URL}"
            try:
                r = session.get(
                    probe_url,
                    timeout=self.timeout,
                    allow_redirects=False,  # must NOT follow — we want the raw Location
                )
            except Exception:
                continue
            location = r.headers.get("Location", "")
            f = check_open_redirect(
                url, param, _REDIRECT_TEST_URL,
                r.status_code, location, source_finding,
            )
            if f:
                return f
        return None

    def _check_cors(self, session, url: str, source_finding) -> object | None:
        """PROBE-007: test CORS reflection."""
        import requests as _req
        try:
            r = session.get(
                url,
                headers={"Origin": _CORS_TEST_ORIGIN},
                timeout=self.timeout,
                allow_redirects=True,
            )
        except Exception:
            return None

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        return check_cors(url, acao, acac, _CORS_TEST_ORIGIN, source_finding)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_path(description: str) -> str:
    """Extract the URL/path from a JSEP finding description string."""
    import re
    # 'API endpoint reference: '/api/v1/users''
    # 'Sensitive endpoint discovered: '/admin/settings' — ...'
    m = re.search(r":\s*'([^']+)'", description)
    if m:
        return m.group(1)
    return ""


def _quick_post_status(session, url: str, timeout: int) -> int:
    """Send a minimal POST to *url* and return the status code (0 on error)."""
    try:
        r = session.post(url, data={}, timeout=timeout, allow_redirects=False)
        return r.status_code
    except Exception:
        return 0
