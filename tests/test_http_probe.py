"""Tests for the http_probe module (scope, checks, prober)."""
from __future__ import annotations

import pytest

from vulnscanner.http_probe.scope import Scope, ScopeViolation
from vulnscanner.http_probe.checks import (
    check_unauth_access,
    check_error_disclosure,
    check_sensitive_data,
    check_method_confusion,
    check_idor,
    check_auth_bypass,
    check_cors,
    check_open_redirect,
)


# ── Scope ─────────────────────────────────────────────────────────────────────

class TestScope:
    def test_allows_declared_domain(self):
        s = Scope(["api.example.com"])
        assert s.is_allowed("https://api.example.com/v1/users")

    def test_blocks_undeclared_domain(self):
        s = Scope(["api.example.com"])
        assert not s.is_allowed("https://evil.com/steal")

    def test_blocks_subdomain_not_declared(self):
        s = Scope(["example.com"])
        assert not s.is_allowed("https://api.example.com/v1/users")

    def test_allows_subdomain_when_declared(self):
        s = Scope(["api.example.com", "example.com"])
        assert s.is_allowed("https://api.example.com/admin")

    def test_check_raises_on_out_of_scope(self):
        s = Scope(["example.com"])
        with pytest.raises(ScopeViolation, match="outside the declared scope"):
            s.check("https://evil.com/exploit")

    def test_build_url_prepends_base(self):
        s = Scope(["example.com"])
        url = s.build_url("https://example.com", "/api/v1/users")
        assert url == "https://example.com/api/v1/users"

    def test_build_url_rejects_out_of_scope_absolute(self):
        s = Scope(["example.com"])
        with pytest.raises(ScopeViolation):
            s.build_url("https://example.com", "https://evil.com/path")

    def test_empty_scope_raises(self):
        with pytest.raises(ValueError):
            Scope([])

    def test_scope_normalizes_scheme(self):
        s = Scope(["https://example.com"])
        assert s.is_allowed("https://example.com/path")

    def test_scope_normalizes_port(self):
        s = Scope(["example.com:8080"])
        assert s.is_allowed("https://example.com/path")

    def test_domains_property(self):
        s = Scope(["api.example.com", "example.com"])
        assert "example.com" in s.domains
        assert "api.example.com" in s.domains


# ── Checks ────────────────────────────────────────────────────────────────────

class TestCheckUnauth:
    def test_flags_200_on_admin(self):
        f = check_unauth_access("https://example.com/admin/users", 200, "{}", None)
        assert f is not None
        assert f.rule_id == "PROBE-001"
        assert f.severity.value == "HIGH"

    def test_flags_200_on_general(self):
        f = check_unauth_access("https://example.com/api/v1/users", 200, "[]", None)
        assert f is not None
        assert f.severity.value == "MEDIUM"

    def test_ignores_401(self):
        f = check_unauth_access("https://example.com/admin/users", 401, "Unauthorized", None)
        assert f is None

    def test_ignores_403(self):
        f = check_unauth_access("https://example.com/api/data", 403, "Forbidden", None)
        assert f is None


class TestCheckErrorDisclosure:
    def test_detects_php_fatal(self):
        body = "Fatal error: Call to undefined method User::save() in /var/www/html/app.php"
        f = check_error_disclosure("https://example.com/api/save", 500, body, None)
        assert f is not None
        assert f.rule_id == "PROBE-002"

    def test_detects_sql_error(self):
        body = "You have an error in your SQL syntax near '' at line 1"
        f = check_error_disclosure("https://example.com/api/search", 500, body, None)
        assert f is not None

    def test_detects_java_stacktrace(self):
        body = "at com.example.UserService.save(UserService.java:42)"
        f = check_error_disclosure("https://example.com/api/user", 500, body, None)
        assert f is not None

    def test_ignores_clean_json(self):
        f = check_error_disclosure("https://example.com/api/users", 200, '{"users":[]}', None)
        assert f is None


class TestCheckSensitiveData:
    def test_detects_private_key(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."
        f = check_sensitive_data("https://example.com/api/key", 200, body, None)
        assert f is not None
        assert f.rule_id == "PROBE-003"
        assert f.severity.value == "HIGH"

    def test_detects_aws_key(self):
        body = '{"key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}'
        f = check_sensitive_data("https://example.com/api/config", 200, body, None)
        assert f is not None

    def test_detects_password_in_json(self):
        body = '{"username": "admin", "password": "supersecret"}'
        f = check_sensitive_data("https://example.com/api/users/1", 200, body, None)
        assert f is not None

    def test_ignores_clean_response(self):
        f = check_sensitive_data("https://example.com/api/items", 200, '{"items": [1, 2, 3]}', None)
        assert f is None


class TestCheckMethodConfusion:
    def test_flags_get_200_on_write_endpoint(self):
        f = check_method_confusion("https://example.com/api/delete", 200, 200, None)
        assert f is not None
        assert f.rule_id == "PROBE-004"

    def test_ignores_get_404(self):
        f = check_method_confusion("https://example.com/api/delete", 404, 200, None)
        assert f is None

    def test_ignores_post_only_404(self):
        f = check_method_confusion("https://example.com/api/delete", 200, 404, None)
        assert f is None


# ── ProbeResult path extraction ───────────────────────────────────────────────

class TestProberHelpers:
    def test_extract_path_jsep001(self):
        from vulnscanner.http_probe.prober import _extract_path
        desc = "API endpoint reference: '/api/v1/users'"
        assert _extract_path(desc) == "/api/v1/users"

    def test_extract_path_jsep002(self):
        from vulnscanner.http_probe.prober import _extract_path
        desc = "Sensitive endpoint discovered: '/admin/settings' — verify..."
        assert _extract_path(desc) == "/admin/settings"

    def test_extract_path_no_match(self):
        from vulnscanner.http_probe.prober import _extract_path
        assert _extract_path("no path here") == ""


# ── New checks (PROBE-005/006/007) ────────────────────────────────────────────

class TestCheckIDOR:
    def test_flags_different_bodies(self):
        body_a = '{"id": 1, "email": "alice@example.com"}'
        body_b = '{"id": 2, "email": "bob@example.com"}'
        f = check_idor(
            "https://example.com/api/users/1", body_a, body_b,
            "https://example.com/api/users/2", 200, 200, None,
        )
        assert f is not None
        assert f.rule_id == "PROBE-005"
        assert f.severity.value == "HIGH"

    def test_ignores_identical_bodies(self):
        body = '{"public": true}'
        f = check_idor(
            "https://example.com/api/items/1", body, body,
            "https://example.com/api/items/2", 200, 200, None,
        )
        assert f is None

    def test_ignores_non_200_variant(self):
        f = check_idor(
            "https://example.com/api/users/1", '{"id":1}', '{"error":"not found"}',
            "https://example.com/api/users/2", 200, 404, None,
        )
        assert f is None

    def test_flags_size_difference(self):
        body_a = '{"id": 1, "data": "' + "x" * 500 + '"}'
        body_b = '{"id": 2, "data": "' + "y" * 50 + '"}'
        f = check_idor(
            "https://example.com/api/doc/1", body_a, body_b,
            "https://example.com/api/doc/2", 200, 200, None,
        )
        assert f is not None


class TestCheckAuthBypass:
    def test_flags_bypass(self):
        f = check_auth_bypass(
            "https://example.com/admin", 403, 200,
            "X-Forwarded-For: 127.0.0.1", None,
        )
        assert f is not None
        assert f.rule_id == "PROBE-006"
        assert f.severity.value == "CRITICAL"

    def test_ignores_403_stays_403(self):
        f = check_auth_bypass(
            "https://example.com/admin", 403, 403,
            "X-Forwarded-For: 127.0.0.1", None,
        )
        assert f is None

    def test_ignores_200_original(self):
        # If original was 200, there's nothing to bypass
        f = check_auth_bypass(
            "https://example.com/api/users", 200, 200,
            "X-Real-IP: 127.0.0.1", None,
        )
        assert f is None


class TestCheckCORS:
    def test_flags_reflected_origin(self):
        f = check_cors(
            "https://example.com/api/data",
            acao_header="https://corsscan.vulnscanner.invalid",
            acac_header="true",
            origin_sent="https://corsscan.vulnscanner.invalid",
            source_finding=None,
        )
        assert f is not None
        assert f.rule_id == "PROBE-007"
        assert f.severity.value == "HIGH"

    def test_ignores_different_origin(self):
        f = check_cors(
            "https://example.com/api/data",
            acao_header="https://trusted.example.com",
            acac_header="",
            origin_sent="https://corsscan.vulnscanner.invalid",
            source_finding=None,
        )
        assert f is None

    def test_ignores_wildcard_without_credentials(self):
        f = check_cors(
            "https://example.com/api/public",
            acao_header="*",
            acac_header="",
            origin_sent="https://corsscan.vulnscanner.invalid",
            source_finding=None,
        )
        assert f is None

    def test_flags_wildcard_with_credentials(self):
        f = check_cors(
            "https://example.com/api/data",
            acao_header="*",
            acac_header="true",
            origin_sent="https://corsscan.vulnscanner.invalid",
            source_finding=None,
        )
        assert f is not None
        assert f.rule_id == "PROBE-007"


# ── Bug bounty report generator ───────────────────────────────────────────────

class TestBugBountyReport:
    def _make_finding(self, rule_id="PROBE-001", sev="HIGH"):
        from vulnscanner.models import Finding, VulnType, Severity
        return Finding(
            vuln_type=VulnType.MISSING_AUTHORIZATION,
            severity=Severity(sev),
            file_path="app/routes.js",
            line_number=42,
            line_content="app.get('/admin/settings', handler);",
            description="Endpoint '/admin/settings' accessible without authentication",
            rule_id=rule_id,
        )

    def test_markdown_contains_finding(self):
        from vulnscanner.http_probe.report import BugBountyReport
        rpt = BugBountyReport(target="example.com", findings=[self._make_finding()])
        md = rpt.render("markdown")
        assert "PROBE-001" in md
        assert "Missing Authorization" in md
        assert "Remediation" in md

    def test_hackerone_format(self):
        from vulnscanner.http_probe.report import BugBountyReport
        rpt = BugBountyReport(target="example.com", findings=[self._make_finding()])
        text = rpt.render("hackerone")
        assert "Steps To Reproduce" in text
        assert "Impact" in text

    def test_bugcrowd_format(self):
        from vulnscanner.http_probe.report import BugBountyReport
        rpt = BugBountyReport(target="example.com", findings=[self._make_finding()])
        text = rpt.render("bugcrowd")
        assert "P2" in text  # HIGH → P2
        assert "Proof of Concept" in text

    def test_sorts_by_severity(self):
        from vulnscanner.http_probe.report import BugBountyReport
        findings = [
            self._make_finding("PROBE-001", "LOW"),
            self._make_finding("PROBE-002", "CRITICAL"),
            self._make_finding("PROBE-003", "MEDIUM"),
        ]
        rpt = BugBountyReport(target="t", findings=findings)
        md = rpt.render("markdown")
        pos_crit = md.index("CRITICAL")
        pos_low = md.index("LOW")
        assert pos_crit < pos_low  # CRITICAL appears before LOW

    def test_remediation_per_rule(self):
        from vulnscanner.http_probe.report import BugBountyReport
        rpt = BugBountyReport(target="t", findings=[self._make_finding("PROBE-006")])
        md = rpt.render("markdown")
        assert "X-Forwarded-For" in md


# ── PROBE-009: Open redirect ──────────────────────────────────────────────────

class TestCheckOpenRedirect:
    _TEST_URL = "https://open-redirect.vulnscanner.invalid"

    def test_flags_302_location_reflects_injected(self):
        f = check_open_redirect(
            "https://example.com/login",
            param_name="next",
            injected_url=self._TEST_URL,
            response_status=302,
            location_header=self._TEST_URL,
            source_finding=None,
        )
        assert f is not None
        assert f.rule_id == "PROBE-009"
        assert f.severity.value == "MEDIUM"

    def test_flags_301_redirect(self):
        f = check_open_redirect(
            "https://example.com/auth",
            param_name="return_url",
            injected_url=self._TEST_URL,
            response_status=301,
            location_header=self._TEST_URL,
            source_finding=None,
        )
        assert f is not None

    def test_flags_307_redirect(self):
        f = check_open_redirect(
            "https://example.com/redirect",
            param_name="url",
            injected_url=self._TEST_URL,
            response_status=307,
            location_header=f"https://example.com/?{self._TEST_URL}",
            source_finding=None,
        )
        assert f is not None

    def test_ignores_200_response(self):
        f = check_open_redirect(
            "https://example.com/login",
            param_name="next",
            injected_url=self._TEST_URL,
            response_status=200,
            location_header=self._TEST_URL,
            source_finding=None,
        )
        assert f is None

    def test_ignores_302_without_injected_url(self):
        f = check_open_redirect(
            "https://example.com/login",
            param_name="next",
            injected_url=self._TEST_URL,
            response_status=302,
            location_header="https://example.com/dashboard",
            source_finding=None,
        )
        assert f is None

    def test_ignores_empty_location(self):
        f = check_open_redirect(
            "https://example.com/login",
            param_name="next",
            injected_url=self._TEST_URL,
            response_status=302,
            location_header="",
            source_finding=None,
        )
        assert f is None

    def test_description_contains_param_name(self):
        f = check_open_redirect(
            "https://example.com/auth",
            param_name="redirect_uri",
            injected_url=self._TEST_URL,
            response_status=302,
            location_header=self._TEST_URL,
            source_finding=None,
        )
        assert f is not None
        assert "redirect_uri" in f.description

    def test_report_remediation_probe009(self):  # noqa: E301
        from vulnscanner.http_probe.report import BugBountyReport
        from vulnscanner.models import Finding, VulnType, Severity
        finding = Finding(
            vuln_type=VulnType.OPEN_REDIRECT,
            severity=Severity.MEDIUM,
            file_path="https://example.com/login",
            line_number=0,
            line_content="https://example.com/login",
            description="Open redirect via next= parameter",
            rule_id="PROBE-009",
        )
        rpt = BugBountyReport(target="example.com", findings=[finding])
        md = rpt.render("markdown")
        assert "allowlist" in md.lower()


# ── PROBE-010: Subdomain takeover ─────────────────────────────────────────────

class TestSubdomainTakeover:
    def test_extract_github_pages(self):
        from vulnscanner.http_probe.subdomain_takeover import extract_cloud_subdomains
        html = '<a href="https://myapp.github.io/docs">Docs</a>'
        candidates = extract_cloud_subdomains("index.html", html)
        assert any(c.subdomain == "myapp.github.io" for c in candidates)
        assert any(c.service == "GitHub Pages" for c in candidates)

    def test_extract_s3_bucket(self):
        from vulnscanner.http_probe.subdomain_takeover import extract_cloud_subdomains
        html = 'src="https://assets.s3.amazonaws.com/logo.png"'
        candidates = extract_cloud_subdomains("page.html", html)
        assert any("s3.amazonaws.com" in c.subdomain for c in candidates)
        assert any(c.service == "AWS S3" for c in candidates)

    def test_extract_heroku(self):
        from vulnscanner.http_probe.subdomain_takeover import extract_cloud_subdomains
        js = "const apiBase = 'https://myapi.herokuapp.com';"
        candidates = extract_cloud_subdomains("config.js", js)
        assert any(c.service == "Heroku" for c in candidates)

    def test_extract_deduplicates(self):
        from vulnscanner.http_probe.subdomain_takeover import extract_cloud_subdomains
        html = (
            '<a href="https://myapp.github.io">link1</a>\n'
            '<a href="https://myapp.github.io">link2</a>\n'
        )
        candidates = extract_cloud_subdomains("page.html", html)
        gh_candidates = [c for c in candidates if c.subdomain == "myapp.github.io"]
        assert len(gh_candidates) == 1

    def test_no_false_positive_clean_html(self):
        from vulnscanner.http_probe.subdomain_takeover import extract_cloud_subdomains
        html = '<a href="https://example.com/about">About</a>'
        candidates = extract_cloud_subdomains("page.html", html)
        assert candidates == []

    def test_flags_github_pages_unclaimed(self):
        from vulnscanner.http_probe.subdomain_takeover import (
            check_subdomain_takeover, SubdomainCandidate,
        )
        candidate = SubdomainCandidate(
            subdomain="old-project.github.io",
            service="GitHub Pages",
            source_file="index.html",
            source_line=12,
        )
        body = "There isn't a GitHub Pages site here."
        f = check_subdomain_takeover(candidate, 404, body, None)
        assert f is not None
        assert f.rule_id == "PROBE-010"
        assert f.severity.value == "HIGH"
        assert "old-project.github.io" in f.description

    def test_flags_heroku_unclaimed(self):
        from vulnscanner.http_probe.subdomain_takeover import (
            check_subdomain_takeover, SubdomainCandidate,
        )
        candidate = SubdomainCandidate(
            subdomain="stale-app.herokuapp.com",
            service="Heroku",
            source_file="app.js",
            source_line=5,
        )
        body = "No such app"
        f = check_subdomain_takeover(candidate, 404, body, None)
        assert f is not None

    def test_flags_s3_unclaimed(self):
        from vulnscanner.http_probe.subdomain_takeover import (
            check_subdomain_takeover, SubdomainCandidate,
        )
        candidate = SubdomainCandidate(
            subdomain="old-bucket.s3.amazonaws.com",
            service="AWS S3",
            source_file="template.html",
            source_line=8,
        )
        body = "<Error><Code>NoSuchBucket</Code></Error>"
        f = check_subdomain_takeover(candidate, 404, body, None)
        assert f is not None

    def test_ignores_live_service(self):
        from vulnscanner.http_probe.subdomain_takeover import (
            check_subdomain_takeover, SubdomainCandidate,
        )
        candidate = SubdomainCandidate(
            subdomain="active.github.io",
            service="GitHub Pages",
            source_file="index.html",
            source_line=1,
        )
        body = "<html><body>Welcome to our site!</body></html>"
        f = check_subdomain_takeover(candidate, 200, body, None)
        assert f is None

    def test_report_remediation_probe010(self):
        from vulnscanner.http_probe.report import BugBountyReport
        from vulnscanner.models import Finding, VulnType, Severity
        finding = Finding(
            vuln_type=VulnType.MISSING_AUTHORIZATION,
            severity=Severity.HIGH,
            file_path="index.html",
            line_number=12,
            line_content="old-project.github.io",
            description="Subdomain takeover candidate",
            rule_id="PROBE-010",
        )
        rpt = BugBountyReport(target="example.com", findings=[finding])
        md = rpt.render("markdown")
        assert "CNAME" in md or "DNS" in md
