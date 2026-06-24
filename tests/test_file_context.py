"""Tests for the shared file-context classification utilities."""
import pytest

from vulnscanner.analyzers.file_context import (
    classify_file_context,
    is_fixture_path,
    is_test_path,
    is_vendor_file,
)


# ── is_test_path ──────────────────────────────────────────────────────────────

class TestIsTestPath:
    # ── should return True ────────────────────────────────────────────────────

    def test_tests_directory(self):
        assert is_test_path("tests/FooTest.php")

    def test_test_directory(self):
        assert is_test_path("test/example.php")

    def test_spec_directory(self):
        assert is_test_path("spec/UserSpec.php")

    def test_dunder_tests_directory(self):
        assert is_test_path("src/__tests__/foo.php")

    def test_fixtures_subdir_of_tests(self):
        assert is_test_path("tests/fixtures/deser_payload.php")

    def test_java_test_suffix(self):
        assert is_test_path("app/Service/UserServiceTest.java")

    def test_php_test_suffix(self):
        assert is_test_path("app/Service/UserServiceTest.php")

    def test_python_test_prefix(self):
        assert is_test_path("src/test_utils.py")

    def test_python_test_suffix(self):
        assert is_test_path("src/utils_test.py")

    def test_js_test_extension(self):
        assert is_test_path("src/components/Button.test.js")

    def test_ts_spec_extension(self):
        assert is_test_path("src/services/auth.spec.ts")

    def test_ruby_spec_suffix(self):
        assert is_test_path("spec/models/user_spec.rb")

    def test_integration_directory(self):
        assert is_test_path("integration/api_test.py")

    def test_testing_directory(self):
        # pyspider uses pyspider/testing/ for test data
        assert is_test_path("pyspider/testing/data_test_webpage.py")

    def test_it_directory(self):
        # Java Maven integration tests: src/it/
        assert is_test_path("src/it/SomeIT.java")

    def test_webgoat_style_path(self):
        assert is_test_path(
            "src/test/java/org/owasp/webgoat/webwolf/user/UserServiceTest.java"
        )

    # ── should return False ───────────────────────────────────────────────────

    def test_no_fp_contest_controller(self):
        assert not is_test_path("src/ContestController.php")

    def test_no_fp_latest_news(self):
        assert not is_test_path("src/LatestNews.php")

    def test_no_fp_user_controller(self):
        assert not is_test_path("app/Http/Controllers/UserController.php")

    def test_no_fp_view_template(self):
        assert not is_test_path("resources/views/template.php")

    def test_no_fp_plain_config(self):
        assert not is_test_path("config/database.py")

    def test_no_fp_protest_filename(self):
        # "protest" contains "test" but is not a test file
        assert not is_test_path("docs/protest_analysis.md")


# ── is_fixture_path ───────────────────────────────────────────────────────────

class TestIsFixturePath:
    def test_fixtures_directory(self):
        assert is_fixture_path("tests/fixtures/user_payload.php")

    def test_fixture_directory_singular(self):
        assert is_fixture_path("test/fixture/data.json")

    def test_mocks_directory(self):
        assert is_fixture_path("tests/mocks/ApiMock.java")

    def test_mock_directory_singular(self):
        assert is_fixture_path("mock/responses.json")

    def test_stubs_directory(self):
        assert is_fixture_path("stubs/payment_gateway.php")

    def test_stub_directory_singular(self):
        assert is_fixture_path("stub/oauth.json")

    def test_no_fp_production_fixture(self):
        # "fixture" in a production service name should not match
        # but "fixture" as a path segment would match - by design
        assert not is_fixture_path("app/Http/Controllers/UserController.php")

    def test_no_fp_vendor_path(self):
        assert not is_fixture_path("vendor/symfony/http-foundation/Request.php")


# ── is_vendor_file ────────────────────────────────────────────────────────────

class TestIsVendorFile:
    # ── should return True ────────────────────────────────────────────────────

    def test_vendor_composer(self):
        assert is_vendor_file("vendor/symfony/http-foundation/Request.php")

    def test_node_modules(self):
        assert is_vendor_file("node_modules/lodash/index.js")

    def test_bower_components(self):
        assert is_vendor_file("bower_components/jquery/dist/jquery.js")

    def test_third_party(self):
        assert is_vendor_file("third_party/phpmailer/src/PHPMailer.php")

    def test_3rdparty(self):
        assert is_vendor_file("3rdparty/somelib/lib.php")

    def test_external_directory(self):
        assert is_vendor_file("external/requests/requests.py")

    def test_externals_directory(self):
        assert is_vendor_file("externals/libxml/parser.c")

    def test_jquery_filename(self):
        assert is_vendor_file("public/js/jquery-3.6.0.min.js")

    def test_bootstrap_filename(self):
        assert is_vendor_file("assets/js/bootstrap-5.2.0.bundle.min.js")

    def test_html5shiv_filename(self):
        assert is_vendor_file("public/js/html5shiv.min.js")

    def test_modernizr_filename(self):
        assert is_vendor_file("js/modernizr-custom.js")

    def test_invoiceplane_third_party_path(self):
        # Confirmed FP: InvoicePlane MX/Loader.php in third_party/
        assert is_vendor_file(
            "application/third_party/MX/Loader.php"
        )

    def test_snipe_it_html5shiv(self):
        # Confirmed FP: snipe-it html5shiv.js polyfill
        assert is_vendor_file("public/js/html5shiv.js")

    # ── should return False ───────────────────────────────────────────────────

    def test_no_fp_payment_vendor_service(self):
        # "vendor" appears in the class name but not as a path segment
        assert not is_vendor_file("app/Services/PaymentVendorService.php")

    def test_no_fp_external_api_client(self):
        assert not is_vendor_file("src/ExternalApiClient.php")

    def test_no_fp_normal_controller(self):
        assert not is_vendor_file("app/Http/Controllers/UserController.php")


# ── classify_file_context ─────────────────────────────────────────────────────

class TestClassifyFileContext:
    def test_test_file(self):
        ctx = classify_file_context("tests/UserTest.php")
        assert ctx["is_test"] is True
        assert ctx["is_vendor"] is False
        assert ctx["reason"] == "test_path"

    def test_fixture_file(self):
        ctx = classify_file_context("tests/fixtures/payload.json")
        assert ctx["is_fixture"] is True
        assert ctx["reason"] == "fixture_path"

    def test_vendor_file(self):
        ctx = classify_file_context("vendor/guzzle/src/Client.php")
        assert ctx["is_vendor"] is True
        assert ctx["reason"] == "vendor_path"

    def test_vendor_takes_priority_over_test(self):
        # A test file inside vendor/ should be classified as vendor (higher priority)
        ctx = classify_file_context("vendor/phpunit/phpunit/src/Framework/TestCase.php")
        assert ctx["is_vendor"] is True
        assert ctx["reason"] == "vendor_path"

    def test_fixture_takes_priority_over_test(self):
        ctx = classify_file_context("tests/fixtures/deser.php")
        assert ctx["is_fixture"] is True
        assert ctx["reason"] == "fixture_path"

    def test_normal_production_file(self):
        ctx = classify_file_context("app/Http/Controllers/UserController.php")
        assert ctx["is_test"] is False
        assert ctx["is_fixture"] is False
        assert ctx["is_vendor"] is False
        assert ctx["reason"] is None


# ── scanner-level integration ─────────────────────────────────────────────────

class TestScannerContextSuppression:
    """Verify that the scanner suppresses test/vendor findings end-to-end."""

    def test_test_path_findings_suppressed(self, tmp_path):
        from vulnscanner.scanner import VulnScanner

        repo = tmp_path / "myproject"
        (repo / "tests").mkdir(parents=True)
        (repo / "tests" / "AuthTest.java").write_text(
            'String password = "supersecret123";', encoding="utf-8"
        )

        result = VulnScanner().scan(str(repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert "SEC-001" not in rule_ids, "SEC-001 in test file must be suppressed"
        assert result.suppressed_count >= 1

    def test_vendor_path_findings_suppressed(self, tmp_path):
        from vulnscanner.scanner import VulnScanner

        # LocalFetcher already skips 'vendor/' at directory level.
        # Use 'third_party/' which LocalFetcher does NOT skip but file_context detects.
        repo = tmp_path / "myproject"
        (repo / "application" / "third_party" / "MX").mkdir(parents=True)
        (repo / "application" / "third_party" / "MX" / "Loader.php").write_text(
            "echo eval('?>' . file_get_contents($_ci_path));", encoding="utf-8"
        )

        result = VulnScanner().scan(str(repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert "CMD-004" not in rule_ids, "CMD-004 in third_party must be suppressed"
        assert result.suppressed_count >= 1

    def test_node_modules_already_skipped_by_fetcher(self, tmp_path):
        from vulnscanner.scanner import VulnScanner

        # node_modules is excluded by LocalFetcher before reaching the scanner.
        # Verify no findings appear (scanned_files may be 0).
        repo = tmp_path / "proj"
        (repo / "node_modules" / "pkg").mkdir(parents=True)
        (repo / "node_modules" / "pkg" / "index.js").write_text(
            "el.innerHTML = userInput;", encoding="utf-8"
        )
        (repo / "app.js").write_text("const x = 1;", encoding="utf-8")

        result = VulnScanner().scan(str(repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert "XSS-001" not in rule_ids

    def test_production_file_findings_not_suppressed(self, tmp_path):
        from vulnscanner.scanner import VulnScanner

        repo = tmp_path / "myproject" / "app"
        repo.mkdir(parents=True)
        (repo / "controller.php").write_text(
            '$data = unserialize($_POST["data"]);', encoding="utf-8"
        )

        result = VulnScanner().scan(str(repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert "DESER-004" in rule_ids, "Production DESER-004 must NOT be suppressed"

    def test_suppressed_count_tracks_third_party_findings(self, tmp_path):
        from vulnscanner.scanner import VulnScanner

        repo = tmp_path / "proj"
        (repo / "third_party" / "somelib").mkdir(parents=True)
        (repo / "third_party" / "somelib" / "helper.php").write_text(
            "$d = unserialize($_POST['d']);", encoding="utf-8"
        )
        (repo / "app.php").write_text("<?php echo 'hello';", encoding="utf-8")

        result = VulnScanner().scan(str(repo))
        assert result.suppressed_count >= 1
