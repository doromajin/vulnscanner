"""
Shared file-context classification for suppressing findings in test,
fixture, and vendor files.

Configuration
-------------
INCLUDE_TEST_FILES : bool
    When True, findings in test/fixture paths are reported normally.
    Default False (suppress).
INCLUDE_VENDOR_FILES : bool
    When True, findings in vendor/third-party paths are reported normally.
    Default False (suppress).
"""
from __future__ import annotations

import re

# ── Configuration (future CLI flag hooks) ─────────────────────────────────────

INCLUDE_TEST_FILES: bool = False
INCLUDE_VENDOR_FILES: bool = False

# ── Test path detection ────────────────────────────────────────────────────────

# Single directory-name segments that indicate test code.
# Checked against individual path components so "contest" or "latest"
# are NOT matched.
_TEST_SEGMENTS = frozenset({
    "test", "tests",
    "spec", "specs",
    "__tests__",
    "it",           # Java integration tests (src/it/)
    "integration",  # common integration-test directory
    "testing",      # e.g. pyspider/testing/
})

# Single directory-name segments that indicate fixture / mock data.
_FIXTURE_SEGMENTS = frozenset({
    "fixture", "fixtures",
    "mock", "mocks",
    "stub", "stubs",
    "fake", "fakes",
    "testdata", "test_data",
    "sample", "samples",
    "dummy",
})

# File-name patterns that identify test files without a dedicated directory.
_TEST_FILENAME_RE = re.compile(
    r"(?:"
    r"Test\.(?:java|kt|groovy)$"            # Java/Kotlin  *Test.java
    r"|Test\.php$"                           # PHP          *Test.php
    r"|_test\.py$"                           # Python       foo_test.py
    r"|(?:^|[\\/])test_[^/\\]+\.py$"        # Python       test_foo.py
    r"|\.test\.[jt]sx?$"                     # JS/TS        *.test.js/ts
    r"|\.spec\.[jt]sx?$"                     # JS/TS        *.spec.js/ts
    r"|_spec\.rb$"                           # Ruby         foo_spec.rb
    r")",
    re.IGNORECASE,
)


def is_test_path(path: str) -> bool:
    """Return True if *path* resides in a test directory or has a test filename.

    Uses segment-level matching to avoid false positives on names like
    ``ContestController.php`` or ``LatestNews.php``.
    """
    norm = path.replace("\\", "/")
    parts = norm.lower().split("/")
    if any(p in _TEST_SEGMENTS for p in parts):
        return True
    return bool(_TEST_FILENAME_RE.search(norm))


def is_fixture_path(path: str) -> bool:
    """Return True if *path* resides in a fixture, mock, or stub directory."""
    parts = path.replace("\\", "/").lower().split("/")
    return any(p in _FIXTURE_SEGMENTS for p in parts)


# ── Vendor / third-party path detection ───────────────────────────────────────

# Unambiguous vendor directory segment names.
_VENDOR_SEGMENTS = frozenset({
    "vendor",
    "node_modules",
    "bower_components",
    "third_party",
    "3rdparty",
    "external",
    "externals",
})

# Known third-party library file-name prefixes/patterns.
_VENDOR_FILENAME_RE = re.compile(
    r"(?:^|[\\/])(?:"
    r"jquery[.\-]|bootstrap[.\-]|html5shiv|modernizr|respond[.\-]|polyfill|"
    r"lodash[.\-]|underscore|backbone|ember|angular|react|vue[.\-]|"
    r"moment[.\-]|chart\.js|d3[.\-]|leaflet|tinymce|ckeditor|codemirror|"
    r"font-awesome|normalize|reset\.css"
    r")",
    re.IGNORECASE,
)


def is_vendor_file(path: str) -> bool:
    """Return True if *path* is a third-party vendor or library file."""
    norm = path.replace("\\", "/")
    parts = norm.lower().split("/")
    if any(p in _VENDOR_SEGMENTS for p in parts):
        return True
    return bool(_VENDOR_FILENAME_RE.search(norm))


# ── Combined classifier ────────────────────────────────────────────────────────

def classify_file_context(path: str) -> dict:
    """Return a classification dict describing the nature of *path*.

    Returns
    -------
    {
        "is_test":    bool,
        "is_fixture": bool,
        "is_vendor":  bool,
        "reason":     "vendor_path" | "fixture_path" | "test_path" | None,
    }

    ``reason`` is the primary suppression reason in priority order:
    vendor > fixture > test.
    """
    vendor = is_vendor_file(path)
    fixture = is_fixture_path(path)
    test = is_test_path(path)

    if vendor:
        reason: str | None = "vendor_path"
    elif fixture:
        reason = "fixture_path"
    elif test:
        reason = "test_path"
    else:
        reason = None

    return {
        "is_test": test,
        "is_fixture": fixture,
        "is_vendor": vendor,
        "reason": reason,
    }
