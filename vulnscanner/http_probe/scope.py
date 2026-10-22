"""Scope management for authorized HTTP testing.

All probe requests MUST pass scope validation before being sent.
Out-of-scope requests raise ScopeViolation — they are never silently skipped.
"""
from __future__ import annotations

from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a URL is outside the declared testing scope."""


class Scope:
    """Strict allowlist of authorized domains for HTTP probing.

    Only exact domain matches (and their subpaths) are permitted.
    Subdomains require explicit declaration.

    Example:
        scope = Scope(["api.example.com", "example.com"])
        scope.check("https://api.example.com/v1/users")  # OK
        scope.check("https://evil.com/")                 # raises ScopeViolation
    """

    def __init__(self, domains: list[str]) -> None:
        if not domains:
            raise ValueError("At least one scope domain is required")
        # Normalize: strip scheme, port, trailing slash, lowercase
        self._domains: frozenset[str] = frozenset(
            _normalize_domain(d) for d in domains
        )

    @property
    def domains(self) -> list[str]:
        return sorted(self._domains)

    def is_allowed(self, url: str) -> bool:
        """Return True if *url* is within scope."""
        try:
            host = _normalize_domain(urlparse(url).netloc)
        except Exception:
            return False
        return host in self._domains

    def check(self, url: str) -> None:
        """Raise ScopeViolation if *url* is outside scope."""
        if not self.is_allowed(url):
            parsed = urlparse(url)
            raise ScopeViolation(
                f"URL {url!r} is outside the declared scope.\n"
                f"  Host    : {parsed.netloc}\n"
                f"  Allowed : {', '.join(self.domains)}\n"
                f"  Add --scope {parsed.netloc} to authorize testing this domain."
            )

    def build_url(self, base_url: str, path: str) -> str:
        """Combine *base_url* and *path* into a full URL, then validate scope."""
        base = base_url.rstrip("/")
        if path.startswith("http://") or path.startswith("https://"):
            full = path
        else:
            full = base + "/" + path.lstrip("/")
        self.check(full)
        return full


def _normalize_domain(netloc: str) -> str:
    """Extract lowercase hostname without port from a netloc or plain domain string."""
    # If it looks like a URL scheme was included, parse it out
    if "://" in netloc:
        netloc = urlparse(netloc).netloc
    # Strip port
    host = netloc.split(":")[0].strip().lower()
    return host
