"""CORS Misconfiguration Analyzer (CWE-346).

Detects CORS policies that allow unauthorized cross-origin access to sensitive resources.
Most dangerous: wildcard origin combined with credentials, or reflected origin without allowlist.
"""
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_CORS = VulnType.CORS_MISCONFIGURATION

_RULES = [
    # Python Flask-CORS / Django-CORS-Headers: wildcard + credentials (HIGH risk)
    (
        "CORS-001",
        re.compile(
            r'CORS\s*\([^)]*origins\s*=\s*["\'][*]["\'][^)]*supports_credentials\s*=\s*True'
            r'|CORS\s*\([^)]*supports_credentials\s*=\s*True[^)]*origins\s*=\s*["\'][*]["\']',
            re.IGNORECASE,
        ),
        "CORS wildcard origin with credentials=True — any site can make credentialed cross-origin requests; specify allowed origins explicitly",
        Severity.HIGH, _CORS, (".py",),
    ),
    # Django settings: CORS_ALLOW_ALL_ORIGINS = True (any origin allowed)
    (
        "CORS-002",
        re.compile(
            r'CORS_ALLOW_ALL_ORIGINS\s*=\s*True',
            re.IGNORECASE,
        ),
        "CORS_ALLOW_ALL_ORIGINS = True allows any origin to make cross-origin requests — use CORS_ALLOWED_ORIGINS with an explicit allowlist",
        Severity.MEDIUM, _CORS, (".py",),
    ),
    # Express: res.header("Access-Control-Allow-Origin", req.headers.origin) — reflects arbitrary origin
    (
        "CORS-003",
        re.compile(
            r'(?:res|response|ctx)\.(?:header|set|setHeader)\s*\([^)]*Access-Control-Allow-Origin[^)]*req\.(?:headers?\.origin|get\s*\(\s*["\']origin["\'])',
            re.IGNORECASE,
        ),
        "CORS policy reflects request Origin header without allowlist validation — any site can make credentialed cross-origin requests",
        Severity.HIGH, _CORS, (".js", ".ts"),
    ),
    # Node.js cors() middleware with origin: '*'
    (
        "CORS-004",
        re.compile(
            r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\'][*]["\']',
            re.IGNORECASE,
        ),
        "cors() middleware with origin: '*' — wildcard CORS allows any site to make cross-origin requests",
        Severity.MEDIUM, _CORS, (".js", ".ts"),
    ),
    # Java Spring: setAllowedOrigins("*") with setAllowCredentials(true)
    (
        "CORS-005",
        re.compile(
            r'setAllowedOrigins\s*\(\s*(?:["\'][*]["\']|Arrays\.asList\s*\(\s*["\'][*]["\'])',
            re.IGNORECASE,
        ),
        "Spring CORS setAllowedOrigins(\"*\") allows all origins — use a specific origin allowlist",
        Severity.MEDIUM, _CORS, (".java",),
    ),
    # Java Spring: @CrossOrigin(origins = "*")
    (
        "CORS-006",
        re.compile(
            r'@CrossOrigin\s*\([^)]*origins\s*=\s*(?:["\'][*]["\']|\*)',
            re.IGNORECASE,
        ),
        "@CrossOrigin with origins=\"*\" allows any site to make cross-origin requests to this endpoint",
        Severity.MEDIUM, _CORS, (".java",),
    ),
    # PHP: header("Access-Control-Allow-Origin: *")
    (
        "CORS-007",
        re.compile(
            r'header\s*\(\s*["\']Access-Control-Allow-Origin\s*:\s*\*["\']',
            re.IGNORECASE,
        ),
        "PHP header sets wildcard CORS — any origin can read responses from this endpoint",
        Severity.MEDIUM, _CORS, (".php",),
    ),
    # Python: response.headers["Access-Control-Allow-Origin"] = "*" or request.headers.get("Origin")
    (
        "CORS-008",
        re.compile(
            r'(?:response\.headers|headers)\s*\[\s*["\']Access-Control-Allow-Origin["\']'
            r'\s*\]\s*=\s*(?:["\'][*]["\']|request\.headers\.(?:get\s*\(\s*["\']Origin["\']|origin))',
            re.IGNORECASE,
        ),
        "CORS header set to wildcard or reflected request origin — restrict to known origins to prevent CSRF via CORS",
        Severity.MEDIUM, _CORS, (".py",),
    ),
]

_GUARD = re.compile(
    r'Access-Control-Allow-Origin|CORS_ALLOW_ALL_ORIGINS|cors\s*\(|@CrossOrigin|setAllowedOrigins|supports_credentials',
    re.IGNORECASE,
)


class CORSAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".js", ".ts", ".java", ".php")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []
        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if file_path.endswith(exts)
        ]
        if not applicable:
            return []
        return self._scan_lines(file_path, content, repo_url, applicable, guard=None,
                                mask_strings_py=True)
