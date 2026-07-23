"""JWT Misconfiguration Analyzer (CWE-347).

Detects disabled signature verification and algorithm-confusion patterns.
References: CVE-2015-9235 (PyJWT alg:none), CVE-2022-21449 (ECDSA).
"""
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_JWT = VulnType.JWT_MISCONFIGURATION

_RULES = [
    # Python PyJWT >= 2.x: options={"verify_signature": False}
    (
        "JWT-001",
        re.compile(
            r'jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*["\']?verify_signature["\']?\s*:\s*False',
            re.IGNORECASE | re.DOTALL,
        ),
        "jwt.decode() with verify_signature=False disables signature validation — tokens are fully trusted without cryptographic proof",
        Severity.CRITICAL, _JWT, (".py",),
    ),
    # Python PyJWT: algorithms=["none"] or algorithms=["None"]
    (
        "JWT-002",
        re.compile(
            r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[[^\]]*(?:["\']none["\']|None)',
            re.IGNORECASE,
        ),
        "jwt.decode() with algorithms=['none'] accepts unsigned tokens — algorithm confusion attack (CVE-2015-9235)",
        Severity.CRITICAL, _JWT, (".py",),
    ),
    # Python python-jose: options={"verify_signature": False}
    (
        "JWT-003",
        re.compile(
            r'(?:jose\.)?jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*["\']?verify_at_hash["\']?\s*:\s*False|'
            r'(?:jose\.)?jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*["\']?verify_signature["\']?\s*:\s*False',
            re.IGNORECASE | re.DOTALL,
        ),
        "python-jose jwt.decode() with disabled verification option — JWT signatures not validated",
        Severity.CRITICAL, _JWT, (".py",),
    ),
    # Node.js jsonwebtoken: algorithms: ['none']
    (
        "JWT-004",
        re.compile(
            r'jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*["\']none["\']',
            re.IGNORECASE,
        ),
        "jwt.verify() with algorithms: ['none'] accepts unsigned tokens — reject the 'none' algorithm",
        Severity.CRITICAL, _JWT, (".js", ".ts"),
    ),
    # Node.js: jwt.sign with algorithm: 'none'
    (
        "JWT-005",
        re.compile(
            r'jwt\.sign\s*\([^)]*algorithm\s*:\s*["\']none["\']',
            re.IGNORECASE,
        ),
        "jwt.sign() with algorithm: 'none' creates unsigned tokens — use RS256 or HS256",
        Severity.HIGH, _JWT, (".js", ".ts"),
    ),
    # Java Auth0: JWT.decode() decodes without verifying (use JWT.require().build().verify())
    (
        "JWT-006",
        re.compile(
            r'\bJWT\.decode\s*\(',
            re.IGNORECASE,
        ),
        "Auth0 Java JWT.decode() decodes without signature verification — use JWT.require(algorithm).build().verify(token)",
        Severity.HIGH, _JWT, (".java",),
    ),
    # Java JJWT: Jwts.parser() without signing key check (deprecated unsecured form)
    (
        "JWT-007",
        re.compile(
            r'\bJwts\.(?:parser|parserBuilder)\s*\(\s*\)(?:\s*\.\s*(?!setSigningKey|verifyWith)\w+\s*\([^)]*\))*\s*\.\s*parse(?:ClaimsJwt|UnsecuredClaims)\s*\(',
            re.IGNORECASE,
        ),
        "JJWT Jwts.parser().parseClaimsJwt() parses unsigned JWTs — use parseClaimsJws() with setSigningKey()",
        Severity.HIGH, _JWT, (".java",),
    ),
]

_GUARD = re.compile(
    r'jwt\.decode|jwt\.verify|jwt\.sign|JWT\.decode|JWT\.require|Jwts\.parser|jose\.jwt',
    re.IGNORECASE,
)


class JWTAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".js", ".ts", ".java")

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
