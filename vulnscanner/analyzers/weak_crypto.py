import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_WC = VulnType.WEAK_CRYPTOGRAPHY

_RULES = [
    # ECB mode — identical plaintext blocks produce identical ciphertext blocks
    (
        "WCRYPTO-001",
        re.compile(
            r'(?:'
            r'Cipher\.getInstance\s*\(\s*["\'][^"\']*(?:AES|DES)[^"\']*ECB'
            r'|AES\.MODE_ECB'
            r'|CipherMode\.ECB'
            r')',
            re.IGNORECASE,
        ),
        "ECB cipher mode leaks plaintext patterns — use AES-GCM or AES-CBC with HMAC",
        Severity.HIGH, _WC, None,
    ),
    # DES / 3DES — 56-bit key is brute-forceable; deprecated since 2017
    (
        "WCRYPTO-002",
        re.compile(
            r'(?:'
            r'Cipher\.getInstance\s*\(\s*["\'](?:DES|DESede|TripleDES)[/"\'\/]'
            r'|from\s+Crypto\.Cipher\s+import\s+DES\b'
            r'|import\s+javax\.crypto.*\bDES\b'
            r')',
            re.IGNORECASE,
        ),
        "DES/3DES is broken (56-bit key, known weak) — use AES-256",
        Severity.HIGH, _WC, None,
    ),
    # RC4 — multiple biases, BEAST/NOMORE attacks
    (
        "WCRYPTO-003",
        re.compile(
            r'Cipher\.getInstance\s*\(\s*["\'](?:RC4|ARCFOUR)["\']',
            re.IGNORECASE,
        ),
        "RC4 stream cipher has known statistical biases — use AES-GCM",
        Severity.HIGH, _WC, (".java",),
    ),
    # MD5 for password hashing (PHP: md5($password) or sha1($password))
    (
        "WCRYPTO-004",
        re.compile(
            r'\b(?:md5|sha1)\s*\(\s*\$(?:pass(?:word)?|pwd|secret|credential)',
            re.IGNORECASE,
        ),
        "MD5/SHA1 is not a password hashing function — use password_hash() with PASSWORD_BCRYPT/ARGON2",
        Severity.CRITICAL, _WC, (".php",),
    ),
    # MD5/SHA1 for password hashing (Python: hashlib.md5(password...))
    (
        "WCRYPTO-005",
        re.compile(
            r'hashlib\.(?:md5|sha1)\s*\([^)]*(?:pass(?:word)?|pwd|secret|credential)',
            re.IGNORECASE,
        ),
        "hashlib.md5/sha1 used with password-like variable — use bcrypt, argon2-cffi, or hashlib.scrypt",
        Severity.CRITICAL, _WC, (".py",),
    ),
    # MD5/SHA1 for password hashing (Node.js: crypto.createHash('md5').update(password))
    (
        "WCRYPTO-006",
        re.compile(
            r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)"
            r"[^;\n]{0,80}\.update\s*\([^)]*(?:pass(?:word)?|pwd|secret|credential)",
            re.IGNORECASE,
        ),
        "crypto.createHash('md5'/'sha1') for password hashing — use bcrypt, scrypt, or argon2",
        Severity.CRITICAL, _WC, (".js", ".ts"),
    ),
    # MessageDigest MD5/SHA1 in Java (general; SHA-1 is broken for signatures)
    (
        "WCRYPTO-007",
        re.compile(
            r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-?1)["\']',
            re.IGNORECASE,
        ),
        "MD5/SHA-1 MessageDigest is cryptographically broken — use SHA-256+ for checksums; bcrypt/PBKDF2 for passwords",
        Severity.MEDIUM, _WC, (".java",),
    ),
    # Math.random() on a line that also mentions a security-sensitive term
    (
        "WCRYPTO-008",
        re.compile(
            r'(?:token|secret|nonce|salt|csrf|api[_.\-]?key|password)[^;\n]{0,80}Math\.random\s*\(\s*\)'
            r'|Math\.random\s*\(\s*\)[^;\n]{0,80}(?:token|secret|nonce|salt|csrf|api[_.\-]?key|password)',
            re.IGNORECASE,
        ),
        "Math.random() is not cryptographically secure — use crypto.randomBytes() or crypto.getRandomValues()",
        Severity.HIGH, _WC, (".js", ".ts"),
    ),
]

_GUARD = re.compile(
    r'AES\.MODE_ECB|CipherMode\.ECB|Cipher\.getInstance'
    r'|DESede|TripleDES|RC4|ARCFOUR'
    r'|Crypto\.Cipher'
    r'|\bmd5\s*\(|\bsha1\s*\('
    r'|hashlib\.(?:md5|sha1)'
    r'|crypto\.createHash\s*\(["\'](?:md5|sha1)'
    r'|MessageDigest\.getInstance'
    r'|Math\.random\s*\(\s*\)',
    re.IGNORECASE,
)


class WeakCryptoAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".php", ".java", ".js", ".ts",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []

        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if exts is None or file_path.endswith(exts)
        ]
        if not applicable:
            return []
        return self._scan_lines(file_path, content, repo_url, applicable, guard=None)
