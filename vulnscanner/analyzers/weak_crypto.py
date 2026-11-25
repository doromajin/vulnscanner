import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.file_context import rust_test_lines
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
    # Python: random module used for security-sensitive values
    (
        "WCRYPTO-009",
        re.compile(
            r'(?:token|secret|nonce|salt|csrf|api[_.\-]?key|password|pin|otp)[^=\n]{0,30}='
            r'[^;\n]*\brandom\.(?:choice|randint|random|getrandbits|uniform|sample)\s*\('
            r'|\brandom\.(?:choice|randint|random|getrandbits|uniform|sample)\s*\([^;\n]{0,100}'
            r'(?:token|secret|nonce|salt|csrf|api[_.\-]?key|password|pin|otp)',
            re.IGNORECASE,
        ),
        "Python random module is not cryptographically secure — use secrets.choice(), secrets.token_hex(), or secrets.token_bytes() for security-sensitive values",
        Severity.HIGH, _WC, (".py",),
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
    r'|Math\.random\s*\(\s*\)'
    r'|\brandom\.(?:choice|randint|random|getrandbits|uniform|sample)\s*\(',
    re.IGNORECASE,
)

# Cheap pre-filter for the Go / Ruby / Rust / C# rules.
_LANG_GUARD = re.compile(
    r'md5|sha1|\bdes\.|\bDES\b|TripleDES|RC[24]|OpenSSL::|InsecureSkipVerify|VERIFY_NONE|danger_accept'
    r'|ServerCertificate|DangerousAccept|MinVersion|min_version|ssl_version|SslProtocols|SecurityProtocol'
    r'|\brand\b|Random|DefaultHasher|thread_rng|fastrand|SmallRng|oorandom|ECB',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------------------------
# Go / Ruby / Rust / C#
#
# Rule tuple: (rule_id, regex, description, severity, vuln_type, extensions, skip_regex, file_predicate)
# `skip_regex` suppresses a line that also matches it; `file_predicate(content)` gates the rule on a
# whole-file condition (e.g. the file imports math/rand and not crypto/rand).
# ---------------------------------------------------------------------------------------------

_GO, _RB, _RS, _CS = (".go",), (".rb",), (".rs",), (".cs",)
_I = re.IGNORECASE

# A digest used for an ETag, cache key, avatar URL or as the inner hash of an HMAC is not a security control.
_HASH_BENIGN_RE = re.compile(r'hmac|etag|checksum|fingerprint|cache|gravatar|md5hash|content_?md5', _I)
_PWD_WORD = r'(?:pass(?:word|wd|phrase)|\bpass\b|\bpwd|credential|secret)'
_PWD_ARG_RE = re.compile(_PWD_WORD, _I)
_HASH_OR_PWD_SKIP_RE = re.compile(r'hmac|etag|checksum|fingerprint|cache|gravatar|md5hash|content_?md5|' + _PWD_WORD, _I)
_CONDITIONAL_RE = re.compile(r'\b(?:if|unless|elsif|else|when|match)\b|\?[^?\n]*:')
_RUST_USE_RE = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?use\s')

_MD5_SHA1 = {
    ".go": re.compile(r'\b(?:md5|sha1)\.(?:New|Sum)\s*\('),
    ".rb": re.compile(r'\bDigest::(?:MD5|SHA1)\b|\bOpenSSL::Digest(?:\.new)?\s*\(\s*["\'](?:MD5|SHA1)["\']', _I),
    ".rs": re.compile(r'\b(?:md5::compute|Md5::(?:new|digest|default)|Sha1::(?:new|digest|default|from)|sha1::Sha1::)'),
    ".cs": re.compile(
        r'\b(?:MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)?\.(?:Create|HashData)\s*\('
        r'|\bnew\s+(?:MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)\s*\('
        r'|\bHashAlgorithm\.Create\s*\(\s*"(?:MD5|SHA1)"'
        r'|\bHashAlgorithmName\.(?:MD5|SHA1)\b'
    ),
}
_MD5_SHA1_PWD = {
    ext: re.compile(r'(?:' + rx.pattern + r')[^\n]*' + _PWD_WORD, rx.flags | _I)
    for ext, rx in _MD5_SHA1.items()
}


_SENSITIVE_CTX_RE = re.compile(
    r'pass(?:word|wd|phrase)|\bpwd|secret|token|\bauth|session|\bsign|hmac|verif|credential|login|\bsalt', _I)
_IDENTITY_CTX_RE = re.compile(r'hash|digest|checksum|etag|fingerprint|cache|content_?md5|dedup|\bmd5\b|\bsha1\b', _I)
_IDENTITY_NEAR_RE = re.compile(
    r'hashcode|\bhashed\b|checksum|etag|fingerprint|cache[_ ]?key|content-?md5|dedup|\b(?:id|key)\w*\s*=', _I)
_FUNC_START_RE = re.compile(
    r'^\s*(?:func\s+(?:\([^)]*\)\s*)?(\w+)|def\s+(?:self\.)?(\w+[?!]?)|(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)'
    r'|(?:(?:public|private|protected|internal|static|override|virtual|async|unsafe)\s+)+[\w<>\[\],.?]+\s+(\w+)\s*(?:<[^>]*>)?\()')


def _enclosing_function(lines, idx):
    """(start, end, name) of the nearest function declaration at or above `idx`; start == end when none."""
    for i in range(idx, max(-1, idx - 80), -1):
        m = _FUNC_START_RE.match(lines[i])
        if m:
            name = next(g for g in m.groups() if g)
            end = min(len(lines), idx + 80)
            for j in range(idx + 1, end):
                if _FUNC_START_RE.match(lines[j]):
                    end = j
                    break
            return i, end, name
    return 0, 0, ""


def _hash_rules():
    out = []
    for ext, rx in _MD5_SHA1.items():
        skip = _HASH_OR_PWD_SKIP_RE if ext != ".rs" else re.compile(_HASH_OR_PWD_SKIP_RE.pattern + r'|' + _RUST_USE_RE.pattern, _I)
        out.append((
            "WCRYPTO-010", rx,
            "MD5/SHA-1 is cryptographically broken — use SHA-256+ for integrity; a password hash (argon2/bcrypt/scrypt) for credentials",
            Severity.MEDIUM, _WC, (ext,), skip, None,
        ))
        out.append((
            "WCRYPTO-011", _MD5_SHA1_PWD[ext],
            "MD5/SHA-1 is not a password hashing function — use argon2, bcrypt or scrypt",
            Severity.CRITICAL, _WC, (ext,), _HASH_BENIGN_RE, None,
        ))
    return out


def _no_crypto_rand_go(content: str) -> bool:
    return '"math/rand' in content and '"crypto/rand"' not in content


def _rust_non_os_rng(content: str) -> bool:
    return not re.search(r'\bOsRng\b|getrandom|from_entropy|ChaCha\w*Rng|\bStdRng\b', content)


_SECRET_NAME = (
    r'(?:token|secret|passw|nonce|salt|csrf|otp|api_?key|session_?(?:id|key|token)\w*'
    r'|(?:enc\w*|priv\w*|sign\w*|auth|crypto|aes|master|access|secret)_?key)'
)

_LANG_RULES = _hash_rules() + [
    # DES / 3DES / RC2 / RC4 cipher constructors
    (
        "WCRYPTO-012",
        re.compile(r'\b(?:des\.(?:NewCipher|NewTripleDESCipher)|rc4\.NewCipher)\s*\('),
        "DES/3DES/RC4 are broken ciphers — use AES-GCM (crypto/cipher)",
        Severity.HIGH, _WC, _GO, None, None,
    ),
    (
        "WCRYPTO-012",
        re.compile(r'OpenSSL::Cipher(?:::(?:DES|RC4|RC2|BF)\b|\.new\s*\(\s*["\'](?:des|rc4|rc2|bf|arcfour)[-\w]*["\'])', _I),
        "DES/RC4/RC2/Blowfish are broken or obsolete ciphers — use aes-256-gcm",
        Severity.HIGH, _WC, _RB, None, None,
    ),
    (
        "WCRYPTO-012",
        re.compile(
            r'\b(?:DES|TripleDES|RC2)(?:CryptoServiceProvider|Cng)?\.Create\s*\('
            r'|\bnew\s+(?:DES|TripleDES|RC2)(?:CryptoServiceProvider|Cng)\s*\('
        ),
        "DES/3DES/RC2 are broken ciphers — use AES-GCM (System.Security.Cryptography.AesGcm)",
        Severity.HIGH, _WC, _CS, None, None,
    ),
    # ECB mode (Ruby; Java/Python/C# are covered by WCRYPTO-001)
    (
        "WCRYPTO-017",
        re.compile(r'OpenSSL::Cipher(?:\.new\s*\(\s*["\'][^"\']*ecb[^"\']*["\']|::\w+::ECB\b)', _I),
        "ECB cipher mode leaks plaintext patterns — use aes-256-gcm",
        Severity.HIGH, _WC, _RB, None, None,
    ),
    # Certificate validation disabled
    (
        "WCRYPTO-013",
        re.compile(r'\bInsecureSkipVerify\s*(?::|=)\s*true\b'),
        "TLS certificate verification disabled (InsecureSkipVerify) — connections can be intercepted; trust the right CA instead",
        Severity.HIGH, _WC, _GO, re.compile(r'#nosec|nolint:gosec|//\s*nosec', _I), None,  # gosec suppression with a stated reason
    ),
    (
        "WCRYPTO-013",
        re.compile(r'\bVERIFY_NONE\b'),
        "SSL verify_mode VERIFY_NONE disables certificate validation — use OpenSSL::SSL::VERIFY_PEER",
        Severity.HIGH, _WC, _RB, None, None,
    ),
    (
        "WCRYPTO-013",
        re.compile(r'\bdanger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)'),
        "TLS certificate/hostname verification disabled — remove danger_accept_invalid_* and trust the right CA instead",
        Severity.HIGH, _WC, _RS, None, None,
    ),
    (
        "WCRYPTO-013",
        re.compile(
            r'\bServerCertificate(?:Custom)?ValidationCallback\s*\+?=\s*'
            r'(?:\([^)]*\)|\w+|delegate\s*(?:\([^)]*\))?)\s*(?:=>\s*true\b|\{\s*return\s+true\s*;)'
            r'|\bDangerousAcceptAnyServerCertificateValidator\b'
        ),
        "TLS certificate validation callback accepts every certificate — validate the chain instead",
        Severity.HIGH, _WC, _CS, None, None,
    ),
    # Legacy TLS / SSL protocol versions
    (
        "WCRYPTO-014",
        re.compile(r'\bMinVersion\s*:\s*tls\.Version(?:SSL30|TLS10|TLS11)\b'),
        "Minimum TLS version below 1.2 allows protocol-downgrade attacks — set MinVersion to tls.VersionTLS12 or higher",
        Severity.MEDIUM, _WC, _GO, None, None,
    ),
    (
        "WCRYPTO-014",
        re.compile(
            r'\b(?:ssl_version|min_version)\s*=\s*(?::|["\'])?(?:SSLv2|SSLv3|TLSv1(?:_1)?\b|OpenSSL::SSL::(?:SSL3|TLS1|TLS1_1)_VERSION)',
            _I,
        ),
        "SSL/TLS protocol version below 1.2 is deprecated — use TLS 1.2 or higher",
        Severity.MEDIUM, _WC, _RB, None, None,
    ),
    (
        "WCRYPTO-014",
        re.compile(r'\bProtocol::(?:Sslv3|Tlsv10|Tlsv11)\b|\bVersion::TLS_1_[01]\b'),
        "SSL/TLS protocol version below 1.2 is deprecated — use TLS 1.2 or higher",
        Severity.MEDIUM, _WC, _RS, None, None,
    ),
    (
        "WCRYPTO-014",
        re.compile(r'\bSslProtocols\.(?:Ssl2|Ssl3|Tls|Tls11)\b|\bSecurityProtocolType\.(?:Ssl3|Tls|Tls11)\b'),
        "SSL/TLS protocol version below 1.2 is deprecated — use TLS 1.2+ (or SslProtocols.None to defer to the OS)",
        Severity.MEDIUM, _WC, _CS, None, None,
    ),
    # Non-cryptographic PRNG feeding a secret-looking name
    (
        "WCRYPTO-015",
        re.compile(
            r'\b\w*' + _SECRET_NAME + r'\w*\s*(?::=|=)[^\n]*\brand\.(?:Int|Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float32|Float64|Read|Perm)\s*\(',
            _I,
        ),
        "math/rand is predictable — use crypto/rand for tokens, keys, passwords and nonces",
        Severity.MEDIUM, _WC, _GO, None, _no_crypto_rand_go,
    ),
    (
        "WCRYPTO-015",
        re.compile(
            r'\b\w*' + _SECRET_NAME + r'\w*\s*=[^\n]*(?:(?<![\w.:@])(?:Kernel\.)?rand\b(?![\w:])|\bRandom\.(?:rand|new|bytes)\b)',
            _I,
        ),
        "Kernel#rand / Random are predictable — use SecureRandom for tokens, keys, passwords and nonces",
        Severity.MEDIUM, _WC, _RB, re.compile(r'Secure|OpenSSL::Random'), None,
    ),
    (
        "WCRYPTO-015",
        re.compile(
            r'\b\w*' + _SECRET_NAME + r'\w*\s*(?::[^=\n]+)?=[^\n]*(?:\bfastrand::|\bSmallRng\b|\boorandom::|\bXorShift\w*|\bPcg\d*\b)',
            _I,
        ),
        "Non-cryptographic PRNG feeding a secret — use rand::rngs::OsRng (or getrandom) for tokens, keys and nonces",
        Severity.MEDIUM, _WC, _RS, None, _rust_non_os_rng,
    ),
    (
        "WCRYPTO-016",
        re.compile(
            r'\b\w*' + _SECRET_NAME + r'\w*\s*(?::[^=\n]+)?=[^\n]*(?:\brng\.(?:gen|gen_range|random|fill|fill_bytes)\b|\bthread_rng\s*\(|\brand::random\b)',
            _I,
        ),
        "General-purpose rand RNG feeding a secret — prefer rand::rngs::OsRng for tokens, keys and nonces (low confidence)",
        Severity.LOW, _WC, _RS, None,
        lambda c: bool(re.search(r'\bthread_rng\b|\brand::random\b', c)) and _rust_non_os_rng(c),
    ),
    (
        "WCRYPTO-015",
        re.compile(
            r'\b\w*' + _SECRET_NAME + r'\w*\s*=[^;\n]*(?:\bnew\s+Random\s*\(|\b_?(?:random|rnd|rand)\.Next\w*\s*\(|\bRandom\.Shared\.Next)',
            _I,
        ),
        "System.Random is predictable — use RandomNumberGenerator for tokens, keys, passwords and nonces",
        Severity.MEDIUM, _WC, _CS, None, None,
    ),
]

_LANG_EXTS = (".go", ".rb", ".rs", ".cs")

_GO_FUNC_RE = re.compile(r'^func\s+(?:\([^)]*\)\s*)?(\w+)')
_GO_SECRET_FUNC_RE = re.compile(r'token|password|passwd|secret|nonce|session|apikey|salt|csrf', _I)
_GO_RAND_CALL_RE = re.compile(r'\brand\.(?:Int|Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float64|Read|Perm)\s*\(')

_RUST_FN_RE = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s')
_RUST_DEFAULT_HASHER_RE = re.compile(r'\bDefaultHasher::(?:new|default)\s*\(')
_RUST_SECRET_HASH_RE = re.compile(r'\b\w*(?:passw|secret|token|credential|api_?key)\w*(?:\.\w+\(\))*\.hash\s*\(', _I)


_PWNED_API_RE = re.compile(r"pwnedpasswords\.com|haveibeenpwned", re.IGNORECASE)


class WeakCryptoAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".php", ".java", ".js", ".ts",
        ".go", ".rb", ".rs", ".cs",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        is_lang = file_path.endswith(_LANG_EXTS)
        if not _GUARD.search(content) and not (is_lang and _LANG_GUARD.search(content)):
            return []

        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if exts is None or file_path.endswith(exts)
        ]
        if is_lang:
            applicable += [
                (rid, re_obj, desc, sev, vt, skip)
                for rid, re_obj, desc, sev, vt, exts, skip, pred in _LANG_RULES
                if file_path.endswith(exts) and (pred is None or pred(content))
            ]
        if not applicable:
            return []
        findings = self._scan_lines(file_path, content, repo_url, applicable, guard=None)
        if _PWNED_API_RE.search(content):
            # The Have I Been Pwned range API is queried with the SHA-1 prefix of the password:
            # the protocol fixes the algorithm and only 5 hex characters leave the server.
            findings = [f for f in findings if f.rule_id != "WCRYPTO-004"]
        if is_lang and any(f.rule_id == "WCRYPTO-013" for f in findings):
            self._demote_conditional_tls_opt_out(content, findings)
        if is_lang and any(f.rule_id == "WCRYPTO-010" for f in findings):
            findings = self._drop_benign_digest_context(content, findings, file_path)
        if file_path.endswith(".go"):
            findings += self._go_secret_function_prng(file_path, content, repo_url, findings)
        elif file_path.endswith(".rs"):
            findings += self._rust_default_hasher(file_path, content, repo_url)
            if findings:
                test_lines = rust_test_lines(content)
                findings = [f for f in findings if f.line_number not in test_lines]
        return findings

    @staticmethod
    def _demote_conditional_tls_opt_out(content: str, findings: list[Finding]) -> None:
        """`if options[:no_check_certificate]` / `ssl == 'force'`: a user-selected opt-out, not an always-on bypass."""
        lines = content.splitlines()
        for f in findings:
            if f.rule_id != "WCRYPTO-013" or f.severity != Severity.HIGH:
                continue
            window = lines[max(0, f.line_number - 4):f.line_number]
            if any(_CONDITIONAL_RE.search(l) for l in window):
                f.severity = Severity.LOW
                f.description += " (conditional opt-out: verify the default path keeps validation on)"

    @staticmethod
    def _drop_benign_digest_context(content: str, findings: list[Finding], file_path: str = "") -> list[Finding]:
        """WCRYPTO-010 context heuristic (MD5/SHA-1 in Go / Ruby / Rust / C#).

        1. A digest next to an ETag / checksum / cache key / HMAC marker is dropped (not a control).
        2. If the enclosing function (or +-6 lines when there is none) mentions a credential/auth word
           (password, secret, token, auth, session, sign, hmac, verify, credential, login, salt), or the
           file name does, severity stays MEDIUM.
        3. Otherwise, if the function name, the file name, or the 3 lines around the digest say it is an
           identity / integrity helper (hash, digest, checksum, etag, fingerprint, hashcode, cache key,
           content-md5, dedupe, id/key derivation), severity drops to LOW: still reported, but it is
           not a security control.
        """
        lines = content.splitlines()
        base = file_path.replace("\\", "/").rsplit("/", 1)[-1]
        kept = []
        for f in findings:
            if f.rule_id == "WCRYPTO-010":
                window = "\n".join(lines[max(0, f.line_number - 9):f.line_number + 4])
                if _HASH_BENIGN_RE.search(window):
                    continue
                start, end, name = _enclosing_function(lines, f.line_number - 1)
                body = "\n".join(lines[start:end])
                if start == end:
                    body = "\n".join(lines[max(0, f.line_number - 7):f.line_number + 6])
                if not _SENSITIVE_CTX_RE.search(body) and not _SENSITIVE_CTX_RE.search(base):
                    near = "\n".join(lines[max(0, f.line_number - 4):f.line_number + 3])
                    if _IDENTITY_CTX_RE.search(name) or _IDENTITY_CTX_RE.search(base) or _IDENTITY_NEAR_RE.search(near):
                        f.severity = Severity.LOW
                        f.description += " (identity/integrity use: no credential context in this function)"
            kept.append(f)
        return kept

    def _finding(self, file_path, lines, lineno, rule_id, desc, sev, repo_url) -> Finding:
        return Finding(
            vuln_type=_WC, severity=sev, file_path=file_path, line_number=lineno,
            line_content=lines[lineno - 1].strip(), description=desc, rule_id=rule_id,
            repo_url=repo_url, snippet=self._extract_snippet(lines, lineno),
        )

    def _go_secret_function_prng(self, file_path, content, repo_url, existing) -> list[Finding]:
        """math/rand calls inside a function whose name says it makes a token / password / secret."""
        if not _no_crypto_rand_go(content):
            return []
        done = {f.line_number for f in existing if f.rule_id == "WCRYPTO-015"}
        lines = content.splitlines()
        out: list[Finding] = []
        current = ""
        for lineno, line in enumerate(lines, 1):
            m = _GO_FUNC_RE.match(line)
            if m:
                current = m.group(1)
                continue
            if line.startswith("}"):
                current = ""
                continue
            if (current and lineno not in done and _GO_SECRET_FUNC_RE.search(current)
                    and not self._is_comment(line) and _GO_RAND_CALL_RE.search(line)):
                out.append(self._finding(
                    file_path, lines, lineno, "WCRYPTO-015",
                    "math/rand is predictable — use crypto/rand for tokens, keys, passwords and nonces",
                    Severity.MEDIUM, repo_url))
        return out

    def _rust_default_hasher(self, file_path, content, repo_url) -> list[Finding]:
        """DefaultHasher (SipHash, not a cryptographic or password hash) fed with a credential-named value."""
        if "DefaultHasher" not in content:
            return []
        lines = content.splitlines()
        out: list[Finding] = []
        for i, line in enumerate(lines):
            if self._is_comment(line) or not _RUST_DEFAULT_HASHER_RE.search(line):
                continue
            for j in range(i + 1, min(i + 10, len(lines))):
                if _RUST_FN_RE.match(lines[j]):
                    break
                if _RUST_SECRET_HASH_RE.search(lines[j]):
                    out.append(self._finding(
                        file_path, lines, i + 1, "WCRYPTO-018",
                        "DefaultHasher is not a cryptographic or password hash — use argon2/bcrypt for credentials",
                        Severity.MEDIUM, repo_url))
                    break
        return out
