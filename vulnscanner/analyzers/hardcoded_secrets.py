import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.file_context import rust_test_lines
from vulnscanner.models import Finding, Severity, VulnType

_HS = VulnType.HARDCODED_SECRET

# `'MAIL_PASSWORD='.$request->pw`: the `=` sits inside the literal, so the next quote closes the
# string and what follows it is code being concatenated, not a password value.
_CONCAT_AFTER_KEY_RE = re.compile(r'(?:password|passwd|pwd)\s*=\s*["\']\s*[.+]\s*[\w$(]', re.IGNORECASE)


def _is_concatenated_key(line: str) -> bool:
    return bool(_CONCAT_AFTER_KEY_RE.search(line))

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "SEC-001",
        re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "Hardcoded password literal",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-002",
        re.compile(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][A-Za-z0-9/+]{16,}["\']', re.IGNORECASE),
        "Hardcoded API key",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-003",
        re.compile(r'(?:secret_key|SECRET_KEY)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
        "Hardcoded secret key",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-004",
        # An access key ID is a standalone upper-case token; the same letters inside a base64 blob
        # (protobuf descriptors, embedded images) are not one.
        re.compile(r'(?<![A-Za-z0-9+/=_-])AKIA[0-9A-Z]{16}(?![A-Za-z0-9+/=_-])'),
        "AWS access key ID pattern detected",
        Severity.CRITICAL, _HS,
    ),
    (
        "SEC-005",
        re.compile(r'-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----', re.IGNORECASE),
        "Private key material in source code",
        Severity.CRITICAL, _HS,
    ),
    (
        "SEC-006",
        re.compile(r'(?:token|auth_token|access_token)\s*=\s*["\'][A-Za-z0-9._\-]{20,}["\']', re.IGNORECASE),
        "Hardcoded token value",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-007",
        re.compile(
            r'(?:connection_string|conn_str|DATABASE_URL)\s*=\s*["\'](?:postgres|mysql|mongodb|redis)://[^"\']+["\']',
            re.IGNORECASE,
        ),
        "Database connection string with embedded credentials",
        Severity.HIGH, _HS,
    ),
    (
        "SEC-008",
        re.compile(
            # JS/Python/Ruby: jwt.sign(payload, "secret") / jwt.encode(data, "key") / JWT.encode(data, "key")
            # PHP:            JWT::encode($data, "key")
            # Go:             token.SignedString([]byte("key"))
            r'(?:'
            r'(?:jwt\.(?:sign|encode)|JWT\.encode|JWT::encode)\s*\([^)\n]{0,200},\s*'
            r'|SignedString\s*\(\s*\[\]byte\s*\(\s*'
            r')'
            r'["\'][A-Za-z0-9._/+=!@#$%^&*()\-]{6,}["\']',
            re.IGNORECASE,
        ),
        "Hardcoded JWT signing secret passed directly to library — use environment variable or secrets manager",
        Severity.CRITICAL, _HS,
    ),
    # SEC-009: GCP / service-account private key embedded in source or config.
    # Four sub-patterns are compiled separately and all share the same rule_id, description, severity.
    #
    # Pattern A — Standard quoted JSON / Python dict:
    #   "private_key": "-----BEGIN RSA PRIVATE KEY-----"
    #   'private_key': '-----BEGIN PRIVATE KEY-----'
    (
        "SEC-009",
        re.compile(
            r'(?P<keyquote>["\'])private_key(?P=keyquote)\s*:\s*'
            r'(?P<valquote>["\'])-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----',
            re.IGNORECASE,
        ),
        "Hardcoded GCP/service-account private key embedded in source code or config — rotate credential immediately",
        Severity.CRITICAL, _HS,
    ),
    # Pattern B — Escaped JSON embedded inside a source string (e.g. a Go/Java string literal):
    #   \"private_key\":\"-----BEGIN PRIVATE KEY-----
    (
        "SEC-009",
        re.compile(
            r'\\["\']private_key\\["\']\s*:\s*'
            r'\\["\']-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----',
            re.IGNORECASE,
        ),
        "Hardcoded GCP/service-account private key embedded in source code or config — rotate credential immediately",
        Severity.CRITICAL, _HS,
    ),
    # Pattern C — Unquoted JS/TS/Python object key (word-boundary guarded):
    #   private_key: "-----BEGIN PRIVATE KEY-----"
    #   private_key: '-----BEGIN RSA PRIVATE KEY-----'
    (
        "SEC-009",
        re.compile(
            r'\bprivate_key\s*:\s*'
            r'["\']-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----',
            re.IGNORECASE,
        ),
        "Hardcoded GCP/service-account private key embedded in source code or config — rotate credential immediately",
        Severity.CRITICAL, _HS,
    ),
    # Pattern D — YAML block scalar (multiline-aware, up to 200 chars lookahead):
    #   private_key: |
    #     -----BEGIN PRIVATE KEY-----
    # Uses re.DOTALL so . matches newlines within the lookahead window.
    (
        "SEC-009",
        re.compile(
            r'\bprivate_key\s*:\s*[|>][+\-]?\s{0,10}[\r\n]'
            r'(?:[ \t]*[^\r\n]*[\r\n]){0,5}'
            r'[ \t]*-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----',
            re.IGNORECASE | re.MULTILINE,
        ),
        "Hardcoded GCP/service-account private key embedded in source code or config (YAML block scalar) — rotate credential immediately",
        Severity.CRITICAL, _HS,
    ),
    # SEC-010: Hardcoded VCS personal access tokens.
    #
    # GitHub classic PATs start with ghp_ followed by exactly 36 alphanumeric chars.
    # GitHub fine-grained PATs start with github_pat_ followed by 82+ alphanumeric/underscore chars.
    # GitLab PATs start with glpat- followed by exactly 20 alphanumeric/hyphen chars.
    #
    # These token formats are well-documented by the vendors and have a very low false-positive
    # rate because the prefix anchors are unique and the body length constraints are tight.
    # Real-world impact: thousands of leaked GitHub/GitLab tokens on public repos (e.g. Truffle
    # Security research, GitGuardian reports), enabling full repo/org takeover.
    (
        "SEC-010",
        re.compile(
            r'\b(?:'
            r'ghp_[A-Za-z0-9]{36}'            # GitHub classic PAT
            r'|github_pat_[A-Za-z0-9_]{82,}'  # GitHub fine-grained PAT
            r'|glpat-[A-Za-z0-9\-]{20}'       # GitLab PAT
            r')\b',
            re.IGNORECASE,
        ),
        "Hardcoded VCS personal access token (GitHub/GitLab PAT) detected — revoke and rotate immediately",
        Severity.CRITICAL, _HS,
    ),
    # SEC-011: Slack API tokens.
    # Bot tokens (xoxb-), user tokens (xoxp-), workspace app tokens (xoxa-), and
    # legacy tokens (xoxs-). Format: xox{type}-{team_id}-{token_id}-{secret}.
    # A leaked bot token gives full access to all channels the bot is in.
    (
        "SEC-011",
        re.compile(
            r'\bxox[bpsa]-\d{8,13}-\d{8,13}-[A-Za-z0-9]{16,}\b',
            re.IGNORECASE,
        ),
        "Hardcoded Slack API token detected — revoke at api.slack.com/apps and rotate immediately",
        Severity.CRITICAL, _HS,
    ),
    # SEC-012: Stripe secret and restricted keys.
    # sk_live_ = full secret key (can charge cards, issue refunds).
    # rk_live_ = restricted key (scoped permissions, but still sensitive).
    # sk_test_ is also flagged at HIGH since test keys often share structure with live.
    (
        "SEC-012",
        re.compile(
            r'\b(?:sk_live_|rk_live_)[A-Za-z0-9]{20,}\b',
            re.IGNORECASE,
        ),
        "Hardcoded Stripe live secret key — immediate revocation required (financial data at risk)",
        Severity.CRITICAL, _HS,
    ),
    (
        "SEC-012",
        re.compile(
            r'\bsk_test_[A-Za-z0-9]{20,}\b',
            re.IGNORECASE,
        ),
        "Hardcoded Stripe test secret key — rotate before production deployment",
        Severity.HIGH, _HS,
    ),
    # SEC-013: SendGrid API keys.
    # Format: SG. followed by 22 base64url chars, a dot, then 43 base64url chars.
    # A leaked key allows sending email as the account owner (phishing risk).
    (
        "SEC-013",
        re.compile(
            r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b',
        ),
        "Hardcoded SendGrid API key detected — revoke at app.sendgrid.com/settings/api_keys",
        Severity.CRITICAL, _HS,
    ),
    # SEC-014: npm access tokens.
    # Format: npm_ followed by 36 alphanumeric chars (introduced 2021).
    # A leaked publish token enables supply-chain attacks via malicious package versions.
    (
        "SEC-014",
        re.compile(
            r'\bnpm_[A-Za-z0-9]{36}\b',
        ),
        "Hardcoded npm access token — revoke at npmjs.com/settings/tokens (supply-chain attack risk)",
        Severity.CRITICAL, _HS,
    ),
]

# Merged allowlist: a single compiled OR pattern replaces three separate re.search calls.
_ALLOWLIST_RE = re.compile(
    r'example|sample|placeholder|your[_-]|<[^>]+>|\*{3,}|xxx|dummy|fake'
    r'|#.*(?:password|secret|key|token)'
    r'|^\s*//',
    re.IGNORECASE,
)

# Content-level guard: skip files that contain none of the relevant keywords.
_GUARD = re.compile(
    r'password|passwd|pwd|api[_-]?key|api[_-]?secret|secret[_-]?key|SECRET_KEY'
    r'|AKIA[0-9A-Z]|PRIVATE KEY|token|auth_token|access_token'
    r'|connection_string|conn_str|DATABASE_URL'
    r'|jwt\.(?:sign|encode)|JWT\.encode|JWT::encode|SignedString'
    r'|private_key'
    r'|ghp_|github_pat_|glpat-'
    r'|xox[bpsa]-'
    r'|sk_live_|rk_live_|sk_test_'
    r'|SG\.[A-Za-z0-9_-]{10}'
    r'|npm_|credential|secret_key_base|_KEY\b|\bKEY\b',
    re.IGNORECASE,
)


# `const PASSWORD = 'password';` / `case PASSWORD = 'password';` — a constant or enum case
# whose value is a lowercase label naming the field, not a credential.
_CONST_DECL_RE = re.compile(r'\b(?:const|case)\b|^\s*(?:[A-Za-z_]+\s+)*[A-Z][A-Z0-9_]{2,}\s*=')
_LABEL_VALUE_RE = re.compile(
    r'(?:password|passwd|pwd)\s*=\s*["\']([a-z]+(?:[-_./][a-z0-9]+)*)["\']', re.IGNORECASE
)
_LABEL_WORD_RE = re.compile(r'password|passwd|pwd')


# `var msg = '{{ trans('x') }}'`: the "password" is a rendered template expression, not a literal.
_TEMPLATE_VALUE_RE = re.compile(
    r"""(?:password|passwd|pwd)\w*\s*=\s*["'](?:\{\{|\{%|<\?|<%|\$\{)""", re.IGNORECASE)


def _is_password_label(line: str) -> bool:
    """True for constant declarations whose value is a slug that names the field itself."""
    m = _LABEL_VALUE_RE.search(line)
    if not m:
        return False
    value = m.group(1)
    if value != value.lower():
        return False
    # `tmplResetPassword = "auth/reset_passwd"`: a template / route path is never a credential,
    # whatever the declaration looks like (Go const blocks have no `const` on the line).
    if "/" in value:
        return True
    return bool(_CONST_DECL_RE.search(line)) and bool(_LABEL_WORD_RE.search(value))


# `FieldNamePassword = "password"` / `MFAMethodPassword = "password"`: the right side is only the
# word that names the field (an identifier / enum value), whatever the left side looks like.
_ANY_PASSWORD_VALUE_RE = re.compile(
    r'(?:password|passwd|pwd)\w*\s*(?::[^=]*)?=\s*["\']([^"\']{4,})["\']', re.IGNORECASE)
_NAME_WORD_VALUES = frozenset({
    "password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "secretkey", "authtoken",
})


def _is_name_word_value(line: str) -> bool:
    m = _ANY_PASSWORD_VALUE_RE.search(line)
    if not m:
        return False
    return re.sub(r"[-_.\s]", "", m.group(1)).lower() in _NAME_WORD_VALUES


# SEC-015 / SEC-016: credential constants in Go, Rust, C# and Ruby, whose declaration syntax the
# generic `password = "..."` rules above do not cover (`const X: &str = "..."`, `private const string X = "..."`).
_CRED_NAME = (
    r'(?P<name>\w*(?:secret|passw(?:or)?d|pwd|passphrase|api_?key|apikey|token|credential'
    r'|(?:private|signing|encryption|auth|access|master|jwt|crypto|aes|hmac)_?key)s?)'
)
_CRED_VALUE = r'"(?P<val>[^"\\]{6,})"'
_LANG_SECRET_RULES = [
    (  # Go: `const jwtSecret = "..."` / `var apiKey string = "..."` / a bare line inside a const block
        re.compile(r'^\s*(?:(?:const|var)\s+)?' + _CRED_NAME + r'\s*(?:string\s*)?=\s*' + _CRED_VALUE + r'\s*$', re.IGNORECASE),
        (".go",),
    ),
    (  # Rust: `const JWT_SECRET: &str = "...";`
        re.compile(
            r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+(?P<name>\w*(?:SECRET|PASSW(?:OR)?D|PWD|PASSPHRASE|API_?KEY|TOKEN|CREDENTIAL|_KEY)S?|KEY)'
            r'\s*:\s*&(?:\'static\s+)?str\s*=\s*' + _CRED_VALUE + r'\s*;',
            re.IGNORECASE,
        ),
        (".rs",),
    ),
    (  # C#: `private const string ApiSecret = "...";`
        re.compile(
            r'^\s*(?:(?:public|private|protected|internal|static|readonly|const)\s+)+string\s+' + _CRED_NAME +
            r'\s*=\s*' + _CRED_VALUE + r'\s*;',
            re.IGNORECASE,
        ),
        (".cs",),
    ),
    (  # Ruby: `SECRET = "..."` / `KEY = "..."` upper-case constants
        re.compile(r"^\s*(?P<name>[A-Z][A-Z0-9_]*(?:SECRET|PASSW(?:OR)?D|PWD|PASSPHRASE|API_?KEY|TOKEN|CREDENTIAL|_KEY)S?|KEY)\s*=\s*['\"](?P<val>[^'\"\\]{6,})['\"]"),
        (".rb",),
    ),
]
_RAILS_SECRET_BASE_RE = re.compile(r"""\bsecret_key_base\s*=\s*["'](?P<val>[A-Za-z0-9]{20,})["']""")
_SLUG_LABEL_RE = re.compile(r'[A-Za-z]+(?:[-_.:/ ][A-Za-z]+)*')
_ENV_NAME_RE = re.compile(r'[A-Z][A-Z0-9_]+')
_PLAIN_RE = re.compile(r'[A-Za-z0-9\-_.:/ ]*')
_LINE_ALREADY_REPORTED = ("SEC-001", "SEC-002", "SEC-003", "SEC-006")


def _credential_like_value(value: str) -> bool:
    """False for header names, route paths, URLs, env-var names and the field's own name; True for
    values with a digit or a symbol, which look like actual secrets."""
    if "://" in value or "{" in value or "%s" in value or "$" in value or value.startswith("/") or re.search(r"\s", value):
        return False
    if re.sub(r"[-_.\s]", "", value).lower() in _NAME_WORD_VALUES:
        return False
    if _SLUG_LABEL_RE.fullmatch(value) or _ENV_NAME_RE.fullmatch(value):
        return False
    return not _PLAIN_RE.fullmatch(value) or bool(re.search(r"\d", value))



_PLACEHOLDER_PAREN_RE = re.compile(r"(?:password|passwd|pwd)\s*=\s*[\"']\([^\"')]*\)[\"']", re.IGNORECASE)  # "(removed)", "(hidden)"
_EF_MIGRATION_RE = re.compile(r"(?:^|/)Migrations/")


def _python_docstring_lines(content: str) -> set[int]:
    """1-based line numbers covered by module / class / function docstrings."""
    import ast
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                lines.update(range(body[0].lineno, (body[0].end_lineno or body[0].lineno) + 1))
    return lines


# CI pipelines start a throw-away database or service next to the tests and pass it a placeholder
# password (`mysql --password="root"`, `POSTGRES_PASSWORD: postgres`): not a credential of anything real.
_CI_PATH_RE = re.compile(r"(?:^|/)(?:\.github/workflows/|\.gitlab-ci\.ya?ml$|\.circleci/|azure-pipelines\.ya?ml$|\.travis\.ya?ml$)")
_CI_THROWAWAY_PASSWORDS = frozenset({
    "root", "password", "passwd", "secret", "test", "testing", "postgres", "mysql", "admin", "changeme",
    "pass", "1234", "12345", "123456", "toor", "mariadb", "guest",
})
_PASSWORD_VALUE_RE = re.compile(r"""(?:password|passwd|pwd)\w*\s*[=:]\s*["']?([^"'\s]+)""", re.IGNORECASE)


def _is_ci_throwaway_password(file_path: str, line: str) -> bool:
    if not _CI_PATH_RE.search(file_path.replace("\\", "/")):
        return False
    m = _PASSWORD_VALUE_RE.search(line)
    value = m.group(1).lower() if m else ""
    return value in _CI_THROWAWAY_PASSWORDS


class HardcodedSecretsAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".js", ".ts", ".java", ".rb", ".php", ".go", ".rs", ".cs",
        ".env", ".yml", ".yaml", ".json", ".config", ".tf",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []

        if file_path.endswith(".cs") and _EF_MIGRATION_RE.search(file_path.replace("\\", "/")):
            return []  # generated EF Core migration / model snapshot: seed data repeated from the DbContext

        lines = content.splitlines()
        findings: list[Finding] = []

        # De-duplication: track (rule_id, lineno) pairs already emitted, and track
        # line numbers where SEC-009 fired so we can suppress SEC-005 on the same line.
        seen: set[tuple[str, int]] = set()
        sec009_lines: set[int] = set()

        # ------------------------------------------------------------------ #
        # Pass 1: Pattern D is multiline — run it against the full content     #
        # first so its line numbers can seed the sec009_lines suppression set. #
        # ------------------------------------------------------------------ #
        _pattern_d = _RULES[-2]  # second-to-last entry is Pattern D (SEC-009 YAML)
        rule_id_d, re_d, desc_d, sev_d, vt_d = _pattern_d
        for m in re_d.finditer(content):
            # Determine the starting line number of the match.
            lineno = content[: m.start()].count("\n") + 1
            key = (rule_id_d, lineno)
            if key in seen:
                continue
            if _ALLOWLIST_RE.search(m.group()):
                continue
            seen.add(key)
            sec009_lines.add(lineno)
            stripped = lines[lineno - 1].strip() if lineno <= len(lines) else m.group()[:120]
            findings.append(Finding(
                vuln_type=vt_d,
                severity=sev_d,
                file_path=file_path,
                line_number=lineno,
                line_content=stripped,
                description=desc_d,
                rule_id=rule_id_d,
                repo_url=repo_url,
                snippet=self._extract_snippet(lines, lineno),
            ))

        # ------------------------------------------------------------------ #
        # Pass 2: Line-by-line scan for all other rules (Patterns A-C of      #
        # SEC-009 plus SEC-001 through SEC-008 and SEC-010, excluding          #
        # Pattern D which is the second-to-last entry).                        #
        # ------------------------------------------------------------------ #
        rules_except_d = [r for r in _RULES if not (r[0] == "SEC-009" and r[1].flags & re.MULTILINE and r[1].pattern.startswith(r'\bprivate_key\s*:\s*[|>]'))]
        doc_lines = _python_docstring_lines(content) if file_path.endswith(".py") else set()
        if file_path.endswith(".rs"):
            doc_lines = rust_test_lines(content)  # #[cfg(test)] modules and #[test] fns hold sample values, not product secrets
        for lineno, line in enumerate(lines, 1):
            if self._is_comment(line) or lineno in doc_lines:
                continue
            stripped = line.strip()
            for rule_id, pattern_re, description, severity, vuln_type in rules_except_d:
                # De-duplication: suppress SEC-005 if SEC-009 already fired on this line.
                if rule_id == "SEC-005" and lineno in sec009_lines:
                    continue
                if not pattern_re.search(line):
                    continue
                if _ALLOWLIST_RE.search(line):
                    continue
                if rule_id == "SEC-001" and (_is_password_label(line) or _TEMPLATE_VALUE_RE.search(line)):
                    continue
                if rule_id == "SEC-001" and _is_name_word_value(line):
                    continue
                if rule_id == "SEC-001" and _PLACEHOLDER_PAREN_RE.search(line):
                    continue
                if rule_id == "SEC-001" and _is_concatenated_key(line):
                    continue
                if rule_id == "SEC-001" and _is_ci_throwaway_password(file_path, line):
                    continue
                key = (rule_id, lineno)
                if key in seen:
                    continue
                seen.add(key)
                # If any SEC-009 pattern fires, record the line for SEC-005 suppression.
                if rule_id == "SEC-009":
                    sec009_lines.add(lineno)
                findings.append(Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    file_path=file_path,
                    line_number=lineno,
                    line_content=stripped,
                    description=description,
                    rule_id=rule_id,
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, lineno),
                ))
            self._language_credentials(file_path, line, lineno, stripped, lines, seen, findings, repo_url)
        return findings

    def _language_credentials(self, file_path, line, lineno, stripped, lines, seen, findings, repo_url) -> None:
        """SEC-015 (credential constants) and SEC-016 (Rails secret_key_base) for Go, Rust, C# and Ruby."""
        if not file_path.endswith((".go", ".rs", ".cs", ".rb")):
            return
        if _ALLOWLIST_RE.search(line) or any((r, lineno) in seen for r in _LINE_ALREADY_REPORTED):
            return
        if file_path.endswith(".rb"):
            m = _RAILS_SECRET_BASE_RE.search(line)
            if m:
                seen.add(("SEC-016", lineno))
                findings.append(Finding(
                    vuln_type=_HS, severity=Severity.HIGH, file_path=file_path, line_number=lineno,
                    line_content=stripped, rule_id="SEC-016", repo_url=repo_url,
                    description="Hardcoded Rails secret_key_base — session cookies and signed data can be forged; load it from credentials or ENV",
                    snippet=self._extract_snippet(lines, lineno),
                ))
                return
        for rx, exts in _LANG_SECRET_RULES:
            if not file_path.endswith(exts):
                continue
            m = rx.search(line)
            if not m or not _credential_like_value(m.group("val")):
                continue
            if ("SEC-015", lineno) in seen:
                return
            seen.add(("SEC-015", lineno))
            findings.append(Finding(
                vuln_type=_HS, severity=Severity.HIGH, file_path=file_path, line_number=lineno,
                line_content=stripped, rule_id="SEC-015", repo_url=repo_url,
                description=f"Hardcoded credential constant '{m.group('name')}' — load it from the environment or a secrets manager",
                snippet=self._extract_snippet(lines, lineno),
            ))
            return
