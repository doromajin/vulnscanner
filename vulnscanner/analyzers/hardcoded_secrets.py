import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_HS = VulnType.HARDCODED_SECRET

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
        re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
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
    r'|npm_',
    re.IGNORECASE,
)


# `const PASSWORD = 'password';` / `case PASSWORD = 'password';` — a constant or enum case
# whose value is a lowercase label naming the field, not a credential.
_CONST_DECL_RE = re.compile(r'\b(?:const|case)\b|^\s*(?:[A-Za-z_]+\s+)*[A-Z][A-Z0-9_]{2,}\s*=')
_LABEL_VALUE_RE = re.compile(
    r'(?:password|passwd|pwd)\s*=\s*["\']([a-z]+(?:[-_.][a-z0-9]+)*)["\']', re.IGNORECASE
)
_LABEL_WORD_RE = re.compile(r'password|passwd|pwd')


def _is_password_label(line: str) -> bool:
    """True for constant declarations whose value is a slug that names the field itself."""
    if not _CONST_DECL_RE.search(line):
        return False
    m = _LABEL_VALUE_RE.search(line)
    if not m:
        return False
    value = m.group(1)
    return value == value.lower() and bool(_LABEL_WORD_RE.search(value))


class HardcodedSecretsAnalyzer(BaseAnalyzer):
    supported_extensions = (
        ".py", ".js", ".ts", ".java", ".rb", ".php", ".go",
        ".env", ".yml", ".yaml", ".json", ".config", ".tf",
    )

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []

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
        for lineno, line in enumerate(lines, 1):
            if self._is_comment(line):
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
                if rule_id == "SEC-001" and _is_password_label(line):
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
        return findings
