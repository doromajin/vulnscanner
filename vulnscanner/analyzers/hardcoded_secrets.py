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
    r'|private_key',
    re.IGNORECASE,
)


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
        _pattern_d = _RULES[-1]  # last entry is Pattern D
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
        # SEC-009 plus SEC-001 through SEC-008, excluding Pattern D).         #
        # ------------------------------------------------------------------ #
        rules_except_d = _RULES[:-1]
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
