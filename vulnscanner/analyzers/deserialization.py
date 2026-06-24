import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# PHP 7.0+ safe unserialize: second arg contains ['allowed_classes' => false]
# Confirmed FP in snipe-it: unserialize($x, ['allowed_classes' => false]) blocks object injection
_PHP_SAFE_UNSERIALIZE_RE = re.compile(
    r"unserialize\s*\([^,)]+,\s*\[.*'allowed_classes'\s*=>\s*false",
    re.IGNORECASE | re.DOTALL,
)

# Method-call/definition form of unserialize is a user-defined method, not PHP's built-in.
# Confirmed FP: bludit dbjson.class.php has private method named unserialize() wrapping json_decode().
_PHP_USER_UNSERIALIZE_RE = re.compile(
    r'(?:->\s*unserialize\s*\(|function\s+unserialize\s*\()',
    re.IGNORECASE,
)

# (rule_id, pattern, description, severity, extensions)
_RULES: list[tuple[str, str, str, Severity, tuple[str, ...]]] = [
    # ── Python (regex fallback for files the AST analyzer cannot parse) ────────
    (
        "DESER-001",
        r'\bpickle\.(?:loads?|Unpickler)\s*\(',
        "pickle deserialization - arbitrary code execution if data is attacker-controlled",
        Severity.CRITICAL,
        (".py",),
    ),
    (
        "DESER-002",
        r'\byaml\.(?:load|unsafe_load)\s*\(',
        "yaml.load() without SafeLoader - use yaml.safe_load() to prevent code execution",
        Severity.HIGH,
        (".py",),
    ),
    (
        "DESER-003",
        r'\bmarshal\.loads?\s*\(',
        "marshal deserialization - not safe against malicious data",
        Severity.CRITICAL,
        (".py",),
    ),
    # ── PHP ────────────────────────────────────────────────────────────────────
    (
        "DESER-004",
        r'\bunserialize\s*\(',
        "PHP unserialize() - object injection risk; prefer JSON for untrusted data",
        Severity.CRITICAL,
        (".php",),
    ),
    # ── Java ───────────────────────────────────────────────────────────────────
    (
        "DESER-005",
        r'\bObjectInputStream\b|\breadObject\s*\(\s*\)',
        "Java ObjectInputStream/readObject - deserialization of untrusted data leads to RCE",
        Severity.CRITICAL,
        (".java",),
    ),
    # ── Ruby ───────────────────────────────────────────────────────────────────
    (
        "DESER-006",
        r'\bMarshal\.(?:load|restore)\s*\(',
        "Ruby Marshal.load - arbitrary object creation from untrusted data",
        Severity.CRITICAL,
        (".rb",),
    ),
    (
        "DESER-007",
        r'\bYAML\.(?:unsafe_load|load)\s*\(',
        "Ruby YAML.load / YAML.unsafe_load - code execution risk with untrusted input",
        Severity.HIGH,
        (".rb",),
    ),
    # ── Node.js ────────────────────────────────────────────────────────────────
    (
        "DESER-008",
        r'require\s*\(\s*[\'"]node-serialize[\'"]',
        "node-serialize - known RCE vulnerability; replace with a safe alternative",
        Severity.CRITICAL,
        (".js", ".ts"),
    ),
]


class DeserializationAnalyzer(BaseAnalyzer):
    # Python is primarily handled by PythonASTAnalyzer (higher precision).
    # .py rules here serve as a fallback for files that cannot be AST-parsed.
    supported_extensions = (".py", ".php", ".java", ".rb", ".js", ".ts")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        # For Python files: mask string literal interiors so rule description
        # strings (e.g. "yaml.load() without SafeLoader...") don't match themselves.
        match_lines = (
            self._mask_python_strings(content).splitlines()
            if file_path.endswith(".py")
            else lines
        )

        for rule_id, pattern, description, severity, exts in _RULES:
            if not file_path.endswith(exts):
                continue
            for lineno, (line, mline) in enumerate(zip(lines, match_lines), start=1):
                if self._is_comment(line):
                    continue
                if not re.search(pattern, mline, re.IGNORECASE):
                    continue

                # DESER-004: skip PHP unserialize() with ['allowed_classes' => false]
                # This is the PHP 7.0+ safe form that prevents object injection.
                # Confirmed FP: snipe-it ActionlogsTransformer.php
                if rule_id == "DESER-004":
                    # Check current line and up to 3 following lines for the safe arg
                    window = "\n".join(lines[lineno - 1: lineno + 3])
                    if _PHP_SAFE_UNSERIALIZE_RE.search(window):
                        continue
                    # Skip method-call/definition forms: $this->unserialize() / function unserialize()
                    # These are user-defined methods, not PHP's built-in unserialize().
                    # Confirmed FP: bludit dbjson.class.php private method wrapping json_decode()
                    if _PHP_USER_UNSERIALIZE_RE.search(line):
                        continue

                findings.append(Finding(
                    vuln_type=VulnType.INSECURE_DESERIALIZATION,
                    severity=severity,
                    file_path=file_path,
                    line_number=lineno,
                    line_content=line.strip(),
                    description=description,
                    rule_id=rule_id,
                    repo_url=repo_url,
                    snippet=self._extract_snippet(lines, lineno),
                ))

        return findings
