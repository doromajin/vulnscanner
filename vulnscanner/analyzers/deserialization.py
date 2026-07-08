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

# Java XMLDecoder: exact class name match (case-sensitive — XMLDecoder is a Java class).
# Used to deserialize XML into Java objects; equivalent in danger to ObjectInputStream.
# CVE-2017-10271: Oracle WebLogic XMLDecoder RCE via crafted XML payload.
_JAVA_XMLDECODER_RE = re.compile(r'\bXMLDecoder\b')

# (rule_id, compiled_re, description, severity, vuln_type, exts)
_RULES = [
    # ── Python (regex fallback for files the AST analyzer cannot parse) ────────
    (
        "DESER-001",
        re.compile(r'\bpickle\.(?:loads?|Unpickler)\s*\(', re.IGNORECASE),
        "pickle deserialization - arbitrary code execution if data is attacker-controlled",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (".py",),
    ),
    (
        "DESER-002",
        re.compile(r'\byaml\.(?:load|unsafe_load)\s*\(', re.IGNORECASE),
        "yaml.load() without SafeLoader - use yaml.safe_load() to prevent code execution",
        Severity.HIGH, VulnType.INSECURE_DESERIALIZATION, (".py",),
    ),
    (
        "DESER-003",
        re.compile(r'\bmarshal\.loads?\s*\(', re.IGNORECASE),
        "marshal deserialization - not safe against malicious data",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (".py",),
    ),
    # ── PHP ────────────────────────────────────────────────────────────────────
    (
        "DESER-004",
        re.compile(r'\bunserialize\s*\(', re.IGNORECASE),
        "PHP unserialize() - object injection risk; prefer JSON for untrusted data",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (".php",),
    ),
    # ── Java ───────────────────────────────────────────────────────────────────
    (
        "DESER-005",
        re.compile(r'\bObjectInputStream\b|\breadObject\s*\(\s*\)', re.IGNORECASE),
        "Java ObjectInputStream/readObject - deserialization of untrusted data leads to RCE",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (".java",),
    ),
    (
        "DESER-010",
        _JAVA_XMLDECODER_RE,
        "Java XMLDecoder - XML deserialization allows arbitrary object instantiation and RCE (CVE-2017-10271)",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (".java",),
    ),
    # ── Ruby ───────────────────────────────────────────────────────────────────
    (
        "DESER-006",
        re.compile(r'\bMarshal\.(?:load|restore)\s*\(', re.IGNORECASE),
        "Ruby Marshal.load - arbitrary object creation from untrusted data",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (".rb",),
    ),
    (
        "DESER-007",
        re.compile(r'\bYAML\.(?:unsafe_load|load)\s*\(', re.IGNORECASE),
        "Ruby YAML.load / YAML.unsafe_load - code execution risk with untrusted input",
        Severity.HIGH, VulnType.INSECURE_DESERIALIZATION, (".rb",),
    ),
    # ── Node.js ────────────────────────────────────────────────────────────────
    (
        "DESER-008",
        re.compile(r'require\s*\(\s*[\'"]node-serialize[\'"]', re.IGNORECASE),
        "node-serialize - known RCE vulnerability; replace with a safe alternative",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (".js", ".ts"),
    ),
]

_GUARD = re.compile(
    r'pickle\.|yaml\.(?:load|unsafe_load)|marshal\.load|unserialize\s*\('
    r'|ObjectInputStream|readObject\s*\(|Marshal\.(?:load|restore)|YAML\.(?:load|unsafe_load)'
    r'|node-serialize|XMLDecoder',
    re.IGNORECASE,
)

# Separate guard for XMLDecoder that is case-sensitive (class name must match exactly)
_XMLDECODER_GUARD = re.compile(r'\bXMLDecoder\b')


class DeserializationAnalyzer(BaseAnalyzer):
    # Python is primarily handled by PythonASTAnalyzer (higher precision).
    # .py rules here serve as a fallback for files that cannot be AST-parsed.
    supported_extensions = (".py", ".php", ".java", ".rb", ".js", ".ts")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            # Also check case-sensitive XMLDecoder guard for Java files
            if file_path.endswith(".java") and not _XMLDECODER_GUARD.search(content):
                return []
            elif not file_path.endswith(".java"):
                return []

        # Filter rules to those applicable to this file extension
        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if file_path.endswith(exts)
        ]
        if not applicable:
            return []

        lines = content.splitlines()
        # For Python files: mask string literal interiors so rule description
        # strings (e.g. "yaml.load() without SafeLoader...") don't match themselves.
        match_lines = (
            self._mask_python_strings(content).splitlines()
            if file_path.endswith(".py")
            else lines
        )

        findings: list[Finding] = []
        # Single pass: outer loop over lines, inner loop over applicable rules.
        for lineno, (line, mline) in enumerate(zip(lines, match_lines), start=1):
            if self._is_comment(line):
                continue
            stripped = line.strip()
            for rule_id, pattern_re, description, severity, vuln_type in applicable:
                if not pattern_re.search(mline):
                    continue

                # DESER-004: skip PHP unserialize() with ['allowed_classes' => false]
                # This is the PHP 7.0+ safe form that prevents object injection.
                # Confirmed FP: snipe-it ActionlogsTransformer.php
                if rule_id == "DESER-004":
                    window = "\n".join(lines[lineno - 1: lineno + 3])
                    if _PHP_SAFE_UNSERIALIZE_RE.search(window):
                        continue
                    # Skip method-call/definition forms: $this->unserialize() / function unserialize()
                    # Confirmed FP: bludit dbjson.class.php private method wrapping json_decode()
                    if _PHP_USER_UNSERIALIZE_RE.search(line):
                        continue

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
