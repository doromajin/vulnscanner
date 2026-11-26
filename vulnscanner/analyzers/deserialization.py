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
    r'(?:(?:->|::)\s*unserialize\s*\(|function\s+unserialize\s*\()',
    re.IGNORECASE,
)

# Java XMLDecoder: exact class name match (case-sensitive — XMLDecoder is a Java class).
# Used to deserialize XML into Java objects; equivalent in danger to ObjectInputStream.
# CVE-2017-10271: Oracle WebLogic XMLDecoder RCE via crafted XML payload.
_JAVA_XMLDECODER_RE = re.compile(r'\bXMLDecoder\b')

# (rule_id, compiled_re, description, severity, vuln_type, exts)
_RULES = [
    # ── Python: only used as fallback for files the AST analyzer cannot parse.
    # For parseable .py files, PythonASTAnalyzer provides taint-aware detection (AST-DESER-*)
    # which suppresses findings when the argument is provably clean.
    (
        "DESER-001",
        re.compile(r'\bpickle\.(?:loads?|Unpickler)\s*\(', re.IGNORECASE),
        "pickle deserialization - arbitrary code execution if data is attacker-controlled",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (),
    ),
    (
        "DESER-002",
        re.compile(r'\byaml\.(?:load|unsafe_load)\s*\(', re.IGNORECASE),
        "yaml.load() without SafeLoader - use yaml.safe_load() to prevent code execution",
        Severity.HIGH, VulnType.INSECURE_DESERIALIZATION, (),
    ),
    (
        "DESER-003",
        re.compile(r'\bmarshal\.loads?\s*\(', re.IGNORECASE),
        "marshal deserialization - not safe against malicious data",
        Severity.CRITICAL, VulnType.INSECURE_DESERIALIZATION, (),
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
        "DESER-009",
        re.compile(r'\bfromXML\s*\(', re.IGNORECASE),
        "Java XStream.fromXML() - deserialization of untrusted XML can lead to RCE (CVE-2021-29505, CVE-2020-26217); use XStream security framework or a safe alternative",
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



# Anything in the file that reads data from the HTTP request.
_PHP_REQUEST_INPUT_RE = re.compile(
    r"\$_(?:GET|POST|COOKIE|REQUEST|FILES|SERVER)\b|\$request\b|\brequest\s*\(|\bRequest::|\bInput::"
    r"|php://input|getContent\s*\(|\$this->input\b"
)


# Java: a deserialization stream that is already restricted.  A subclass of ObjectInputStream whose
# resolveClass() rejects classes (allow/deny list), ValidatingObjectInputStream or an ObjectInputFilter
# make DESER-005 (generic ObjectInputStream/readObject) a false positive.
_JAVA_OIS_FILTER_RE = re.compile(
    r"\bValidatingObjectInputStream\b|\bsetObjectInputFilter\b|\bObjectInputFilter\s*\.\s*Config\b"
    r"|\bcreateFilter\s*\(|\bsetSerialFilter\b")
_JAVA_OIS_SUBCLASS_RE = re.compile(r"\bclass\s+\w+\s+extends\s+\w*ObjectInputStream\b")
_JAVA_RESOLVE_REJECT_RE = re.compile(r"resolveClass\s*\([^)]*\)[^{]*\{(?:(?!\n\s*\}\s*\n\s*(?:public|protected|private)).)*?"
                                     r"(?:InvalidClassException|throw\s+new)", re.DOTALL)
_JAVA_CUSTOM_OIS_NEW_RE = re.compile(r"\bnew\s+(\w+ObjectInputStream)\s*\(")
_ois_checked: dict = {}


def _java_ois_restricted(file_path: str, content: str) -> bool:
    if _JAVA_OIS_FILTER_RE.search(content):
        return True
    if _JAVA_OIS_SUBCLASS_RE.search(content) and _JAVA_RESOLVE_REJECT_RE.search(content):
        return True
    names = {n for n in _JAVA_CUSTOM_OIS_NEW_RE.findall(content)
             if n not in ("ObjectInputStream", "SmartObjectInputStream")}
    if not names:
        return False
    norm = file_path.replace("\\", "/")
    idx = norm.find("/src/")
    if idx < 0:
        return False
    root = norm[:idx + 5]
    for n in names:
        key = (root, n)
        if key not in _ois_checked:
            ok = False
            try:
                from pathlib import Path as _P
                for cand in list(_P(root).rglob(n + ".java"))[:3]:
                    txt = cand.read_text(encoding="utf-8", errors="ignore")
                    if _JAVA_OIS_SUBCLASS_RE.search(txt) and _JAVA_RESOLVE_REJECT_RE.search(txt):
                        ok = True
                        break
            except Exception:
                ok = False
            _ois_checked[key] = ok
        if _ois_checked[key]:
            return True
    return False


def _is_migration_path(path: str) -> bool:
    parts = path.replace("\\", "/").lower().split("/")
    return "migrations" in parts[:-1] and path.endswith(".php")


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

                if rule_id == "DESER-005" and _java_ois_restricted(file_path, content):
                    continue

                if rule_id == "DESER-004" and _is_migration_path(file_path):
                    severity = Severity.LOW
                    description += " [low_reach: one-off schema migration reading the application's own database]"
                elif (rule_id == "DESER-004" and file_path.endswith(".php")
                        and severity in (Severity.CRITICAL, Severity.HIGH)
                        and not _PHP_REQUEST_INPUT_RE.search(content)):
                    severity = Severity.MEDIUM
                    description += " [needs_review: no request input is read in this file — check where the data comes from]"
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
