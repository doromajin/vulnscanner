import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# (rule_id, pattern, description, severity, extensions)
_RULES: list[tuple[str, str, str, Severity, tuple[str, ...]]] = [
    # ── PHP ────────────────────────────────────────────────────────────────────
    (
        "SSRF-001",
        r'curl_setopt\s*\(.*CURLOPT_URL.*\$_(?:GET|POST|REQUEST|COOKIE)',
        "PHP cURL with user-controlled URL — SSRF allows requests to internal services",
        Severity.HIGH,
        (".php",),
    ),
    (
        "SSRF-002",
        r'file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)',
        "PHP file_get_contents with user URL — SSRF / path traversal risk",
        Severity.HIGH,
        (".php",),
    ),
    # ── Java ───────────────────────────────────────────────────────────────────
    (
        "SSRF-003",
        r'new\s+URL\s*\(\s*(?![\'"]\s*[\'"]\s*\))',
        "Java URL instantiation with non-literal — verify URL cannot be user-controlled",
        Severity.MEDIUM,
        (".java",),
    ),
    (
        "SSRF-004",
        r'(?:HttpURLConnection|CloseableHttpClient|HttpClient).*(?:getParameter|getAttribute)',
        "Java HTTP client using request parameter as URL — SSRF risk",
        Severity.HIGH,
        (".java",),
    ),
    # ── Node.js / TypeScript ───────────────────────────────────────────────────
    (
        "SSRF-005",
        r'(?:fetch|axios\.(?:get|post|put|patch|delete|request)|(?:http|https)\.(?:get|request))\s*\(\s*req\.(?:query|body|params)',
        "Node.js HTTP request with user-controlled URL — SSRF risk",
        Severity.HIGH,
        (".js", ".ts"),
    ),
    (
        "SSRF-006",
        r'(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*`[^`]*\$\{req\.',
        "Node.js HTTP request with URL template containing request data — SSRF risk",
        Severity.HIGH,
        (".js", ".ts"),
    ),
    # ── Ruby ───────────────────────────────────────────────────────────────────
    (
        "SSRF-007",
        r'(?:Net::HTTP\.get|open-uri|URI\.open|RestClient\.(?:get|post))\s*\(\s*params\[',
        "Ruby HTTP request with user-supplied URL — SSRF risk",
        Severity.HIGH,
        (".rb",),
    ),
    # ── Go ─────────────────────────────────────────────────────────────────────
    (
        "SSRF-008",
        r'http\.(?:Get|Post|NewRequest)\s*\(\s*(?:r\.(?:FormValue|URL|Header)|fmt\.Sprintf)',
        "Go HTTP request with dynamic URL — verify URL cannot be user-controlled",
        Severity.MEDIUM,
        (".go",),
    ),
]


class SSRFAnalyzer(BaseAnalyzer):
    # Python SSRF is handled by PythonASTAnalyzer with taint-aware detection.
    supported_extensions = (".php", ".java", ".js", ".ts", ".rb", ".go")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule_id, pattern, description, severity, exts in _RULES:
            if not file_path.endswith(exts):
                continue
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        vuln_type=VulnType.SSRF,
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
