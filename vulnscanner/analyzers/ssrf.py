import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_SR = VulnType.SSRF

# (rule_id, compiled_re, description, severity, vuln_type, exts)
_RULES = [
    (
        "SSRF-001",
        re.compile(r'curl_setopt\s*\(.*CURLOPT_URL.*\$_(?:GET|POST|REQUEST|COOKIE)', re.IGNORECASE),
        "PHP cURL with user-controlled URL - SSRF allows requests to internal services",
        Severity.HIGH, _SR, (".php",),
    ),
    (
        "SSRF-002",
        re.compile(r'file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)', re.IGNORECASE),
        "PHP file_get_contents with user URL - SSRF / path traversal risk",
        Severity.HIGH, _SR, (".php",),
    ),
    (
        "SSRF-003",
        re.compile(r'new\s+URL\s*\(\s*(?![\'"]\s*[\'"]\s*\))', re.IGNORECASE),
        "Java URL instantiation with non-literal - verify URL cannot be user-controlled",
        Severity.MEDIUM, _SR, (".java",),
    ),
    (
        "SSRF-004",
        re.compile(r'(?:HttpURLConnection|CloseableHttpClient|HttpClient).*(?:getParameter|getAttribute)', re.IGNORECASE),
        "Java HTTP client using request parameter as URL - SSRF risk",
        Severity.HIGH, _SR, (".java",),
    ),
    (
        "SSRF-005",
        re.compile(
            r'(?:fetch|axios\.(?:get|post|put|patch|delete|request)|(?:http|https)\.(?:get|request))\s*\(\s*req\.(?:query|body|params)',
            re.IGNORECASE,
        ),
        "Node.js HTTP request with user-controlled URL - SSRF risk",
        Severity.HIGH, _SR, (".js", ".ts"),
    ),
    (
        "SSRF-006",
        re.compile(
            r'(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*`[^`]*\$\{req\.',
            re.IGNORECASE,
        ),
        "Node.js HTTP request with URL template containing request data - SSRF risk",
        Severity.HIGH, _SR, (".js", ".ts"),
    ),
    (
        "SSRF-007",
        re.compile(r'(?:Net::HTTP\.get|open-uri|URI\.open|RestClient\.(?:get|post))\s*\(\s*params\[', re.IGNORECASE),
        "Ruby HTTP request with user-supplied URL - SSRF risk",
        Severity.HIGH, _SR, (".rb",),
    ),
    (
        "SSRF-008",
        re.compile(r'http\.(?:Get|Post|NewRequest)\s*\(\s*(?:r\.(?:FormValue|URL|Header)|fmt\.Sprintf)', re.IGNORECASE),
        "Go HTTP request with dynamic URL - verify URL cannot be user-controlled",
        Severity.MEDIUM, _SR, (".go",),
    ),
    (
        "SSRF-009",
        re.compile(r'p?fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', re.IGNORECASE),
        "PHP fsockopen/pfsockopen with user-controlled host - SSRF enables internal port scanning and network probing",
        Severity.HIGH, _SR, (".php",),
    ),
    (
        "SSRF-010",
        re.compile(
            r'\b(?:restTemplate\s*\.\s*(?:getForObject|getForEntity|postForObject|postForEntity'
            r'|exchange|execute|put|delete|patchForObject)'
            r'|WebClient\s*\.\s*create)\s*\('
            r'(?=[^;\n]{0,300}(?:getParameter|getHeader|getQueryString|getAttribute|request\.))',
            re.IGNORECASE,
        ),
        "Spring RestTemplate/WebClient called with request-derived URL — SSRF risk (attacker can probe internal services)",
        Severity.HIGH, _SR, (".java",),
    ),
]

_GUARD = re.compile(
    r'curl_setopt|file_get_contents|new\s+URL\s*\(|HttpURLConnection|CloseableHttpClient'
    r'|fetch\s*\(|axios\.|http\.get|http\.request|https\.get|https\.request'
    r'|Net::HTTP|open-uri|URI\.open|RestClient\.|http\.Get|http\.Post|http\.NewRequest'
    r'|p?fsockopen|restTemplate\.|WebClient\.create',
    re.IGNORECASE,
)


class SSRFAnalyzer(BaseAnalyzer):
    # Python SSRF is handled by PythonASTAnalyzer with taint-aware detection.
    supported_extensions = (".php", ".java", ".js", ".ts", ".rb", ".go")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if file_path.endswith(exts)
        ]
        if not applicable:
            return []
        return self._scan_lines(file_path, content, repo_url, applicable, guard=_GUARD)
