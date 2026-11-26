"""CORS Misconfiguration Analyzer (CWE-346).

Detects CORS policies that allow unauthorized cross-origin access to sensitive resources.
Most dangerous: wildcard origin combined with credentials, or reflected origin without allowlist.
"""
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_CORS = VulnType.CORS_MISCONFIGURATION

_RULES = [
    # Python Flask-CORS / Django-CORS-Headers: wildcard + credentials (HIGH risk)
    (
        "CORS-001",
        re.compile(
            r'CORS\s*\([^)]*origins\s*=\s*["\'][*]["\'][^)]*supports_credentials\s*=\s*True'
            r'|CORS\s*\([^)]*supports_credentials\s*=\s*True[^)]*origins\s*=\s*["\'][*]["\']',
            re.IGNORECASE,
        ),
        "CORS wildcard origin with credentials=True — any site can make credentialed cross-origin requests; specify allowed origins explicitly",
        Severity.HIGH, _CORS, (".py",),
    ),
    # Django settings: CORS_ALLOW_ALL_ORIGINS = True (any origin allowed)
    (
        "CORS-002",
        re.compile(
            r'CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True',
            re.IGNORECASE,
        ),
        "CORS_ALLOW_ALL_ORIGINS = True allows any origin to make cross-origin requests — use CORS_ALLOWED_ORIGINS with an explicit allowlist",
        Severity.MEDIUM, _CORS, (".py",),
    ),
    # Express: res.header("Access-Control-Allow-Origin", req.headers.origin) — reflects arbitrary origin
    (
        "CORS-003",
        re.compile(
            r'(?:res|response|ctx)\.(?:header|set|setHeader)\s*\([^)]*Access-Control-Allow-Origin[^)]*req\.(?:headers?\.origin|get\s*\(\s*["\']origin["\'])',
            re.IGNORECASE,
        ),
        "CORS policy reflects request Origin header without allowlist validation — any site can make credentialed cross-origin requests",
        Severity.HIGH, _CORS, (".js", ".ts"),
    ),
    # Node.js cors() middleware with origin: '*'
    (
        "CORS-004",
        re.compile(
            r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\'][*]["\']',
            re.IGNORECASE,
        ),
        "cors() middleware with origin: '*' — wildcard CORS allows any site to make cross-origin requests",
        Severity.MEDIUM, _CORS, (".js", ".ts"),
    ),
    # Java Spring: setAllowedOrigins("*") with setAllowCredentials(true)
    (
        "CORS-005",
        re.compile(
            r'setAllowedOrigins\s*\(\s*(?:["\'][*]["\']|Arrays\.asList\s*\(\s*["\'][*]["\'])',
            re.IGNORECASE,
        ),
        "Spring CORS setAllowedOrigins(\"*\") allows all origins — use a specific origin allowlist",
        Severity.MEDIUM, _CORS, (".java",),
    ),
    # Java Spring: @CrossOrigin(origins = "*")
    (
        "CORS-006",
        re.compile(
            r'@CrossOrigin\s*\([^)]*origins\s*=\s*(?:["\'][*]["\']|\*)',
            re.IGNORECASE,
        ),
        "@CrossOrigin with origins=\"*\" allows any site to make cross-origin requests to this endpoint",
        Severity.MEDIUM, _CORS, (".java",),
    ),
    # PHP: header("Access-Control-Allow-Origin: *")
    (
        "CORS-007",
        re.compile(
            r'header\s*\(\s*["\']Access-Control-Allow-Origin\s*:\s*\*["\']',
            re.IGNORECASE,
        ),
        "PHP header sets wildcard CORS — any origin can read responses from this endpoint",
        Severity.MEDIUM, _CORS, (".php",),
    ),
    # PHP / Laravel / Symfony: the request Origin echoed into Access-Control-Allow-Origin
    (
        "CORS-009",
        re.compile(
            r'Access-Control-Allow-Origin["\']?\s*[,:]\s*["\']?\s*(?:\.\s*)?'
            r'(?:\$_SERVER\s*\[\s*["\']HTTP_ORIGIN["\']\s*\]'
            r'|\$\w+\s*->\s*header\s*\(\s*["\']Origin["\']\s*\)'
            r'|\$\w+\s*->\s*headers\s*->\s*get\s*\(\s*["\']Origin["\']\s*\))',
            re.IGNORECASE,
        ),
        "CORS policy reflects the request Origin header without an allowlist — any site can make credentialed cross-origin requests",
        Severity.HIGH, _CORS, (".php",),
    ),
    # Laravel / Symfony response header: ->header('Access-Control-Allow-Origin', '*')
    (
        "CORS-010",
        re.compile(
            r'->\s*(?:header|set)\s*\(\s*["\']Access-Control-Allow-Origin["\']\s*,\s*["\'][*]["\']',
            re.IGNORECASE,
        ),
        "Response sets a wildcard Access-Control-Allow-Origin — any origin can read it; restrict to known origins",
        Severity.MEDIUM, _CORS, (".php",),
    ),
    # Python: response.headers["Access-Control-Allow-Origin"] = "*" or request.headers.get("Origin")
    (
        "CORS-008",
        re.compile(
            r'(?:response\.headers|headers)\s*\[\s*["\']Access-Control-Allow-Origin["\']'
            r'\s*\]\s*=\s*(?:["\'][*]["\']|request\.headers\.(?:get\s*\(\s*["\']Origin["\']|origin))',
            re.IGNORECASE,
        ),
        "CORS header set to wildcard or reflected request origin — restrict to known origins to prevent CSRF via CORS",
        Severity.MEDIUM, _CORS, (".py",),
    ),
    # Java: response header / Spring config allowing every origin
    (
        "CORS-012",
        re.compile(
            r'(?:(?:set|add)Header\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*"[*]"'
            r'|(?:addAllowedOrigin|allowedOrigins|allowedOriginPatterns|addAllowedOriginPattern'
            r'|setAllowedOriginPatterns)\s*\(\s*(?:(?:Arrays\.asList|List\.of)\s*\(\s*)?"[*]")',
        ),
        "CORS policy allows every origin (wildcard) - restrict to an explicit origin allowlist; with credentials this exposes authenticated responses",
        Severity.MEDIUM, _CORS, (".java",),
    ),
    # Java Spring: @CrossOrigin("*") shorthand
    (
        "CORS-013",
        re.compile(r'@CrossOrigin\s*\(\s*(?:value\s*=\s*)?"[*]"'),
        "@CrossOrigin(\"*\") allows any site to make cross-origin requests to this endpoint",
        Severity.MEDIUM, _CORS, (".java",),
    ),
]

_GUARD = re.compile(
    r'Access-Control-Allow-Origin|CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL|cors\s*\(|@CrossOrigin|llowedOrigin|supports_credentials',
    re.IGNORECASE,
)


_JAVA_ACAO = re.compile(r'(?:set|add)Header\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*([^;]+?)\)\s*;')
_JAVA_ORIGIN_SRC = re.compile(r'getHeader\s*\(\s*"[Oo]rigin"\s*\)')
_JAVA_ORIGIN_VAR = re.compile(r'(?:String\s+)?(\w+)\s*=\s*[^;]*getHeader\s*\(\s*"[Oo]rigin"\s*\)')
_JAVA_LOG = re.compile(r'(?:log(?:ger)?|System\.out|System\.err)\b', re.IGNORECASE)


def _java_reflected_origin(analyzer, file_path, content, repo_url):
    """response.setHeader("Access-Control-Allow-Origin", <request Origin>) without a validation of that value."""
    if "Access-Control-Allow-Origin" not in content or not _JAVA_ORIGIN_SRC.search(content):
        return []
    lines = content.splitlines()
    assigned = {}  # var -> line index of assignment
    for i, ln in enumerate(lines):
        m = _JAVA_ORIGIN_VAR.search(ln)
        if m:
            assigned[m.group(1)] = i
    out = []
    for i, ln in enumerate(lines):
        if analyzer._is_comment(ln):
            continue
        m = _JAVA_ACAO.search(ln)
        if not m:
            continue
        arg = m.group(1).strip()
        if _JAVA_ORIGIN_SRC.search(arg):
            reflected = True
            var = None
        elif re.fullmatch(r'\w+', arg) and arg in assigned and assigned[arg] < i:
            reflected, var = True, arg
        else:
            continue
        if var:
            vre = re.compile(r'(?:^|[^\w.])' + re.escape(var) + r'(?![\w])')
            validated = False
            for j in range(assigned[var] + 1, i):
                seg = lines[j]
                if _JAVA_LOG.search(seg) or not vre.search(seg):
                    continue
                # the value is handed to a call or compared/looked up inside a condition = validated
                if re.search(r'(?:if|while|assert)\s*\(', seg) and re.search(
                        r'\w\s*\([^;]*' + re.escape(var) + r'|' + re.escape(var) + r'\s*\.\s*(?:equals|matches|startsWith|endsWith|contains)\s*\(', seg):
                    validated = True
                    break
                if re.search(r'(?:equals|matches|contains|startsWith|endsWith)\s*\(\s*' + re.escape(var) + r'\b', seg):
                    validated = True
                    break
            if validated:
                continue
        out.append(Finding(
            vuln_type=_CORS, severity=Severity.HIGH, file_path=file_path, line_number=i + 1,
            line_content=ln.strip(),
            description="Access-Control-Allow-Origin is set from the request Origin header without an allowlist check - any site can make credentialed cross-origin requests; compare the origin against a fixed allowlist",
            rule_id="CORS-011", repo_url=repo_url, snippet=analyzer._extract_snippet(lines, i + 1),
        ))
    return out


class CORSAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".js", ".ts", ".java", ".php")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []
        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if file_path.endswith(exts)
        ]
        if not applicable:
            return []
        found = self._scan_lines(file_path, content, repo_url, applicable, guard=None,
                                 mask_strings_py=True)
        if file_path.endswith(".java"):
            found += _java_reflected_origin(self, file_path, content, repo_url)
        return found
