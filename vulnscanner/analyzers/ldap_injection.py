import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_LDAP = VulnType.LDAP_INJECTION

_RULES = [
    # Python python-ldap: ldap.search_s(base, scope, "(uid=" + user_input + ")")
    (
        "LDAP-001",
        re.compile(
            r'\.search(?:_s|_ext|_ext_s)?\s*\([^)]*'
            r'(?:"[^"]*"\s*\+|f["\'][^"\']*\{|["\'][^"\']*["\'\s]*\+)',
            re.IGNORECASE,
        ),
        "LDAP search filter built with string concatenation/interpolation — LDAP injection allows authentication bypass",
        Severity.HIGH, _LDAP, (".py",),
    ),
    # Python ldap3: conn.search(search_base, search_filter=f"(uid={user_input})")
    (
        "LDAP-002",
        re.compile(
            r'conn\.search\s*\([^)]*search_filter\s*=\s*f["\']',
            re.IGNORECASE,
        ),
        "ldap3 conn.search() with f-string filter — LDAP injection risk if filter contains user input",
        Severity.HIGH, _LDAP, (".py",),
    ),
    # PHP: ldap_search($ldap, $base, "(uid=" . $_GET['u'] . ")")
    (
        "LDAP-003",
        re.compile(
            r'\bldap_(?:search|list|read)\s*\([^)]*'
            r'(?:\.[ \t]*\$_(?:GET|POST|REQUEST|COOKIE)|'
            r'\$_(?:GET|POST|REQUEST|COOKIE)[^)]*\.)',
            re.IGNORECASE,
        ),
        "PHP ldap_search/list/read with user-controlled filter — LDAP injection allows authentication bypass",
        Severity.HIGH, _LDAP, (".php",),
    ),
    # Java JNDI: ctx.search(dn, "(uid=" + request.getParameter("u") + ")", ...)
    (
        "LDAP-004",
        re.compile(
            r'\bctx\.(?:search|lookup)\s*\([^;)]*'
            r'(?:getParameter|getHeader|getQueryString|getAttribute|request\.)',
            re.IGNORECASE,
        ),
        "Java JNDI/DirContext search/lookup with request-derived filter — LDAP injection risk",
        Severity.HIGH, _LDAP, (".java",),
    ),
    # Node.js ldapjs / ldapts: client.search with filter containing req.*
    (
        "LDAP-005",
        re.compile(
            r'client\.search\s*\([^)]*filter\s*:\s*["\'][^"\']*["\'\s]*\+[^)]*req\.'
            r'|client\.search\s*\([^)]*filter\s*:[^)]*req\.',
            re.IGNORECASE,
        ),
        "Node.js LDAP client.search with request-derived filter — LDAP injection risk",
        Severity.HIGH, _LDAP, (".js", ".ts"),
    ),
    # Node.js: filter string concatenation with req.* (template literal or concat)
    (
        "LDAP-006",
        re.compile(
            r'filter\s*[:=]\s*`[^`]*\$\{[^`]*req\.',
            re.IGNORECASE,
        ),
        "LDAP filter template literal containing request data — LDAP injection risk",
        Severity.HIGH, _LDAP, (".js", ".ts"),
    ),
]

_GUARD = re.compile(
    r'\.search(?:_s|_ext)?\s*\(|ldap_(?:search|list|read)\s*\('
    r'|conn\.search\s*\(|ctx\.(?:search|lookup)\s*\('
    r'|client\.search\s*\(',
    re.IGNORECASE,
)


class LDAPInjectionAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".php", ".java", ".js", ".ts")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []

        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if exts is None or file_path.endswith(exts)
        ]
        if not applicable:
            return []
        return self._scan_lines(file_path, content, repo_url, applicable, guard=None)
