import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_PT = VulnType.PATH_TRAVERSAL

# exts=None means the rule applies to all supported extensions
# (rule_id, compiled_re, description, severity, vuln_type, exts_or_None)
_RULES = [
    (
        "PATH-001",
        re.compile(r'(?<![\w.])open\s*\(\s*(?:request|req|args|params|data|input)', re.IGNORECASE),
        "open() with potentially user-controlled path",
        Severity.HIGH, _PT, (".py", ".rb"),
    ),
    (
        "PATH-002",
        re.compile(r'(?<![\w.])open\s*\(.*\+|(?<![\w.])open\s*\(.*f["\'].*\{', re.IGNORECASE),
        "open() with string concatenation - path may be user-controlled",
        Severity.MEDIUM, _PT, (".py", ".rb", ".php"),
    ),
    (
        "PATH-003",
        re.compile(r'(?:send_file|send_from_directory|serve_file)\s*\(', re.IGNORECASE),
        "File-serving function - verify path is within expected root",
        Severity.MEDIUM, _PT, None,
    ),
    (
        "PATH-004",
        re.compile(r'\b(?:file_get_contents|include|require|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST)', re.IGNORECASE),
        "PHP file function called with direct user input",
        Severity.CRITICAL, _PT, (".php",),
    ),
    (
        "PATH-005",
        re.compile(r'\.\./|\.\.\\\\', re.IGNORECASE),
        "Literal path traversal sequence in source code",
        Severity.INFO, _PT, None,
    ),
    (
        "PATH-006",
        re.compile(
            r'\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync'
            r'|appendFile|appendFileSync|stat|statSync|lstat|lstatSync|unlink|unlinkSync'
            r'|rename|renameSync)\s*\([^)]*req\s*\.\s*(?:query|params|body)',
            re.IGNORECASE,
        ),
        "Node.js fs operation with request-derived path — path traversal allows reading arbitrary files",
        Severity.HIGH, _PT, (".js", ".ts"),
    ),
    (
        "PATH-007",
        re.compile(
            r'\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream|stat|statSync)\s*\('
            r'[^)]*`[^`]*\$\{',
            re.IGNORECASE,
        ),
        "Node.js fs operation with template literal path — verify no request data injected",
        Severity.MEDIUM, _PT, (".js", ".ts"),
    ),
]

_GUARD = re.compile(
    r'open\s*\(|send_file|send_from_directory|serve_file|file_get_contents'
    r'|include\s*\(|require\s*\(|fopen\s*\(|\.\./|\.\.\\\\'
    r'|fs\s*\.\s*(?:readFile|writeFile|createReadStream|stat|unlink|rename)'
    , re.IGNORECASE,
)


class PathTraversalAnalyzer(BaseAnalyzer):
    # .py is handled by PythonASTAnalyzer with higher precision
    supported_extensions = (".php", ".js", ".ts", ".java", ".rb")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        applicable = [
            (rid, re_obj, desc, sev, vt)
            for rid, re_obj, desc, sev, vt, exts in _RULES
            if exts is None or file_path.endswith(exts)
        ]
        if not applicable:
            return []
        return self._scan_lines(file_path, content, repo_url, applicable, guard=_GUARD)
