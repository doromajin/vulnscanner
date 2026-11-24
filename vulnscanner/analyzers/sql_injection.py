import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_SI = VulnType.SQL_INJECTION

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "SQL-001",
        re.compile(
            r'(?:execute|query|cursor\.execute)\s*\(\s*["\'].*["\'\s]*\+'
            r'|(?:execute|query|cursor\.execute)\s*\(\s*f["\'].*\{',
            re.IGNORECASE,
        ),
        "SQL query built with string concatenation - susceptible to injection",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-002",
        re.compile(r'(?:execute|query)\s*\(\s*["\'].*%[sd].*["\'].*%', re.IGNORECASE),
        "SQL query uses %-formatting with user-controlled data",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-003",
        re.compile(r'(?:execute|query)\s*\(.*\.format\s*\(', re.IGNORECASE),
        "SQL query uses .format() - prefer parameterized queries",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-004",
        re.compile(r'\$(?:sql|query|stmt)\s*=\s*["\']SELECT.*["\'\s]*\.\s*\$', re.IGNORECASE),
        "PHP SQL query built with string concatenation",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-005",
        # `.raw()` with no argument is an accessor, not a query.
        re.compile(r'\.raw\s*\(\s*[^)\s]|\.extra\s*\(.*where', re.IGNORECASE),
        "Django ORM raw()/extra() - ensure no unsanitized input",
        Severity.MEDIUM, _SI,
    ),
    (
        "SQL-007",
        re.compile(
            r'\.(?:where|find_by_sql|having|from|joins|select)\s*\(\s*'
            r'(?:"[^"]*#\{|\'[^\']*#\{)',
            re.IGNORECASE,
        ),
        "Ruby ActiveRecord method with string interpolation #{} — SQL injection risk; use parameterized placeholders",
        Severity.HIGH, _SI,
    ),
    (
        "SQL-008",
        re.compile(
            r'(?:ActiveRecord::Base\.connection|connection)\.'
            r'(?:execute|select_all|select_one|select_value)\s*\('
            r'(?:"[^"]*#\{|\'[^\']*#\{)',
            re.IGNORECASE,
        ),
        "Ruby raw ActiveRecord connection query with string interpolation — SQL injection risk",
        Severity.CRITICAL, _SI,
    ),
]

_GUARD = re.compile(
    r'execute\s*\(|query\s*\(|cursor\.|\.raw\s*\(|\.extra\s*\(|\$sql|\$query|\$stmt'
    r'|\.where\s*\(|find_by_sql|\.having\s*\(',
    re.IGNORECASE,
)


_JAVA_SQL_EVIDENCE_RE = re.compile(
    r'java\.sql|javax\.persistence|jakarta\.persistence|JdbcTemplate|EntityManager|\bjooq\b|org\.hibernate'
    r'|createQuery|createNativeQuery|mybatis|SqlSession|DatabaseClient|R2dbc|prepareStatement',
    re.IGNORECASE,
)

_RB_SQL_RULES = frozenset({"SQL-001", "SQL-007", "SQL-008"})
_RB_MIGRATION_RE = re.compile(r'(?:^|/)db/(?:migrate|schema)[^/]*(?:/|\.rb$)')

# An interpolated expression that cannot carry request data into SQL text: a table name, a
# constant, an integer coercion, or the adapter's own boolean literals.
_RB_SAFE_EXPR_RE = re.compile(
    r'^(?:[\w:@.()]*\.)?(?:quoted_)?table_name$'
    r'|^(?:\w+\.)*connection\.quoted_(?:true|false)$'
    r'|^[A-Z][A-Z0-9_]*(?:::[A-Z][A-Z0-9_]*)*$'
    r'|\.to_i$|\.to_f$|^Integer\(.*\)$|^Float\(.*\)$'
)


def _rb_interpolations(line: str) -> list[str] | None:
    """`#{...}` expressions of the first double-quoted literal on the line (None: no such literal)."""
    start = line.find('"')
    if start < 0:
        return None
    exprs: list[str] = []
    i = start + 1
    while i < len(line):
        c = line[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return exprs
        if c == "#" and line[i + 1:i + 2] == "{":
            depth, j = 1, i + 2
            while j < len(line) and depth:
                depth += (line[j] == "{") - (line[j] == "}")
                j += 1
            exprs.append(line[i + 2:j - 1].strip())
            i = j
            continue
        i += 1
    return exprs


def _filter_ruby_interpolation(file_path: str, content: str, findings: list[Finding]) -> list[Finding]:
    """Ruby SQL rules fire on any `#{` in the first argument; keep only those whose interpolation
    is not a table name / constant / integer, and none in schema migrations (run by developers)."""
    if _RB_MIGRATION_RE.search(file_path.replace("\\", "/")):
        return [f for f in findings if f.rule_id not in _RB_SQL_RULES]
    kept: list[Finding] = []
    for f in findings:
        if f.rule_id not in ("SQL-007", "SQL-008"):
            kept.append(f)
            continue
        text = f.line_content
        m = re.search(r'\(\s*(?=["\'])', text)
        if m and text[m.end():m.end() + 1] == "'":
            continue  # single-quoted: `#{` is literal text, not interpolation
        exprs = _rb_interpolations(text[m.end():]) if m else None
        if exprs is None:
            kept.append(f)
            continue
        unsafe = [e for e in exprs
                  if not _RB_SAFE_EXPR_RE.search(e)
                  and not re.search(rf'^\s*{re.escape(e)}\s*=\s*.*table_name\s*$', content, re.MULTILINE)]
        if unsafe:
            kept.append(f)
    return kept


class SQLInjectionAnalyzer(BaseAnalyzer):
    # .py is handled by PythonASTAnalyzer with higher precision
    supported_extensions = (".php", ".js", ".ts", ".java", ".rb")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        rules = _RULES
        if file_path.endswith((".js", ".ts")) or file_path.endswith(".rb"):
            # `.raw(` is a Django ORM hook; in JS it is Guid.raw() / String.raw`` / knex.raw(),
            # and knex.raw with request data is covered by the JS taint analyzer.
            # In Ruby it is ActiveSupport's `raw` HTML helper.
            rules = [r for r in _RULES if r[0] != "SQL-005"]
        elif file_path.endswith(".java") and not _JAVA_SQL_EVIDENCE_RE.search(content):
            # A builder method named raw() in a file that never touches JDBC / JPA is not SQL.
            rules = [r for r in _RULES if r[0] != "SQL-005"]
        findings = self._scan_lines(file_path, content, repo_url, rules, guard=_GUARD)
        if file_path.endswith(".rb") and findings:
            findings = _filter_ruby_interpolation(file_path, content, findings)
        return findings
