"""Java-specific vulnerability analyzer.

Covers Java/Spring/JEE patterns not handled by language-agnostic analyzers.
All rules target .java files only; PythonASTAnalyzer handles Python with
higher precision for overlapping concepts (SQL, path, SSRF).
"""
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_SI   = VulnType.SQL_INJECTION
_CI   = VulnType.COMMAND_INJECTION
_PT   = VulnType.PATH_TRAVERSAL
_SSRF = VulnType.SSRF
_DESER = VulnType.INSECURE_DESERIALIZATION
_XXE  = VulnType.XXE
_JNDI = VulnType.JNDI_INJECTION

# (rule_id, compiled_re, description, severity, vuln_type)
_RULES = [
    (
        "JAVA-SQL-001",
        re.compile(
            r'(?:Statement|PreparedStatement|createStatement)\s*[^;]*\n?'
            r'.*\.execute(?:Query|Update|Batch)?\s*\(\s*(?:["\'].*["\'\s]*\+|.*\bgetParam|.*\brequest\.)',
            re.IGNORECASE,
        ),
        "Java Statement.execute*() with string concatenation — SQL injection risk",
        Severity.HIGH, _SI,
    ),
    (
        "JAVA-SQL-002",
        re.compile(
            r'(?:createQuery|createNativeQuery|createNamedQuery)\s*\(\s*["\'].*["\'\s]*\+',
            re.IGNORECASE,
        ),
        "JPA createQuery/createNativeQuery with string concatenation — SQL injection",
        Severity.HIGH, _SI,
    ),
    (
        "JAVA-CMD-001",
        re.compile(
            r'(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(',
            re.IGNORECASE,
        ),
        "Java Runtime.exec / ProcessBuilder — verify arguments are not user-controlled",
        Severity.HIGH, _CI,
    ),
    (
        "JAVA-XXE-001",
        re.compile(
            r'DocumentBuilderFactory\.newInstance\(\)',
            re.IGNORECASE,
        ),
        "Java DocumentBuilderFactory without XXE hardening — external entity injection risk",
        Severity.HIGH, _XXE,
    ),
    (
        "JAVA-XXE-002",
        re.compile(
            r'SAXParserFactory\.newInstance\(\)',
            re.IGNORECASE,
        ),
        "Java SAXParserFactory without XXE hardening",
        Severity.HIGH, _XXE,
    ),
    (
        "JAVA-DESER-001",
        re.compile(
            r'new\s+ObjectInputStream\s*\(',
            re.IGNORECASE,
        ),
        "Java ObjectInputStream.readObject() — unsafe deserialization of untrusted data",
        Severity.CRITICAL, _DESER,
    ),
    (
        "JAVA-JNDI-001",
        re.compile(
            r'InitialContext\(\)\.lookup\s*\(',
            re.IGNORECASE,
        ),
        "Java JNDI lookup with potentially user-controlled name — Log4Shell-style injection",
        Severity.CRITICAL, _JNDI,
    ),
    (
        "JAVA-PATH-001",
        re.compile(
            r'new\s+File(?:InputStream|Reader|RandomAccessFile)?\s*\(\s*(?:request\.|getParam|getHeader)',
            re.IGNORECASE,
        ),
        "Java file access with request parameter — path traversal risk",
        Severity.HIGH, _PT,
    ),
    (
        "JAVA-SSRF-001",
        re.compile(
            r'new\s+URL\s*\(\s*(?:request\.|getParam|getHeader)',
            re.IGNORECASE,
        ),
        "Java URL instantiation with request parameter — SSRF risk",
        Severity.HIGH, _SSRF,
    ),
    # SQL-006: JDBC/JPA string concatenation (statement-bounded, requires SQL keyword)
    (
        "SQL-006",
        re.compile(
            r'\b(?:\w+\s*\.\s*)?(?:prepareStatement|prepareCall|createQuery|createNativeQuery'
            r'|createSQLQuery|executeQuery|executeUpdate|execute|addBatch)\s*\('
            r'(?=[^;\n]{0,300}\+)'          # concat operator present within statement
            r'(?=[^;\n]{0,300}\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO|SET)\b)',
            re.IGNORECASE,
        ),
        "Java JDBC/JPA call with string concatenation containing SQL keyword — SQL injection risk",
        Severity.HIGH, _SI,
    ),
    # CMD-008: ProcessBuilder / Runtime.exec with non-literal first argument
    (
        "CMD-008",
        re.compile(
            r'\bnew\s+ProcessBuilder\s*\([^;\n]{0,300}'
            r'(?:getParam|getHeader|getQueryString|getAttribute|request\.|args\[|argv\[)',
            re.IGNORECASE,
        ),
        "Java ProcessBuilder with request-derived argument — command injection risk",
        Severity.CRITICAL, _CI,
    ),
    # PATH-006: File/Path construction with request-derived argument
    (
        "PATH-006",
        re.compile(
            r'\b(?:new\s+(?:java\.io\.)?(?:File|FileInputStream|FileReader|FileOutputStream|FileWriter)'
            r'|(?:java\.nio\.file\.)?(?:Paths\.get|Path\.of))\s*\('
            r'(?=[^;\n]{0,300}(?:getParam|getHeader|getQueryString|getAttribute|request\.))',
            re.IGNORECASE,
        ),
        "Java File/Path construction with request-derived argument — path traversal risk",
        Severity.HIGH, _PT,
    ),
    # DESER-009: XStream deserialization (CVE-2013-7285, CVE-2021-21351)
    (
        "DESER-009",
        re.compile(
            r'\bnew\s+(?:[\w$]+\.)*XStream\s*\('
            r'|xstream\.(?:fromXML|unmarshal)\s*\(',
            re.IGNORECASE,
        ),
        "Java XStream deserialization — RCE risk without allowlist (CVE-2021-21351)",
        Severity.CRITICAL, _DESER,
    ),
    # JAVA-XXE-003: XMLInputFactory without disabling external entities
    (
        "JAVA-XXE-003",
        re.compile(
            r'\b(?:javax\.xml\.stream\.)?XMLInputFactory\s*\.\s*(?:newInstance|newFactory)\s*\(',
            re.IGNORECASE,
        ),
        "Java XMLInputFactory (StAX) without disabling IS_SUPPORTING_EXTERNAL_ENTITIES — XXE risk",
        Severity.HIGH, _XXE,
    ),
]

_GUARD = re.compile(
    r'ObjectInputStream|DocumentBuilderFactory|SAXParserFactory'
    r'|InitialContext|ProcessBuilder|Runtime\.getRuntime'
    r'|createQuery|createNativeQuery|new\s+URL\s*\('
    r'|XStream|fromXML|unmarshal|XMLInputFactory'
    r'|prepareStatement|prepareCall|executeQuery|executeUpdate'
    r'|new\s+File|Paths\.get|Path\.of',
    re.IGNORECASE,
)


class JavaAnalyzer(BaseAnalyzer):
    supported_extensions = (".java",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        return self._scan_lines(file_path, content, repo_url, _RULES, guard=_GUARD)
