import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_NOSQL = VulnType.SQL_INJECTION  # reuse; no dedicated NoSQL type yet

_RULES = [
    # MongoDB JS/TS: collection.find({$where: userInput})
    (
        "NOSQL-001",
        re.compile(r'\$where\s*:', re.IGNORECASE),
        "MongoDB $where operator with JavaScript evaluation — NoSQL injection / RCE risk",
        Severity.CRITICAL,
    ),
    # MongoDB JS/TS: collection.find(req.body) — passing request body directly as query
    (
        "NOSQL-002",
        re.compile(
            r'\.(?:find|findOne|findById|count|countDocuments|deleteOne|deleteMany'
            r'|updateOne|updateMany|replaceOne)\s*\(\s*req\.',
            re.IGNORECASE,
        ),
        "MongoDB query receives request object directly — operator injection ($gt, $ne, $where) risk",
        Severity.HIGH,
    ),
    # Python pymongo: collection.find(request_data) or find({"$where": ...})
    (
        "NOSQL-003",
        re.compile(
            r'\.(?:find|find_one|count_documents|delete_one|delete_many'
            r'|update_one|update_many)\s*\(\s*(?:request\.|req\.|body\[|args\[)',
            re.IGNORECASE,
        ),
        "pymongo query receives request-derived data — NoSQL operator injection risk",
        Severity.HIGH,
    ),
    # Mongoose: Model.find(JSON.parse(userInput))
    (
        "NOSQL-004",
        re.compile(
            r'\.(?:find|findOne|findById|countDocuments)\s*\(\s*JSON\.parse\s*\(',
            re.IGNORECASE,
        ),
        "Mongoose query uses JSON.parse(userInput) — attacker can inject MongoDB operators",
        Severity.HIGH,
    ),
    # Node.js MongoDB: $regex operator with user input (ReDoS + injection)
    (
        "NOSQL-005",
        re.compile(r'\$regex\s*:\s*req\.', re.IGNORECASE),
        "MongoDB $regex operator with request data — ReDoS and injection risk",
        Severity.HIGH,
    ),
    # PHP: MongoDB PHP library — find with $_GET/$_POST
    (
        "NOSQL-006",
        re.compile(
            r'->(?:find|findOne|count|deleteOne|deleteMany|updateOne|updateMany)\s*'
            r'\(\s*\[.*\$_(?:GET|POST|REQUEST)',
            re.IGNORECASE | re.DOTALL,
        ),
        "PHP MongoDB query with superglobal input — NoSQL injection risk",
        Severity.HIGH,
    ),
]

_GUARD = re.compile(
    r'\$where|\$regex|\$gt|\$ne|\$in\b|\.find\s*\(|find_one|findOne|mongoose|pymongo'
    r'|MongoClient|collection\.',
    re.IGNORECASE,
)


class NoSQLInjectionAnalyzer(BaseAnalyzer):
    supported_extensions = (".js", ".ts", ".jsx", ".tsx", ".py", ".php")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD.search(content):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            stripped = line.strip()
            for rule_id, pattern_re, description, severity in _RULES:
                if not pattern_re.search(line):
                    continue
                findings.append(Finding(
                    vuln_type=_NOSQL,
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
