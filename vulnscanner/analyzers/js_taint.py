"""
JavaScript / TypeScript 1-hop taint tracker.

Detects user-controlled data flowing from Express/Koa/Fastify/Lambda request
objects through variable assignments into dangerous sinks.  Complements the
regex rules in command_injection.py and path_traversal.py which only fire
when the request object appears *directly* in the sink call.

Two-pass algorithm (same structure as PHP XSS taint in xss.py):
  Pass 1 — build a taint map {var_name → (src_line, description)}
    • direct:       const x = req.body.cmd          → x tainted
    • destructure:  const { x, y } = req.body        → x, y tainted
    • template:     const s = `prefix ${x}`           → s tainted if x tainted
    • alias:        const z = x                       → z tainted if x tainted
    • sanitized:    const n = parseInt(x)             → n NOT tainted

  Pass 2 — check each sink for tainted variables
    • Command injection:  exec(x), execSync(x), spawn(x, ...), child_process.*
    • SQL injection:      db.query(x), connection.query(x + ...), knex.raw(x)
    • Path traversal:     fs.readFile(x), fs.writeFile(x), path.join(x, ...)
    • XSS (reflected):   res.send(x), res.write(x), res.end(x)
    • Code injection:    eval(x), new Function(x)
    • SSRF:              fetch(x), axios.get(x), http.request(x)
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# ── Source patterns ───────────────────────────────────────────────────────────

# Express/Koa/Fastify/Lambda request taint sources.
_REQ_SOURCE_RE = re.compile(
    r'\b(?:req|request|ctx(?:\.request)?|event)\s*\.'
    r'\s*(?:body|query|params|queryStringParameters|pathParameters|headers|files|cookies)'
    r'(?:\s*\.\s*\w+)*'
    r'|\bevent\s*\.\s*(?:body|queryStringParameters)',
    re.IGNORECASE,
)

# ── Assignment patterns ───────────────────────────────────────────────────────

# const/let/var x = <rhs>   (captures var name + full rhs)
_SIMPLE_ASSIGN_RE = re.compile(
    r'(?:^|;)\s*(?:const|let|var)\s+(\w+)\s*=\s*(.+?)(?:;|$)',
    re.IGNORECASE | re.MULTILINE,
)

# const { a, b: c, d = default } = <rhs>   (named + aliased destructuring)
_DESTRUCT_ASSIGN_RE = re.compile(
    r'(?:^|;)\s*(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+?)(?:;|$)',
    re.IGNORECASE | re.MULTILINE,
)

# Destructuring entry: handles  a, b: localName, c = defaultVal
_DESTRUCT_KEY_RE = re.compile(r'\b(\w+)(?:\s*:\s*(\w+))?(?:\s*=\s*[^,}]+)?')

# Template literal: captures all ${varName} references (simple names only)
_TEMPLATE_VAR_RE = re.compile(r'\$\{(\w+)\}')

# ── Sanitizer detection ───────────────────────────────────────────────────────

# RHS patterns that fully sanitize a value (numeric coercion, escaping)
_SANITIZER_RE = re.compile(
    r'^\s*(?:parseInt|parseFloat|Number|Boolean|BigInt)\s*\('
    r'|^\s*(?:encodeURIComponent|encodeURI|escape)\s*\('
    r'|^\s*(?:DOMPurify\.sanitize|validator\.escape|xss)\s*\('
    r'|^\s*(?:JSON\.stringify)\s*\(',
    re.IGNORECASE,
)

# ── Sink patterns ─────────────────────────────────────────────────────────────
# Each sink: (rule_id, compiled_re, vuln_type, severity, description_template)
# The regex must capture the variable name in group 1.

@dataclass(frozen=True)
class _SinkRule:
    rule_id: str
    pattern: re.Pattern
    vuln_type: VulnType
    severity: Severity
    desc_tmpl: str  # {var} replaced at report time


_SINK_RULES: list[_SinkRule] = [
    _SinkRule(
        rule_id="JSTAINT-CMD-001",
        pattern=re.compile(
            r'\b(?:exec|execSync|execFile|execFileSync|spawnSync)\s*\(\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        desc_tmpl=(
            "{var} flows from user input to child_process sink — "
            "arbitrary OS command execution risk"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-CMD-002",
        pattern=re.compile(
            r'\bspawn\s*\(\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.HIGH,
        desc_tmpl=(
            "{var} flows from user input to spawn() — command injection risk"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-SQL-001",
        pattern=re.compile(
            r'(?:\.query|\.execute|\.raw)\s*\(\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.HIGH,
        desc_tmpl=(
            "{var} flows from user input to SQL query sink — "
            "use parameterized queries instead"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-SQL-002",
        # String concatenation into query: db.query("SELECT ... " + tainted)
        pattern=re.compile(
            r'(?:\.query|\.execute)\s*\([^)]*\+\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.HIGH,
        desc_tmpl=(
            "{var} concatenated into SQL query — injection risk"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-SQL-003",
        # Template literal in query: db.query(`SELECT ... ${tainted}`)
        pattern=re.compile(
            r'(?:\.query|\.execute|\.raw)\s*\(`[^`]*\$\{(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.HIGH,
        desc_tmpl=(
            "{var} interpolated into SQL template literal — injection risk"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-PATH-001",
        pattern=re.compile(
            r'\bfs\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync'
            r'|appendFile|appendFileSync|createReadStream|createWriteStream'
            r'|unlink|unlinkSync|stat|statSync|rename|renameSync)\s*\(\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        desc_tmpl=(
            "{var} flows from user input to fs operation — path traversal risk"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-PATH-002",
        pattern=re.compile(
            r'\bpath\.(?:join|resolve|normalize)\s*\([^)]*,\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.PATH_TRAVERSAL,
        severity=Severity.MEDIUM,
        desc_tmpl=(
            "{var} used in path.join/resolve with user input — verify within allowed root"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-XSS-001",
        pattern=re.compile(
            r'\bres\s*\.\s*(?:send|write|end)\s*\(\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        desc_tmpl=(
            "{var} flows from user input into HTTP response — XSS risk if "
            "Content-Type is text/html; sanitize or set JSON content type"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-EVAL-001",
        pattern=re.compile(
            r'\beval\s*\(\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        desc_tmpl=(
            "{var} flows from user input into eval() — arbitrary code execution"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-EVAL-002",
        pattern=re.compile(
            r'\bnew\s+Function\s*\([^)]*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        desc_tmpl=(
            "{var} flows from user input into new Function() — arbitrary code execution"
        ),
    ),
    _SinkRule(
        rule_id="JSTAINT-SSRF-001",
        pattern=re.compile(
            r'\b(?:fetch|axios\.(?:get|post|put|delete|request)'
            r'|https?\.(?:get|request)|superagent\.(?:get|post))\s*\(\s*(\w+)',
            re.IGNORECASE,
        ),
        vuln_type=VulnType.SSRF,
        severity=Severity.HIGH,
        desc_tmpl=(
            "{var} flows from user input into HTTP request — SSRF risk"
        ),
    ),
]

# Guard: only process files that reference any of these keywords
_GUARD_RE = re.compile(
    r'\breq\s*\.|request\s*\.|ctx\s*\.|event\s*\.',
    re.IGNORECASE,
)

_JS_EXTS = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")


class JSTaintAnalyzer(BaseAnalyzer):
    """JavaScript/TypeScript 1-hop taint tracker for Express/Koa/Lambda apps."""

    supported_extensions = _JS_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _GUARD_RE.search(content):
            return []

        lines = content.splitlines()
        tainted = self._build_taint_map(lines)
        if not tainted:
            return []

        return self._check_sinks(file_path, lines, tainted, repo_url)

    # ── Pass 1: build taint map ───────────────────────────────────────────────

    def _build_taint_map(
        self, lines: list[str]
    ) -> dict[str, tuple[int, str]]:
        """Return {var_name: (line_no, taint_reason)} for all tainted vars."""
        tainted: dict[str, tuple[int, str]] = {}

        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if self._is_comment(line):
                continue

            # Direct assignment: const x = req.body.cmd
            for m in _SIMPLE_ASSIGN_RE.finditer(raw):
                var, rhs = m.group(1), m.group(2).strip()
                self._process_simple_assign(var, rhs, lineno, tainted)

            # Destructuring: const { a, b: localB } = req.body
            for m in _DESTRUCT_ASSIGN_RE.finditer(raw):
                keys_str, rhs = m.group(1), m.group(2).strip()
                self._process_destruct_assign(keys_str, rhs, lineno, tainted)

        # Second sub-pass: propagate taint through aliases and template literals.
        # Repeat until no new tainted variables are added (1-2 hops typical).
        changed = True
        while changed:
            changed = False
            for lineno, raw in enumerate(lines, 1):
                if self._is_comment(raw.strip()):
                    continue
                for m in _SIMPLE_ASSIGN_RE.finditer(raw):
                    var, rhs = m.group(1), m.group(2).strip()
                    if var in tainted:
                        continue
                    if self._rhs_is_tainted(rhs, tainted):
                        tainted[var] = (lineno, f"derived from tainted value")
                        changed = True

        return tainted

    def _process_simple_assign(
        self,
        var: str,
        rhs: str,
        lineno: int,
        tainted: dict[str, tuple[int, str]],
    ) -> None:
        """Handle const x = <rhs>."""
        if _SANITIZER_RE.match(rhs):
            tainted.pop(var, None)
            return
        if _REQ_SOURCE_RE.search(rhs):
            tainted[var] = (lineno, f"assigned from request data: {rhs[:60]}")

    def _process_destruct_assign(
        self,
        keys_str: str,
        rhs: str,
        lineno: int,
        tainted: dict[str, tuple[int, str]],
    ) -> None:
        """Handle const { a, b: localB } = req.body."""
        if not _REQ_SOURCE_RE.search(rhs):
            return
        for km in _DESTRUCT_KEY_RE.finditer(keys_str):
            # If aliased (b: localB), the local name is group 2; otherwise group 1
            local_name = km.group(2) or km.group(1)
            tainted[local_name] = (lineno, f"destructured from request data: {rhs[:60]}")

    def _rhs_is_tainted(
        self, rhs: str, tainted: dict[str, tuple[int, str]]
    ) -> bool:
        """Return True if rhs references a tainted variable (alias or template)."""
        if _SANITIZER_RE.match(rhs):
            return False
        # Template literal: check each ${varName} placeholder
        if '`' in rhs or '${' in rhs:
            for var_m in _TEMPLATE_VAR_RE.finditer(rhs):
                if var_m.group(1) in tainted:
                    return True
        # Simple alias: rhs is exactly a tainted variable name
        rhs_stripped = rhs.strip().rstrip(';')
        if re.fullmatch(r'\w+', rhs_stripped) and rhs_stripped in tainted:
            return True
        # String concatenation: "SELECT ... " + taintedVar
        for word in re.findall(r'\b(\w+)\b', rhs):
            if word in tainted and re.search(r'\+\s*' + re.escape(word) + r'\b', rhs):  # vulnscanner: ignore
                return True
        return False

    # ── Pass 2: check sinks ───────────────────────────────────────────────────

    def _check_sinks(
        self,
        file_path: str,
        lines: list[str],
        tainted: dict[str, tuple[int, str]],
        repo_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()  # (rule_id, lineno) dedup

        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if self._is_comment(line):
                continue
            for sink in _SINK_RULES:
                for m in sink.pattern.finditer(raw):
                    var = m.group(1)
                    if var not in tainted:
                        continue
                    key = (sink.rule_id, lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    src_line, reason = tainted[var]
                    findings.append(Finding(
                        vuln_type=sink.vuln_type,
                        severity=sink.severity,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line,
                        description=(
                            sink.desc_tmpl.format(var=var)
                            + f" (tainted at line {src_line}: {reason})"
                        ),
                        rule_id=sink.rule_id,
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))
        return findings
