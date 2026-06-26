import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# ── Simple per-line rules (XSS-002 to XSS-007) ────────────────────────────────

# DOM manipulation APIs that only exist in JavaScript/HTML contexts.
# Restricting their rules to these extensions prevents self-reference FPs
# when their pattern strings appear inside Python source files.
_JS_HTML_EXTS = (".js", ".ts", ".jsx", ".tsx", ".html")
# Rule IDs restricted to JS/HTML only (DOM APIs absent from Python)
_JS_HTML_ONLY = frozenset({"XSS-002", "XSS-006"})

_SIMPLE_RULES = [
    (
        "XSS-002",
        r'document\.write\s*\(',
        "document.write() with potentially unsanitized input",
        Severity.HIGH,
    ),
    (
        "XSS-003",
        r'outerHTML\s*=\s*(?![\'"]\s*[\'"])',
        "Direct outerHTML assignment",
        Severity.HIGH,
    ),
    (
        "XSS-004",
        r'\|\s*safe\b|mark_safe\s*\(|format_html\s*\(.*\+',
        "Template value marked safe without explicit sanitization",
        Severity.MEDIUM,
    ),
    (
        "XSS-005",
        r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE)',
        "PHP direct echo of user-supplied input",
        Severity.HIGH,
    ),
    (
        "XSS-006",
        r'insertAdjacentHTML\s*\(',
        "insertAdjacentHTML() - verify content is sanitized",
        Severity.MEDIUM,
    ),
    (
        "XSS-007",
        r'eval\s*\(\s*(?:location|document\.|window\.)',
        "eval() with browser-controlled input",
        Severity.CRITICAL,
    ),
]

# ── XSS-001: innerHTML smart analysis ─────────────────────────────────────────

# Functions whose return value is safe to assign to innerHTML.
_SAFE_FUNCS = frozenset({
    "escHtml", "escapeHtml", "htmlEscape", "sanitize", "sanitizeHtml", "escape",
    "encodeURIComponent", "encodeURI",
    "DOMPurify.sanitize",
    "Number", "parseInt", "parseFloat",
    "JSON.stringify",
})

# Regex to extract all ${...} interpolations from a template literal.
_INTERP_RE = re.compile(r'\$\{([^}]+)\}')

# ── PHP XSS 1-hop taint analysis (XSS-008) ────────────────────────────────────

# PHP superglobals that carry user-controlled input
_PHP_SUPERGLOBALS_RE = re.compile(
    r'\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[',
    re.IGNORECASE,
)

# Functions that sanitize a value for HTML output — wrapping a superglobal
# in one of these makes the variable safe to echo.
_PHP_XSS_CLEAN_RE = re.compile(
    r"^\s*(?:htmlspecialchars|htmlentities|strip_tags|esc_html|esc_attr"
    r"|wp_kses|wp_kses_post|intval|floatval|abs)\s*\(",
    re.IGNORECASE,
)

# Single-line PHP assignment: $varname = expr;
_PHP_ASSIGN_RE = re.compile(r"^\s*\$(\w+)\s*=\s*(.+?);\s*$", re.IGNORECASE)

# echo / print sink (captures the full expression, greedy)
_PHP_ECHO_RE = re.compile(r"^\s*(?:echo|print)\b\s+(.+)", re.IGNORECASE)


def _is_safe_interpolation(expr: str) -> bool:
    """
    Return True when a ${expr} value cannot introduce XSS.

    Conservative rule: any function call is treated as safer than a bare
    identifier/property access.  Only bare references (e.g. ``${c.id}``,
    ``${title}``) are considered unsafe.
    """
    expr = expr.strip()

    # Numeric / boolean constant
    if re.match(r'^[\d.]+$', expr) or expr in ('true', 'false', 'null', 'undefined'):
        return True

    # .length is always a number
    if re.match(r'^[\w$.]+\.length$', expr):
        return True

    # Arithmetic / comparison / conditional operators mean the value is not
    # a direct variable reference
    if any(op in expr for op in (' + ', ' - ', ' * ', ' / ', ' ? ', ' : ', ' === ', ' !== ', ' == ', ' != ')):
        return True

    # Known-safe sanitization function
    for func in _SAFE_FUNCS:
        if expr.startswith(func + '('):
            return True

    # Any function call at all - the developer is applying some transformation
    if re.search(r'\w\s*\(', expr):
        return True

    # Bare identifier (``varName``) or property access (``obj.prop``) - flag
    return False


def _innerhtml_is_unsafe(block: str) -> bool:
    """
    Analyse a (possibly multiline) ``innerHTML = ...`` assignment block.

    Returns True only when there is evidence of unsanitized data interpolation.

    Safe patterns (return False):
    - Quoted string literals  e.g.  innerHTML = '<div>static</div>'
    - Template literals with no ${}  e.g.  innerHTML = `<svg>...</svg>`
    - Template literals where every ${} uses a known-safe or any function call
    - Ternary expressions where no ${} appears anywhere
    """
    m = re.search(r'innerHTML\s*=\s*([\s\S]*)', block)
    if not m:
        return False
    rhs = m.group(1).strip().rstrip(';').strip()
    if not rhs:
        return False

    # ── quoted string literal ─────────────────────────────────────────────────
    # JS string literals ('' or "") cannot contain variable interpolation.
    # Only flag if there is a concatenation operator after a closing quote.
    if rhs[0] in ("'", '"'):
        return bool(re.search(r"['\"]\s*\+", rhs))

    # ── template literal ──────────────────────────────────────────────────────
    if rhs[0] == '`':
        if '${' not in rhs:
            return False
        return any(
            not _is_safe_interpolation(e)
            for e in _INTERP_RE.findall(rhs)
        )

    # ── no template interpolation anywhere in the block ───────────────────────
    # Handles ternary/conditional expressions whose branches are all literals,
    # e.g.  innerHTML = model === 'x' ? '⚡ Ultra' : `<svg>...</svg>`
    if '${' not in block:
        if '?' in rhs:
            return False  # ternary with literal branches
        # Bare variable assignment or other non-literal expression
        return True

    # Has ${} but rhs doesn't open with a backtick - flag conservatively
    return True


class XSSAnalyzer(BaseAnalyzer):
    supported_extensions = (".js", ".ts", ".jsx", ".tsx", ".html", ".php", ".py")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        # XSS-001: smart innerHTML check (handles multiline template literals)
        findings.extend(self._check_innerhtml(file_path, lines, repo_url))

        # XSS-002 to XSS-007: simple per-line regex rules
        for rule_id, pattern, description, severity in _SIMPLE_RULES:
            if rule_id in _JS_HTML_ONLY and not file_path.endswith(_JS_HTML_EXTS):
                continue
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            vuln_type=VulnType.XSS,
                            severity=severity,
                            file_path=file_path,
                            line_number=lineno,
                            line_content=line.strip(),
                            description=description,
                            rule_id=rule_id,
                            repo_url=repo_url,
                            snippet=self._extract_snippet(lines, lineno),
                        )
                    )

        # XSS-008: PHP 1-hop taint analysis ($_GET/$_POST → $var → echo)
        if file_path.endswith(".php"):
            findings.extend(self._check_php_taint(file_path, lines, repo_url))

        return findings

    def _check_innerhtml(
        self, file_path: str, lines: list[str], repo_url: str
    ) -> list[Finding]:
        # innerHTML is a DOM API — not applicable to Python source files.
        # Guarding here prevents false positives from docstrings that mention innerHTML.
        if not file_path.endswith(_JS_HTML_EXTS + (".php",)):
            return []
        findings: list[Finding] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if not self._is_comment(line) and 'innerHTML' in line and re.search(r'innerHTML\s*=', line):
                lineno = i + 1
                block = self._collect_block(lines, i)
                if _innerhtml_is_unsafe(block):
                    findings.append(Finding(
                        vuln_type=VulnType.XSS,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line.strip(),
                        description=(
                            "Direct innerHTML assignment - user data written without sanitization"
                        ),
                        rule_id="XSS-001",
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))
            i += 1
        return findings

    def _collect_block(self, lines: list[str], start: int) -> str:
        """
        Return the full assignment text for the innerHTML on ``lines[start]``.

        If the RHS opens an unclosed template literal (multiline template),
        collect subsequent lines until the closing backtick.
        """
        line = lines[start]
        parts = re.split(r'innerHTML\s*=\s*', line, maxsplit=1)
        rhs_start = parts[1].lstrip() if len(parts) > 1 else ''

        # Multiline template: exactly one backtick on this line (the opening one)
        if rhs_start.startswith('`') and rhs_start.count('`') == 1:
            block = line
            for j in range(start + 1, len(lines)):
                block += '\n' + lines[j]
                if '`' in lines[j]:
                    break
            return block

        return line

    def _check_php_taint(
        self, file_path: str, lines: list[str], repo_url: str
    ) -> list[Finding]:
        """PHP XSS 1-hop taint: detect $_GET/$_POST → $var → echo $var.

        Pass 1: collect variables assigned directly from superglobals and not
                immediately wrapped in an HTML-sanitizing function.
        Pass 2: report echo/print statements that output a tainted variable
                without going through a sanitizer (XSS-005 already covers
                direct superglobal echoes; we skip those here).
        """
        # ── Pass 1: build tainted variable map ──────────────────────────────
        tainted: dict[str, int] = {}   # var_name → assignment line number

        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            m = _PHP_ASSIGN_RE.match(line)
            if not m:
                continue
            var_name, rhs = m.group(1), m.group(2).strip()

            if _PHP_SUPERGLOBALS_RE.search(rhs):
                if _PHP_XSS_CLEAN_RE.match(rhs):
                    # e.g. $safe = htmlspecialchars($_GET['x']) — not tainted
                    tainted.pop(var_name, None)
                else:
                    tainted[var_name] = lineno
            elif var_name in tainted and _PHP_XSS_CLEAN_RE.match(rhs):
                # Variable re-sanitized after being tainted: $v = htmlentities($v)
                tainted.pop(var_name, None)

        if not tainted:
            return []

        # ── Pass 2: find echo/print that outputs a tainted variable ──────────
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            m = _PHP_ECHO_RE.match(line)
            if not m:
                continue
            expr = m.group(1).rstrip("; \t")

            # Skip direct superglobal echo — already caught by XSS-005
            if _PHP_SUPERGLOBALS_RE.search(expr):
                continue

            for var_name, src_line in tainted.items():
                # Match $varname as a standalone token (not part of a longer name)
                if re.search(r"\$" + re.escape(var_name) + r"\b", expr):
                    findings.append(Finding(
                        vuln_type=VulnType.XSS,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=line.strip(),
                        description=(
                            f"${var_name} was assigned from user input "
                            f"($_GET/$_POST) on line {src_line} and echoed "
                            f"without HTML encoding — use htmlspecialchars()"
                        ),
                        rule_id="XSS-008",
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))
                    break  # one finding per sink line is enough

        return findings
