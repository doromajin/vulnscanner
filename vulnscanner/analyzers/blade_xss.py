"""Laravel Blade: unescaped output `{!! ... !!}`.

`{{ }}` HTML-escapes its value; `{!! !!}` prints it raw, so whatever reaches it must already be
trusted markup. Rules:

BLADE-XSS-001  `{!! !!}` printing request data (request(), $request, old(), superglobals) - HIGH
BLADE-XSS-002  `{!! !!}` printing a variable that nothing in the template shows to be sanitised - LOW,
               a review pointer (applications legitimately render stored HTML this way)
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RAW_ECHO_RE = re.compile(r"\{!!\s*(.+?)\s*!!\}", re.DOTALL)
_COMMENT_RE = re.compile(r"\{\{--.*?--\}\}", re.DOTALL)

# Request-derived expressions.
_REQUEST_RE = re.compile(
    r"\brequest\s*\(|\$request\b|\bRequest::|\bold\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"
    r"|\bInput::|\bsession\s*\(\s*['\"]_old_input"
)
# Calls whose result is markup the framework or an escaper produced.
_SAFE_CALL_RE = re.compile(
    r"\b(?:e|htmlspecialchars|htmlentities|strip_tags|clean|purify|sanitize\w*|nl2br|"
    r"__|trans|trans_choice|route|url|asset|secure_asset|secure_url|action|mix|vite|csrf_field|"
    r"csrf_token|method_field|json_encode|json|markdown|render|links|toHtml|toJson)\s*\("
    r"|Purifier::|Str::(?:markdown|inlineMarkdown|sanitize)|Js::from|\$slot\b|\$errors\b"
    r"|\$attributes\b|\$__env\b|->(?:render|links|toHtml|withQueryString)\b|\$(?:paginator|links)\b"
    r"|\bhtmlentities\b|@json",
    re.IGNORECASE,
)
# Helpers that escape the values they receive (Laravel Collective forms, Html builders).
_ESCAPING_HELPER_RE = re.compile(r"^\s*\(?\s*(?:Form|Html|Collective)::|^\s*(?:link_to|form_|trans)\w*\s*\(", re.IGNORECASE)
# Conditions and comparisons print literals, not the request data they test.
_CONDITIONAL_RE = re.compile(r"\?(?!->|\?)|===?|!==?|&&|\|\||->\s*(?:is|routeIs|has|filled|isMethod|boolean)\s*\(")
# Variable names that usually hold user-authored content.
_CONTENT_NAME_RE = re.compile(
    r"body|content|description|comment|message|text|html|bio|note|summary|excerpt|title|name|"
    r"review|post|reply|about|markup|snippet|signature",
    re.IGNORECASE,
)
# A single variable / property / method chain with no sanitising wrapper.
_PLAIN_VALUE_RE = re.compile(r"^\$[A-Za-z_]\w*(?:\s*(?:->|\?->|::)\s*\$?[A-Za-z_]\w*(?:\([^()]*\))?|\[[^\]]*\])*$")


class BladeXSSAnalyzer(BaseAnalyzer):
    supported_extensions = (".blade.php",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if "{!!" not in content:
            return []
        stripped = _COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), content)
        lines = content.splitlines()
        findings: list[Finding] = []
        for m in _RAW_ECHO_RE.finditer(stripped):
            expr = m.group(1)
            line_no = stripped.count("\n", 0, m.start()) + 1
            if _SAFE_CALL_RE.search(expr) or _ESCAPING_HELPER_RE.search(expr):
                continue
            if _REQUEST_RE.search(expr):
                if _CONDITIONAL_RE.search(expr):
                    continue
                rule_id, severity = "BLADE-XSS-001", Severity.HIGH
                desc = (f"Request data printed unescaped by {{!! {expr[:60]} !!}} — reflected XSS; "
                        "use {{ }} or sanitise it first")
            elif _PLAIN_VALUE_RE.match(expr) and _CONTENT_NAME_RE.search(expr):
                rule_id, severity = "BLADE-XSS-002", Severity.LOW
                desc = (f"[needs_review] {{!! {expr[:60]} !!}} prints a value without HTML escaping — "
                        "stored XSS if the value can contain user input; sanitise (e.g. HTMLPurifier) or use {{ }}")
            else:
                continue
            findings.append(Finding(
                vuln_type=VulnType.XSS,
                severity=severity,
                file_path=file_path,
                line_number=line_no,
                line_content=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else expr,
                description=desc,
                rule_id=rule_id,
                repo_url=repo_url,
                snippet=self._extract_snippet(lines, line_no),
            ))
        return findings
