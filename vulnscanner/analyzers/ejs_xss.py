"""EJS templates: unescaped output `<%- expr %>`.

`<%= %>` HTML-escapes its value; `<%- %>` prints it raw, so whatever reaches it must already be
trusted markup. Rules:

EJS-XSS-001  `<%- %>` printing a value that nothing shows to be sanitised - HIGH (request data,
             loop values, any non-literal expression); MEDIUM for obvious server-side constants;
             LOW (needs_review) behind an encoder/sanitiser, for `JSON.stringify`, and for the
             layout idiom `<%- body %>`.
`<%- include(...) %>` and literals are template plumbing and never reported.
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_COMMENT_RE = re.compile(r"<%#.*?%>", re.DOTALL)
_RAW_ECHO_RE = re.compile(r"<%-\s*(.*?)\s*-?%>", re.DOTALL)

_INCLUDE_RE = re.compile(r"^(?:include|partial|await\s+include)\s*\(")
_LITERAL_RE = re.compile(r"""^(?:'[^']*'|"[^"]*"|`[^`$]*`|-?\d+(?:\.\d+)?|true|false|null|undefined)$""")
_LAYOUT_RE = re.compile(r"^(?:body|contents?|yield|layoutBody|_layoutContent)$")
_ENCODER_RE = re.compile(
    r"\b(?:escape\w*|encodeURI(?:Component)?|encodeHTML|encodeForHTML|sanitize\w*|DOMPurify|xss|"
    r"purify|clean|stripTags|strip_tags|htmlEscape|he\.encode|_\.escape)\b\s*[.(]",
    re.IGNORECASE,
)
_JSON_RE = re.compile(r"^JSON\.stringify\s*\(")
_CONSTANT_RE = re.compile(
    r"^(?:config|settings|env|process\.env|version|appName|csrfToken|_csrf|nonce|assetUrl|baseUrl|"
    r"staticUrl|locals\.(?:config|settings))\b|^[A-Z][A-Z0-9_]+$",
)


class EjsXSSAnalyzer(BaseAnalyzer):
    supported_extensions = (".ejs",)

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if "<%-" not in content:
            return []
        stripped = _COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), content)
        lines = content.splitlines()
        findings: list[Finding] = []
        for m in _RAW_ECHO_RE.finditer(stripped):
            expr = m.group(1).strip()
            if not expr or _INCLUDE_RE.match(expr) or _LITERAL_RE.match(expr):
                continue
            line_no = stripped.count("\n", 0, m.start()) + 1
            if _ENCODER_RE.search(expr):
                severity = Severity.LOW
                desc = (f"[needs_review] <%- {expr[:60]} %> prints the result of an encoder/sanitiser "
                        "unescaped — confirm it encodes for the HTML context")
            elif _JSON_RE.match(expr) or _LAYOUT_RE.match(expr):
                severity = Severity.LOW
                desc = (f"[needs_review] <%- {expr[:60]} %> prints unescaped (layout/JSON idiom) — safe only "
                        "when the content is trusted; JSON inside <script> still needs </script> escaping")
            elif _CONSTANT_RE.match(expr):
                severity = Severity.MEDIUM
                desc = f"<%- {expr[:60]} %> prints a server-side value without HTML escaping; use <%= %>"
            else:
                severity = Severity.HIGH
                desc = (f"<%- {expr[:60]} %> prints a value without HTML escaping — reflected/stored XSS "
                        "if it can hold user input; use <%= %> or sanitise it")
            findings.append(Finding(
                vuln_type=VulnType.XSS,
                severity=severity,
                file_path=file_path,
                line_number=line_no,
                line_content=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else expr,
                description=desc,
                rule_id="EJS-XSS-001",
                repo_url=repo_url,
                snippet=self._extract_snippet(lines, line_no),
            ))
        return findings
