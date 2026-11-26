"""ASP.NET Razor (`.cshtml`, `.razor`): output that bypasses Razor's automatic HTML encoding.

`@expr` is HTML-encoded; `Html.Raw(expr)` and `new HtmlString(expr)` print their argument as markup, so
whatever reaches them must already be trusted. Rules:

CSHTML-XSS-001  raw output of request/view data or a model/loop value (stored or reflected XSS) - HIGH
CSHTML-XSS-002  raw output of a value that is encoded or otherwise not user-shaped - LOW, a review pointer
CSHTML-XSS-003  `Html.Raw(Json.Serialize(...))` inside <script> (the data-embedding idiom) - MEDIUM
CSHTML-XSS-004  raw output of a local member that is not shown to be user content (style.Tag) - LOW

Localised / configuration text (`Localizer[..]`, `Configuration[..]`) is not reported at all: it is server-side
content and made up 35 of the 40 findings on a clean CMS (piranha.core).
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RAZOR_COMMENT_RE = re.compile(r"@\*.*?\*@", re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
# `@@` is a literal at-sign, so `@@Html.Raw(x)` is documentation text, not a call.
_SINK_RE = re.compile(r"(?<![\w@.])@?(?:Html\.Raw|(?:new\s+)?(?:Microsoft\.AspNetCore\.Html\.)?HtmlString)\s*\(")
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.DOTALL | re.IGNORECASE)

_ENCODED_RE = re.compile(
    r"\b(?:Html\.Encode|HtmlEncode|Encoder\.\w*Encode|Url\.Encode|UrlEncode|JavaScriptEncode|JsonEncode)\s*\("
    r"|\b\w*[Ss]anitiz\w*\s*[.(]|\bMarkdown\w*\.\w+\s*\("
)
_JSON_RE = re.compile(r"\b(?:Json\.Serialize|JsonSerializer\.Serialize|JsonConvert\.SerializeObject|Json\.Encode)\s*\(")
_CONSTANT_RE = re.compile(
    r"\b(?:Localizer|_?localizer|L|SR|Resources?|_?config(?:uration)?|Config|Options|Settings|AppSettings)\s*[\[.]"
    r"|\b(?:Url|Html)\.(?:Action|Content|RouteUrl|Partial|AntiForgeryToken|Label|Display\w*)\s*\("
    r"|\bstring\.Empty\b|\bnull\b|\bViewLocalizer\b|\bSharedLocalizer\b",
    re.IGNORECASE,
)
_REQUEST_RE = re.compile(
    r"\bRequest\.|\bContext\.Request\b|\bHttpContext\.Request\b|\bQuery\s*\[|\bForm\s*\[|"
    r"\bViewData\s*\[|\bViewBag\.|\bTempData\s*\[|\bRouteData\b|\bCookies\s*\["
)
_MODEL_RE = re.compile(r"\bModel\b")
_LOCAL_RE = re.compile(r"\b[a-z_]\w*\.[A-Z]\w*")  # a loop/local value such as `item.Text`
# Member names that usually hold user-authored text (as opposed to editor/config metadata).
_CONTENT_NAME_RE = re.compile(
    r"text|content|body|comment|message|desc|title|name|html|bio|note|summary|review|post|reply|about|markup|"
    r"query|input|value|search", re.IGNORECASE)
_LITERAL_RE = re.compile(r'^\s*(?:\$?@?"(?:[^"\\]|\\.|"")*"\s*(?:\+\s*)?)+$', re.DOTALL)


def _blank(m: re.Match) -> str:
    return re.sub(r"[^\n]", " ", m.group(0))


def _balanced_args(text: str, open_idx: int) -> str | None:
    """Return the text between the parenthesis at *open_idx* and its match (string literals aware)."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return None


class CshtmlXSSAnalyzer(BaseAnalyzer):
    supported_extensions = (".cshtml", ".razor")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if "Html.Raw" not in content and "HtmlString" not in content:
            return []
        text = _HTML_COMMENT_RE.sub(_blank, _RAZOR_COMMENT_RE.sub(_blank, content))
        script_spans = [(m.start(), m.end()) for m in _SCRIPT_RE.finditer(text)]
        lines = content.splitlines()
        findings: list[Finding] = []
        for m in _SINK_RE.finditer(text):
            if m.start() > 0 and text[m.start() - 1] == "@":  # `@@Html.Raw(`: an escaped at-sign
                continue
            args = _balanced_args(text, m.end() - 1)
            if args is None:
                continue
            expr = re.sub(r"\s+", " ", args).strip()
            if not expr or _LITERAL_RE.match(expr):
                continue
            in_script = any(s <= m.start() < e for s, e in script_spans)
            if _ENCODED_RE.search(expr):
                rule_id, severity, why = "CSHTML-XSS-002", Severity.LOW, "value passes through an encoder/sanitiser"
            elif _JSON_RE.search(expr):
                if in_script:
                    rule_id, severity, why = "CSHTML-XSS-003", Severity.MEDIUM, "serialised data embedded in <script>"
                else:
                    rule_id, severity, why = "CSHTML-XSS-002", Severity.LOW, "serialised data"
            elif _REQUEST_RE.search(expr):
                rule_id, severity, why = "CSHTML-XSS-001", Severity.HIGH, "request/view data is printed unencoded"
            elif _CONSTANT_RE.search(expr):
                continue  # localised / configuration text is server-side content: reporting it only adds noise
            elif _MODEL_RE.search(expr) or (_LOCAL_RE.search(expr) and _CONTENT_NAME_RE.search(expr)):
                rule_id, severity, why = "CSHTML-XSS-001", Severity.HIGH, "model/content value is printed unencoded"
            elif _LOCAL_RE.search(expr):
                rule_id, severity, why = "CSHTML-XSS-004", Severity.LOW, "local value not shown to be user-controlled"
            else:
                rule_id, severity, why = "CSHTML-XSS-002", Severity.LOW, "value not shown to be user-controlled"
            line_no = text.count("\n", 0, m.start()) + 1
            desc = f"Html.Raw/HtmlString({expr[:60]}) bypasses Razor encoding: {why}"
            if severity is Severity.LOW:
                desc = "[needs_review] " + desc
            else:
                desc += " - stored/reflected XSS; drop Html.Raw or sanitise the value"
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
