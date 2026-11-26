"""MyBatis `${...}` string substitution (CWE-89).

`#{name}` is bound as a prepared-statement parameter; `${name}` is pasted into the SQL text.  Reported:

MYBATIS-001  `${...}` in the text of a statement in a mapper XML file (`<mapper namespace=`)
MYBATIS-002  `${...}` in the SQL string of a `@Select/@Update/@Delete/@Insert` annotation

HIGH when the substituted value is a parameter of the annotated method, or sits where it cannot be bound
anyway (ORDER BY / GROUP BY / LIKE / table name); MEDIUM otherwise.  XML comments, element attributes
(`<if test="...">`, `<foreach collection=...>`) and Java comments are not sinks.
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_TAG_RE = re.compile(r"</?[A-Za-z][\w:.-]*(?:\s[^<>]*)?/?>")
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_SUBST_RE = re.compile(r"\$\{\s*([^}]*?)\s*\}")
_ANNOT_RE = re.compile(r"@(?:Select|Update|Delete|Insert)\s*\(")
_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_JAVA_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_POSITION_RE = re.compile(
    r"(?:order\s+by|group\s+by)\s*$|(?:\blike\s*|\bfrom\s+|\binto\s+|\bupdate\s+|\bjoin\s+)['\"%\s]*$",
    re.IGNORECASE)


def _blank(m: "re.Match") -> str:
    return re.sub(r"[^\n]", " ", m.group(0))


def _position_is_unbindable(text: str, start: int) -> bool:
    before = text[max(0, start - 60):start]
    return bool(_POSITION_RE.search(before.replace("'%", " ").replace("%'", " ")))


class MyBatisAnalyzer(BaseAnalyzer):
    supported_extensions = (".xml", ".java")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if "${" not in content:
            return []
        if file_path.endswith(".xml"):
            return self._xml(file_path, content, repo_url)
        return self._java(file_path, content, repo_url)

    def _finding(self, lines, file_path, repo_url, ln, rule, sev, desc) -> Finding:
        return Finding(
            vuln_type=VulnType.SQL_INJECTION, severity=sev, file_path=file_path, line_number=ln,
            line_content=lines[ln - 1].strip() if 0 < ln <= len(lines) else "", description=desc,
            rule_id=rule, repo_url=repo_url, snippet=self._extract_snippet(lines, ln))

    def _xml(self, file_path, content, repo_url):
        if "<mapper" not in content or "namespace" not in content:
            return []
        text = _XML_COMMENT_RE.sub(_blank, content)
        text = text.replace("<![CDATA[", " " * 9).replace("]]>", " " * 3)
        text = _TAG_RE.sub(_blank, text)
        lines = content.splitlines()
        out = []
        for m in _SUBST_RE.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            sev = Severity.HIGH if _position_is_unbindable(text, m.start()) else Severity.MEDIUM
            out.append(self._finding(
                lines, file_path, repo_url, ln, "MYBATIS-001", sev,
                f"MyBatis ${{{m.group(1)}}} substitutes the value into the SQL text - SQL injection when it is "
                "user-controlled; use #{...}, or validate against an allowlist for ORDER BY / table names"))
        return out

    def _java(self, file_path, content, repo_url):
        if not _ANNOT_RE.search(content):
            return []
        masked = _JAVA_COMMENT_RE.sub(_blank, content)
        lines = content.splitlines()
        out = []
        for am in _ANNOT_RE.finditer(masked):
            depth, i, in_str = 1, am.end(), False
            while i < len(masked) and depth:
                c = masked[i]
                if in_str:
                    if c == "\\":
                        i += 1
                    elif c == '"':
                        in_str = False
                elif c == '"':
                    in_str = True
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                i += 1
            body = masked[am.end():i - 1]
            sql = " ".join(s for s in _STR_RE.findall(body))
            if "${" not in sql:
                continue
            # parameter names of the annotated method
            tail = masked[i:i + 600]
            end = min([k for k in (tail.find(";"), tail.find("{")) if k >= 0] or [len(tail)])
            sig = tail[:end]
            params = set(re.findall(r"@Param\s*\(\s*(?:value\s*=\s*)?\"(\w+)\"\s*\)", sig))
            params |= set(re.findall(r"(\w+)\s*(?=[,)])", sig))
            for sm in _SUBST_RE.finditer(sql):
                name = sm.group(1).split(".")[0].split("[")[0].strip()
                high = name in params or _position_is_unbindable(sql, sm.start())
                # report on the line of the substitution inside the annotation
                pos = masked.find("${", am.end())
                ln = masked.count("\n", 0, pos if pos >= 0 else am.start()) + 1
                out.append(self._finding(
                    lines, file_path, repo_url, ln, "MYBATIS-002",
                    Severity.HIGH if high else Severity.MEDIUM,
                    f"MyBatis annotation SQL uses ${{{sm.group(1)}}} (string substitution) - SQL injection when "
                    "the value is user-controlled; use #{...}"))
                break
        return out
