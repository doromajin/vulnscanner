"""Text-level helpers for Java XXE rules: the method a line belongs to and whether the parser or factory
configured there is hardened against DOCTYPE / external entities.

Shared by the AST analyzer (JAST-XXE-001/002) and the regex fallback in java_analyzer so that a secure
configuration suppresses both.  Strict by design: a feature set to the unsafe value never counts, and a
single partial setting (XInclude off, entity-reference expansion off) is not enough on its own.
"""
from __future__ import annotations

import re

_METHOD_HEADER = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|synchronized|abstract|default)\s+)*"
    r"(?:<[^>]+>\s*)?[\w.<>\[\],?\s]+?\s+\w+\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*(?://.*)?$"
)
_NOT_A_METHOD = re.compile(r"^\s*(?:if|for|while|switch|catch|synchronized|else|try|return|new|do)\b")
_CALL = re.compile(
    r"(\w+)\s*\.\s*(setFeature|setProperty|setAttribute|setExpandEntityReferences|setXIncludeAware)\s*\(([^;]*?)\)\s*;"
)
_DERIVED = re.compile(r"(\w+)\s*=\s*(\w+)\s*\.")
_ENTITY_FEATURES = ("external-general-entities", "external-parameter-entities")


def method_region(lines: list[str], lineno: int) -> tuple[int, int]:
    """0-based [start, end) of the method containing 1-based `lineno` (whole file when unknown)."""
    idx = min(max(lineno - 1, 0), len(lines) - 1) if lines else 0
    start = 0
    for i in range(idx, -1, -1):
        ln = lines[i]
        if _METHOD_HEADER.match(ln) and not _NOT_A_METHOD.match(ln) and not ln.rstrip().endswith(";"):
            start = i
            break
    end = len(lines)
    for j in range(idx + 1, len(lines)):
        ln = lines[j]
        if _METHOD_HEADER.match(ln) and not _NOT_A_METHOD.match(ln) and not ln.strip().startswith(("//", "*")):
            end = j
            break
    return start, end


def _split_args(arg_text: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in arg_text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return out


def _strip_comments(lines: list[str]) -> str:
    kept = []
    for ln in lines:
        s = ln.strip()
        if s.startswith(("//", "*", "/*")):
            kept.append("")
            continue
        kept.append(re.sub(r"\s//.*$", "", ln))
    return "\n".join(kept)


def is_hardened(lines: list[str], lineno: int, var: str | None = None, whole_file: bool = False) -> bool:
    """True when the method of `lineno` (or the whole file) disables DOCTYPE / external entities on `var`."""
    if whole_file:
        region = lines
    else:
        s, e = method_region(lines, lineno)
        region = lines[s:e]
    text = _strip_comments(region)
    # brace depth at the start of every line: a setting made inside an `if (...) { }` that has closed
    # before the parse/newInstance line is conditional, so it cannot be relied on.
    depth_at, d = [], 0
    for ln in text.split(chr(10)):
        depth_at.append(d)
        d += ln.count("{") - ln.count("}")
    use_line = min(max(lineno - 1 - (0 if whole_file else method_region(lines, lineno)[0]), 0), len(depth_at) - 1)
    ref_depth = depth_at[use_line] if depth_at else 0
    quals = {var} if var is not None else None
    if quals is not None:
        # objects derived from the factory/parser (spf -> saxParser -> xmlReader) carry its configuration
        for _ in range(3):
            for m in _DERIVED.finditer(text):
                if m.group(2) in quals:
                    quals.add(m.group(1))
    doctype = secure_proc = gen_off = param_off = dtd_off = False
    stax_off = False
    for m in _CALL.finditer(text):
        qual, meth, raw = m.group(1), m.group(2), m.group(3)
        if not whole_file and depth_at[text.count(chr(10), 0, m.start())] > ref_depth:
            continue
        if quals is not None and qual not in quals:
            continue
        args = _split_args(raw)
        if meth not in ("setFeature", "setProperty", "setAttribute") or len(args) < 2:
            continue
        name, val = args[0], args[1]
        if meth == "setFeature":
            if "disallow-doctype-decl" in name and val == "true":
                doctype = True
            elif "FEATURE_SECURE_PROCESSING" in name or name.strip('"').endswith("feature/secure-processing"):
                secure_proc = secure_proc or val == "true"
            elif "external-general-entities" in name and val == "false":
                gen_off = True
            elif "external-parameter-entities" in name and val == "false":
                param_off = True
        else:
            if ("ACCESS_EXTERNAL_DTD" in name or name.strip('"').endswith("accessExternalDTD")) and val == '""':
                dtd_off = True
            elif ("IS_SUPPORTING_EXTERNAL_ENTITIES" in name or name.strip('"').endswith("isSupportingExternalEntities")
                  or name.strip('"').endswith("supportDTD") or name.strip() == "XMLInputFactory.SUPPORT_DTD") \
                    and val == "false":
                stax_off = True
    return doctype or dtd_off or stax_off or (gen_off and param_off) or (secure_proc and gen_off)


_VAR_DECL = re.compile(r"(?:^|[\s(,;])(?:[\w.<>\[\]]+\s+)?(\w+)\s*=\s*[\w.]*\.\s*(?:newInstance|newFactory)\s*\(")


def factory_var(line: str) -> str | None:
    m = _VAR_DECL.search(line)
    return m.group(1) if m else None
