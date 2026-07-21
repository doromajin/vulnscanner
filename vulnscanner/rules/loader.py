"""Load and validate custom rules from YAML files."""
from __future__ import annotations

import glob as _glob
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from vulnscanner.models import Severity, VulnType

# $VARNAME placeholder → regex wildcard
_PLACEHOLDER_RE = re.compile(r'\$[A-Z_][A-Z0-9_]*')

# language name → file extensions
LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python":     (".py",),
    "java":       (".java",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "go":         (".go",),
    "ruby":       (".rb",),
    "php":        (".php",),
    "kotlin":     (".kt", ".kts"),
    "swift":      (".swift",),
    "csharp":     (".cs",),
    "cpp":        (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"),
    "html":       (".html", ".htm"),
    "yaml":       (".yml", ".yaml"),
    "terraform":  (".tf",),
}

_VALID_SEVERITIES = {s.value for s in Severity}
_VALID_VULN_TYPES = {v.name for v in VulnType}


@dataclass
class CustomRule:
    id: str
    message: str
    severity: Severity
    vuln_type: VulnType
    languages: list[str]           # e.g. ["python", "java"]
    extensions: tuple[str, ...]    # derived from languages
    pattern: Optional[str] = None  # $X wildcard pattern
    regex: Optional[str] = None    # raw regex (alternative to pattern)
    cwe: Optional[int] = None
    source_file: str = ""

    # compiled regex — populated by loader, not stored in YAML
    _compiled: re.Pattern = field(default=None, init=False, repr=False)

    def compile(self) -> None:
        if self._compiled is not None:
            return
        if self.regex:
            self._compiled = re.compile(self.regex)
        elif self.pattern:
            self._compiled = _pattern_to_regex(self.pattern)
        else:
            raise ValueError(f"Rule {self.id}: must specify 'pattern' or 'regex'")

    def matches(self, line: str) -> bool:
        if self._compiled is None:
            self.compile()
        return bool(self._compiled.search(line))

    def supports_extension(self, ext: str) -> bool:
        return ext in self.extensions


def _pattern_to_regex(pattern: str) -> re.Pattern:
    """Convert a $X wildcard pattern to a compiled regex.

    Each $VARNAME placeholder becomes a non-greedy wildcard that matches
    any non-newline sequence (including nothing).
    Example: "os.system($X)" → r"os\\.system\\([^\\n]*?\\)"
    """
    parts = _PLACEHOLDER_RE.split(pattern)
    escaped = [re.escape(p) for p in parts]
    # Join escaped parts with a wildcard that matches any non-newline content
    return re.compile(r'[^\n]*?'.join(escaped))


def _parse_rule(raw: dict, source_file: str) -> CustomRule:
    """Parse a single rule dict from YAML."""
    rule_id = str(raw.get("id", "")).strip()
    if not rule_id:
        raise ValueError(f"Rule missing 'id' in {source_file}")

    message = str(raw.get("message", raw.get("msg", ""))).strip()
    if not message:
        raise ValueError(f"Rule {rule_id}: missing 'message'")

    # severity
    sev_raw = str(raw.get("severity", "MEDIUM")).upper()
    if sev_raw not in _VALID_SEVERITIES:
        raise ValueError(
            f"Rule {rule_id}: invalid severity '{sev_raw}'. "
            f"Valid values: {sorted(_VALID_SEVERITIES)}"
        )
    severity = Severity(sev_raw)

    # vuln_type — accepts enum key (COMMAND_INJECTION) or a display name substring
    vt_raw = str(raw.get("vuln_type", "COMMAND_INJECTION")).upper().replace(" ", "_").replace("-", "_")
    if vt_raw not in _VALID_VULN_TYPES:
        # Try fuzzy match on enum key prefixes
        matches = [k for k in _VALID_VULN_TYPES if k.startswith(vt_raw[:4])]
        if len(matches) == 1:
            vt_raw = matches[0]
        else:
            raise ValueError(
                f"Rule {rule_id}: unknown vuln_type '{vt_raw}'. "
                f"Valid values: {sorted(_VALID_VULN_TYPES)}"
            )
    vuln_type = VulnType[vt_raw]

    # languages
    raw_langs = raw.get("languages", list(LANG_EXTENSIONS.keys()))
    if isinstance(raw_langs, str):
        raw_langs = [raw_langs]
    languages = [str(l).lower() for l in raw_langs]
    unknown = [l for l in languages if l not in LANG_EXTENSIONS]
    if unknown:
        raise ValueError(
            f"Rule {rule_id}: unknown language(s) {unknown}. "
            f"Valid: {sorted(LANG_EXTENSIONS)}"
        )
    extensions: tuple[str, ...] = tuple(
        ext for lang in languages for ext in LANG_EXTENSIONS[lang]
    )

    pattern = raw.get("pattern")
    regex = raw.get("regex")
    if not pattern and not regex:
        raise ValueError(f"Rule {rule_id}: must specify 'pattern' or 'regex'")

    cwe_raw = raw.get("cwe")
    cwe = int(cwe_raw) if cwe_raw is not None else None

    rule = CustomRule(
        id=rule_id,
        message=message,
        severity=severity,
        vuln_type=vuln_type,
        languages=languages,
        extensions=extensions,
        pattern=str(pattern) if pattern else None,
        regex=str(regex) if regex else None,
        cwe=cwe,
        source_file=source_file,
    )
    rule.compile()
    return rule


def load_rules_from_file(path: str) -> list[CustomRule]:
    """Load all rules from a single YAML file."""
    try:
        import yaml  # pyyaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for custom rules: pip install pyyaml"
        )

    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return []

    # Support both a bare list and a dict with a 'rules' key
    if isinstance(data, dict):
        data = data.get("rules", [])
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a YAML list (or 'rules' key) at top level")

    rules: list[CustomRule] = []
    errors: list[str] = []
    for i, raw in enumerate(data):
        try:
            rules.append(_parse_rule(raw, source_file=path))
        except (ValueError, TypeError, re.error) as exc:
            errors.append(f"  [{path}#{i}] {exc}")

    if errors:
        import warnings
        warnings.warn(
            f"Custom rule loading errors ({len(errors)}):\n" + "\n".join(errors),
            stacklevel=2,
        )
    return rules


def load_rules(paths: list[str]) -> list[CustomRule]:
    """Load rules from a list of file paths or glob patterns.

    Each element of *paths* may be:
    - an exact file path ending in .yaml / .yml
    - a glob pattern (e.g. "rules/*.yaml")
    - a directory path (loads all *.yaml and *.yml files within)
    """
    rules: list[CustomRule] = []
    seen_files: set[str] = set()

    for path_or_glob in paths:
        p = Path(path_or_glob)
        if p.is_dir():
            candidates = list(p.glob("**/*.yaml")) + list(p.glob("**/*.yml"))
        else:
            candidates = [Path(f) for f in _glob.glob(path_or_glob, recursive=True)]

        for candidate in candidates:
            abs_path = str(candidate.resolve())
            if abs_path in seen_files:
                continue
            seen_files.add(abs_path)
            try:
                rules.extend(load_rules_from_file(str(candidate)))
            except Exception as exc:
                import warnings
                warnings.warn(f"Failed to load {candidate}: {exc}", stacklevel=2)

    return rules
