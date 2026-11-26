import re
import threading

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

# ── Simple per-line rules (XSS-002 to XSS-007) ────────────────────────────────

# DOM manipulation APIs that only exist in JavaScript/HTML contexts.
# Restricting their rules to these extensions prevents self-reference FPs
# when their pattern strings appear inside Python source files.
_JS_HTML_EXTS = (".js", ".ts", ".jsx", ".tsx", ".html")
# Rule IDs restricted to JS/HTML only (DOM APIs absent from Python)
_JS_HTML_ONLY = frozenset({"XSS-002", "XSS-006"})
_PHP_ONLY     = frozenset({"XSS-005"})  # "echo $_GET" pattern — PHP syntax only

_SIMPLE_RULES = [
    (
        "XSS-002",
        re.compile(r'document\.write\s*\(', re.IGNORECASE),
        "document.write() with potentially unsanitized input",
        Severity.HIGH,
    ),
    (
        "XSS-003",
        re.compile(r'outerHTML\s*=\s*(?![\'"]\s*[\'"])', re.IGNORECASE),
        "Direct outerHTML assignment",
        Severity.HIGH,
    ),
    (
        "XSS-004",
        re.compile(r'\|\s*safe\b|mark_safe\s*\(|format_html\s*\(.*\+', re.IGNORECASE),
        "Template value marked safe without explicit sanitization",
        Severity.MEDIUM,
    ),
    (
        "XSS-005",
        re.compile(r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE)', re.IGNORECASE),
        "PHP direct echo of user-supplied input",
        Severity.HIGH,
    ),
    (
        "XSS-006",
        re.compile(r'insertAdjacentHTML\s*\(', re.IGNORECASE),
        "insertAdjacentHTML() - verify content is sanitized",
        Severity.MEDIUM,
    ),
    (
        "XSS-007",
        re.compile(r'eval\s*\(\s*(?:location|document\.|window\.)', re.IGNORECASE),
        "eval() with browser-controlled input",
        Severity.CRITICAL,
    ),
]

# Content guard for the simple XSS rules (XSS-002 to XSS-007)
_SIMPLE_GUARD = re.compile(
    r'document\.write|outerHTML\s*=|\|\s*safe\b|mark_safe\s*\('
    r'|format_html\s*\(|echo\s+\$_|insertAdjacentHTML\s*\('
    r'|eval\s*\(\s*(?:location|document\.|window\.)',
    re.IGNORECASE,
)

# Django / Jinja template with no HTML markup at all (notification subjects, plain-text bodies):
# `{{ x|safe }}` there only stops HTML-escaping of text, it cannot inject markup.
_HTML_TAG_RE = re.compile(r"<\s*/?\s*[A-Za-z][^<>]*>|<!--")
_FORMAT_HTML_CONCAT_RE = re.compile(r"format_html\s*\(.*\+", re.IGNORECASE)
# Template variables that the template itself defines from string literals:
#   {% cycle '' '</tr><tr>' as trtr silent %}   {% with sep="<br>" %}
# `{{ trtr|safe }}` on those cannot carry request data.
_TPL_CYCLE_AS_RE = re.compile(r"\{%-?\s*cycle\s+((?:'[^']*'|\"[^\"]*\"|\s)+?)\s+as\s+(\w+)")
_TPL_WITH_LITERAL_RE = re.compile(r"\{%-?\s*with\s+(?:\w+\s*=\s*(?:'[^']*'|\"[^\"]*\")\s*)*?(\w+)\s*=\s*(?:'[^']*'|\"[^\"]*\")")
_TPL_SAFE_VAR_RE = re.compile(r"\{\{\s*(\w+)\s*(?:\|\s*\w+(?::[^|}]*)?\s*)*\|\s*safe\b")


def _template_literal_vars(content: str) -> set[str]:
    names = {m.group(2) for m in _TPL_CYCLE_AS_RE.finditer(content)}
    names |= {m.group(1) for m in _TPL_WITH_LITERAL_RE.finditer(content)}
    return names
# Simple DOM-sink rules that, like innerHTML, only matter when the page has an attacker-controlled input
_DOM_GATED_RULES = frozenset({"XSS-002", "XSS-003", "XSS-006"})

# ── XSS-001: innerHTML smart analysis ─────────────────────────────────────────

_BLADE_ESCAPED_RE = re.compile(r"\{\{.*?\}\}", re.DOTALL)
_LITERAL_CHAIN_RE = re.compile(r"""\s*(?:(?:'[^']*'|"[^"]*")\s*\+?\s*)+;?\s*(?://.*)?""")


def _blade_literal_only(rhs: str) -> bool:
    """A Blade `{{ }}` is HTML-escaped on the server, so an innerHTML value made only of string literals and
    `{{ }}` expressions (`'<span>' + '{{ __("x") }}' + '</span>'`) carries no client data."""
    return bool(_LITERAL_CHAIN_RE.fullmatch(_BLADE_ESCAPED_RE.sub("x", rhs)))


# Browser-controlled input sources.  Keep in sync with evidence_regex in
# rules/builtin/javascript.yaml.
_DOM_SOURCE_RE = re.compile(
    r'\blocation\.(?:search|hash|href)|document\.(?:URL|documentURI|referrer|cookie)'
    r'|window\.name|URLSearchParams|postMessage'
    r'|\baddEventListener\s*\(\s*[\x22\x27]message|\bonmessage\b|\bevent\.data\b'
)

# PHP emitting a JS handler: `... b.innerHTML='<span>' . $var . '` — the RHS is a
# PHP-escaped string literal.  Only the concatenated PHP variables can carry data.
_PHP_ESCAPED_RHS_RE = re.compile(r"innerHTML\s*=\s*\\['\"]")
_PHP_CONCAT_VAR_RE = re.compile(r"\.\s*\$(\w+)")
_PHP_SANITIZED_ASSIGN = (
    r"\$%s\s*=\s*(?:\w+::)?(?:html|htmlspecialchars|htmlentities|esc_\w+|escape\w*|encode|e|h)\s*\("
)

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
    r"^\s*(?:htmlspecialchars|htmlentities|strip_tags"
    r"|esc_html|esc_attr|esc_textarea|esc_url"
    r"|wp_kses|wp_kses_post|sanitize_text_field|wp_strip_all_tags"
    r"|intval|floatval|abs)\s*\(",
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


# Lookup of a developer-authored message catalogue (this.translate('k'),
# translation.get('k'), i18n.t('k'), gettext('k'), __('k')).  The returned text
# is fixed at build time, so it carries no attacker data.
_I18N_ASSIGN = (
    r"(?:const|let|var)\s+%s\s*=\s*"
    r"(?:(?:this|[\w$]+)\.)?(?:translate|translation\.get|i18n\.t|t|gettext|ngettext|__|_)\s*\("
)
_STR_LITERAL_RE = re.compile(r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*\"""")
_BARE_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")


def _concat_vars_are_i18n(rhs: str, lines: list[str], idx: int) -> bool:
    """
    True when ``rhs`` is string literals joined by ``+`` with at least one bare
    variable, and every such variable was assigned from an i18n lookup shortly
    before line ``idx``.
    """
    rest = _STR_LITERAL_RE.sub("", rhs).rstrip().rstrip(";")
    tokens = [t.strip() for t in rest.split("+") if t.strip()]
    if not tokens or not all(_BARE_IDENT_RE.match(t) for t in tokens):
        return False
    window = "\n".join(lines[max(0, idx - 40):idx])
    return all(re.search(_I18N_ASSIGN % re.escape(t), window) for t in tokens)


_STATIC_STRING_RHS = (
    r"(?:'(?:[^'\\\n]|\\.)*'"      # 'single quoted'
    r'|"(?:[^"\\\n]|\\.)*"'        # "double quoted"
    r"|`[^`$]*`)"                  # `template literal without ${}`
)


# `name = ...` and the compound forms (`name += ...`): all of them change what `name` holds
_ASSIGN_NAME_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|\?\?|\|\||&&)?=(?![=>])"
)
# `const NAME = <literal>` that ends the statement: a `;`, or no operator continuing the expression
# (`'<b>' + name`, `'x'.repeat(n)`)
_STATIC_DEF_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*" + _STATIC_STRING_RHS
    + r"(?:\s*;|(?!\s*[-+.?\[(|&,*/%]))"
)
_static_const_local = threading.local()


def _static_string_constants(content: str) -> frozenset[str]:
    """Names assigned exactly once in *content*, to a literal without interpolation.

    Computed once per file (single linear pass) and cached for the next call on the same string:
    a bundle can hold thousands of innerHTML assignments, each of which asks this question.
    """
    cached = getattr(_static_const_local, "entry", None)
    if cached is not None and cached[0] is content:
        return cached[1]
    counts: dict[str, int] = {}
    for m in _ASSIGN_NAME_RE.finditer(content):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    names = frozenset(m.group(1) for m in _STATIC_DEF_RE.finditer(content) if counts.get(m.group(1)) == 1)
    _static_const_local.entry = (content, names)
    return names


def _is_static_string_constant(name: str, content: str) -> bool:
    """True when *name* is assigned exactly once in *content*, to a literal with no interpolation."""
    return name in _static_string_constants(content)


def _is_static_interpolation(expr: str, content: str | None) -> bool:
    """``${NAME}`` where NAME is assigned exactly once, to a plain string literal."""
    expr = expr.strip()
    return bool(content) and bool(_BARE_IDENT_RE.match(expr)) and _is_static_string_constant(expr, content)


# ── inert-value proof ─────────────────────────────────────────────────────────
# `el.innerHTML = emptyListbox` is safe when every assignment to `emptyListbox` in the file is a
# literal, a number, a counter increment, or a template/concatenation/ternary of such values
# (`this.listboxId = \`results-${this.instanceId}\``, `this.instanceId = ++counter`).  A call result
# (`location.hash.slice(1)`) or a name nobody assigns in this file (a parameter) is NOT inert.

_REF_RE = re.compile(r"(?:this\.)?[A-Za-z_$][\w$]*")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
_INCDEC_RE = re.compile(r"(?:\+\+|--)\s*(?:this\.)?[A-Za-z_$][\w$]*|(?:this\.)?[A-Za-z_$][\w$]*\s*(?:\+\+|--)")
_QUOTED_RE = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*\"""")
_MAX_INERT_DEPTH = 5
_MAX_EXPR_CHARS = 3000
_inert_local = threading.local()


def _scan_code(s: str, i: int, stop_chars: str) -> int:
    """Index of the first char in *stop_chars* at nesting depth 0 (outside strings, templates and
    brackets), scanning *s* from *i*; len(s) when there is none, -1 when the text is malformed."""
    depth = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c in "'\"":
            j = i + 1
            while j < n and s[j] != c:
                j += 2 if s[j] == "\\" else 1
                if j < n and s[j] == "\n":
                    return -1
            i = j + 1
            continue
        if c == "`":
            i = _skip_template(s, i)
            if i < 0:
                return -1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i if c in stop_chars else -1
            depth -= 1
        elif depth == 0 and c in stop_chars:
            return i
        i += 1
    return n


def _skip_template(s: str, i: int) -> int:
    """Index just past the template literal opening at s[i] == '`'; -1 when it never closes."""
    n = len(s)
    i += 1
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i + 1
        if c == "$" and s[i + 1:i + 2] == "{":
            end = _scan_code(s, i + 2, "}")
            if end < 0 or end >= n:
                return -1
            i = end + 1
            continue
        i += 1
    return -1


def _split_top_level(expr: str, ch: str) -> list[str]:
    parts, start, i = [], 0, 0
    while True:
        i = _scan_code(expr, i, ch)
        if i < 0:
            return [expr]
        if i >= len(expr):
            parts.append(expr[start:])
            return parts
        parts.append(expr[start:i])
        start = i = i + 1


def _ternary_branches(expr: str) -> list[str] | None:
    """[then, else] of a top-level `cond ? then : else` (not `?.`/`??`); None when there is none."""
    i = 0
    while True:
        q = _scan_code(expr, i, "?")
        if q < 0 or q >= len(expr):
            return None
        if expr[q + 1:q + 2] in (".", "?") or expr[q - 1:q] == "?":
            i = q + 1
            continue
        c = _scan_code(expr, q + 1, ":")
        if c < 0 or c >= len(expr):
            return None
        return [expr[q + 1:c], expr[c + 1:]]


_CONTROL_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "typeof", "await"})


_ASSIGN_ANY_RE = re.compile(
    r"(?<![\w$.])((?:this\.)?[A-Za-z_$][\w$]*)\s*([-+*/%&|^]|\*\*|<<|>>>?|\?\?|\|\||&&)?=(?![=>])\s*"
)
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
# Places that bind a name without an `=`: parameter lists (arrow, function, method) and the heads of
# for / catch.  Every identifier inside is treated as bound (over-cautious, never under-).
_BINDER_RES = (
    re.compile(r"\(([^()]*)\)\s*=>"),
    re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=>"),
    re.compile(r"\bfunction\b[^(\n]*\(([^()]*)\)"),
    re.compile(r"\b(?:for|catch)\s*(?:await\s*)?\(([^;()]*)"),
)
_METHOD_DEF_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{")


class _FileIndex:
    """One linear pass over a file: where each name is assigned, and which names are bound as
    parameters or loop variables.  The proof asks about many names; a regex pass per name would be
    quadratic on a bundle."""

    __slots__ = ("assigns", "bound")

    def __init__(self, content: str) -> None:
        self.assigns: dict[str, list[tuple[str | None, int]]] = {}
        for m in _ASSIGN_ANY_RE.finditer(content):
            self.assigns.setdefault(m.group(1), []).append((m.group(2), m.end()))
        self.bound: set[str] = set()
        for rx in _BINDER_RES:
            for m in rx.finditer(content):
                self.bound.update(_IDENT_RE.findall(m.group(1)))
        for m in _METHOD_DEF_RE.finditer(content):
            if m.group(1) not in _CONTROL_KEYWORDS:
                self.bound.update(_IDENT_RE.findall(m.group(2)))     # `render(name) {`


def _proof_state(content: str) -> dict:
    cache = getattr(_inert_local, "entry", None)
    if cache is None or cache[0] is not content:
        cache = (content, {})
        _inert_local.entry = cache
    return cache[1]


def _definition_rhs(content: str, name: str) -> list[str] | None:
    """Right-hand sides of every assignment to *name* (a bare name or `this.prop`) in *content*;
    None when there is no assignment, a compound assignment, a parameter, or the text is odd."""
    state = _proof_state(content)
    idx = state.get("index")
    if idx is None:
        idx = state["index"] = _FileIndex(content)
    entries = idx.assigns.get(name)
    if not entries:
        return None
    # `name += x` appends to the string, so x joins the other right-hand sides; any other compound
    # operator is not something this proof models
    if any(op not in (None, "+") for op, _ in entries):
        return None
    if not name.startswith("this.") and name in idx.bound:
        return None
    rhs_list: list[str] = []
    for _op, rhs_start in entries:
        end = _scan_code(content, rhs_start, ";\n")
        if end < 0:
            return None
        # a statement continues past a newline when it ends in an operator or the next line starts with one
        while end < len(content) and content[end] == "\n":
            before = content[rhs_start:end].rstrip()
            after = content[end + 1:end + 200].lstrip()
            if before and (before[-1] in "+-*/%&|^?:=(,[{<>." or after[:1] in "+-*/%&|^?:.,)]}"
                           or after[:2] in ("?.", "??")):
                nxt = _scan_code(content, end + 1, ";\n")
                if nxt < 0:
                    return None
                end = nxt
                continue
            break
        rhs = content[rhs_start:end].strip()
        if not rhs or len(rhs) > _MAX_EXPR_CHARS:
            return None
        rhs_list.append(rhs)
    return rhs_list or None


def _expr_is_inert(expr: str, content: str, depth: int = 0, seen: frozenset[str] = frozenset()) -> bool:
    expr = expr.strip()
    if (not expr or depth > _MAX_INERT_DEPTH or len(expr) > _MAX_EXPR_CHARS
            or len(content) > _MAX_PROOF_FILE_CHARS):
        return False
    if _INCDEC_RE.fullmatch(expr):
        return True     # `++counter`: always a number
    branches = _ternary_branches(expr)
    if branches is not None:
        return all(_expr_is_inert(b, content, depth + 1, seen) for b in branches)
    terms = _split_top_level(expr, "+")
    if len(terms) > 1:
        return all(_expr_is_inert(t, content, depth + 1, seen) for t in terms)
    term = expr
    while term.startswith("(") and term.endswith(")") and _scan_code(term, 1, ")") == len(term) - 1:
        term = term[1:-1].strip()
    if term != expr:
        return _expr_is_inert(term, content, depth + 1, seen)
    if (_QUOTED_RE.fullmatch(term) or _NUMBER_RE.fullmatch(term) or _INCDEC_RE.fullmatch(term)
            or term in ("true", "false", "null", "undefined")):
        return True
    if term.startswith("`") and _skip_template(term, 0) == len(term):
        interps = _INTERP_RE.findall(term)
        if len(interps) != term.count("${"):
            return False
        return all(_expr_is_inert(e, content, depth + 1, seen) for e in interps)
    if re.fullmatch(r"[\w$.]+\.length", term):
        return True
    if any(term.startswith(f + "(") for f in ("Number", "parseInt", "parseFloat", "encodeURIComponent",
                                              "escapeHtml", "this.escapeHtml")) and term.endswith(")"):
        return True
    if _REF_RE.fullmatch(term):
        return _ref_is_inert(term, content, depth, seen)
    return False


def _ref_is_inert(name: str, content: str, depth: int = 0, seen: frozenset[str] = frozenset()) -> bool:
    if name in seen or depth > _MAX_INERT_DEPTH:
        return False
    state = _proof_state(content)
    # The verdict for a name does not depend on how it was reached, except through the cycle guard
    # and the depth budget; cache only top-level answers and the extracted definitions.
    if depth == 0 and name in state:
        return state[name]
    rhs_list = state.get(("rhs", name), False)
    if rhs_list is False:
        rhs_list = state[("rhs", name)] = _definition_rhs(content, name)
    result = bool(rhs_list) and len(rhs_list) <= 60 and all(
        _expr_is_inert(r, content, depth + 1, seen | {name}) for r in rhs_list
    )
    if depth == 0:
        state[name] = result
    return result


def innerhtml_rhs_is_inert(rhs: str, content: str | None) -> bool:
    """True when the whole right-hand side of an `innerHTML =` assignment is provably inert."""
    rhs = rhs.strip().rstrip(";").strip()
    return bool(content) and bool(rhs) and _expr_is_inert(rhs, content)


# A bundle or minified file holds thousands of sinks and one-letter names reused everywhere: the
# proof (a few regex passes over the file per name) is not worth its cost, and never holds there.
_MAX_PROOF_FILE_CHARS = 300_000


def _innerhtml_is_unsafe(block: str, content: str | None = None) -> bool:
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

    # ── copy of another element's markup: `a.innerHTML = b.innerHTML` ────────
    # The markup was already parsed into the DOM once; copying it adds no new untrusted data.
    if re.fullmatch(r"[\w$.\[\]'\"]+\.(?:innerHTML|outerHTML)", rhs):
        return False

    # ── quoted string literal ─────────────────────────────────────────────────
    # JS string literals ('' or "") cannot contain variable interpolation.
    # Only flag if there is a concatenation operator after a closing quote.
    if rhs[0] in ("'", '"'):
        return bool(re.search(r"['\"]\s*\+", rhs))  # vulnscanner: ignore[LDAP-001]

    # ── template literal ──────────────────────────────────────────────────────
    if rhs[0] == '`':
        if '${' not in rhs:
            return False
        return any(
            not (_is_safe_interpolation(e) or _is_static_interpolation(e, content)
                 or (content and _expr_is_inert(e, content)))
            for e in _INTERP_RE.findall(rhs)
        )

    # ── no template interpolation anywhere in the block ───────────────────────
    # Handles ternary/conditional expressions whose branches are all literals,
    # e.g.  innerHTML = model === 'x' ? '⚡ Ultra' : `<svg>...</svg>`
    if '${' not in block:
        if '?' in rhs:
            return False  # ternary with literal branches
        # Any function call — developer is applying some transformation (same
        # policy as the template-literal branch: function call = not a bare ref).
        # e.g. innerHTML = DOMPurify.sanitize(x)  or  innerHTML = escapeHtml(x)
        if re.search(r'\w\s*\(', rhs):
            return False
        # A constant that is only ever a plain string literal carries no user data
        if content and _BARE_IDENT_RE.match(rhs) and _is_static_string_constant(rhs, content):
            return False
        # Variables and concatenations that only ever hold literals, numbers and counters
        if content and _expr_is_inert(rhs, content):
            return False
        # Bare variable or property access — flag
        return True

    # Has ${} but rhs doesn't open with a backtick - flag conservatively
    if content and _expr_is_inert(rhs, content):
        return False
    return True


class XSSAnalyzer(BaseAnalyzer):
    supported_extensions = (".js", ".ts", ".jsx", ".tsx", ".html", ".php", ".py", ".cshtml", ".razor")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        # XSS-001: smart innerHTML check (handles multiline template literals)
        findings.extend(self._check_innerhtml(file_path, lines, repo_url))

        # Razor views: only the innerHTML check applies to their <script> blocks; the per-line rules
        # below are not written for Razor syntax (`@` expressions).
        if file_path.endswith((".cshtml", ".razor")):
            return findings

        # XSS-002 to XSS-007: simple per-line regex rules (single-pass, pre-compiled)
        if _SIMPLE_GUARD.search(content):
            is_js_html = file_path.endswith(_JS_HTML_EXTS)
            is_php = file_path.endswith(".php")
            is_py = file_path.endswith(".py")
            plain_text_template = file_path.endswith((".html", ".htm")) and not _HTML_TAG_RE.search(content)
            tpl_literal_vars = (
                _template_literal_vars(content) if file_path.endswith((".html", ".htm")) else set()
            )
            dom_reachable = bool(_DOM_SOURCE_RE.search(content))
            simple_rules = [
                (rid, pat, desc, sev)
                for rid, pat, desc, sev in _SIMPLE_RULES
                if (rid not in _JS_HTML_ONLY or is_js_html)
                and (rid not in _PHP_ONLY or is_php)
            ]
            for lineno, line in enumerate(lines, 1):
                if self._is_comment(line):
                    continue
                stripped = line.strip()
                for rule_id, pattern_re, description, severity in simple_rules:
                    if pattern_re.search(line):
                        if rule_id == "XSS-004":
                            # mark_safe() in .py is judged by PythonASTAnalyzer (AST-XSS-001)
                            if is_py and not _FORMAT_HTML_CONCAT_RE.search(line):
                                continue
                            if plain_text_template:
                                continue
                            if tpl_literal_vars:
                                safe_vars = _TPL_SAFE_VAR_RE.findall(line)
                                if safe_vars and all(v in tpl_literal_vars for v in safe_vars):
                                    continue
                        sev, ts, conf = severity, None, 1.0
                        if rule_id in _DOM_GATED_RULES and is_js_html and not dom_reachable:
                            sev, ts, conf = Severity.LOW, "unknown", 0.3
                        findings.append(Finding(
                            vuln_type=VulnType.XSS,
                            severity=sev,
                            taint_status=ts,
                            confidence=conf,
                            file_path=file_path,
                            line_number=lineno,
                            line_content=stripped,
                            description=description,
                            rule_id=rule_id,
                            repo_url=repo_url,
                            snippet=self._extract_snippet(lines, lineno),
                        ))

        # XSS-008: PHP 1-hop taint analysis ($_GET/$_POST → $var → echo)
        if file_path.endswith(".php"):
            findings.extend(self._check_php_taint(file_path, lines, repo_url))

        return findings

    @staticmethod
    def _php_escaped_literal_is_safe(line: str, content: str) -> bool:
        """innerHTML inside a PHP-escaped JS string: safe unless an unsanitized $var is concatenated."""
        if not _PHP_ESCAPED_RHS_RE.search(line):
            return False
        for var in _PHP_CONCAT_VAR_RE.findall(line):
            if not re.search(_PHP_SANITIZED_ASSIGN % re.escape(var), content):
                return False
        return True

    def _check_innerhtml(
        self, file_path: str, lines: list[str], repo_url: str
    ) -> list[Finding]:
        # innerHTML is a DOM API — not applicable to Python source files.
        # Guarding here prevents false positives from docstrings that mention innerHTML.
        if not file_path.endswith(_JS_HTML_EXTS + (".php", ".cshtml", ".razor")):
            return []
        findings: list[Finding] = []
        content = "\n".join(lines)
        is_php = file_path.endswith(".php")
        dom_source_in_file: bool | None = None
        i = 0
        while i < len(lines):
            line = lines[i]
            if not self._is_comment(line) and 'innerHTML' in line and re.search(r'innerHTML\s*=', line):
                lineno = i + 1
                block = self._collect_block(lines, i)
                if is_php and self._php_escaped_literal_is_safe(line, content):
                    i += 1
                    continue
                rhs_m = re.search(r'innerHTML\s*=\s*([^\n]*)', line)
                if (rhs_m and file_path.endswith(".blade.php")
                        and _blade_literal_only(rhs_m.group(1))):
                    i += 1
                    continue
                if rhs_m and _concat_vars_are_i18n(rhs_m.group(1), lines, i):
                    i += 1
                    continue
                if _innerhtml_is_unsafe(block, content):
                    # A DOM sink in a file with no browser-controlled input source
                    # (URL, referrer, postMessage, storage …) is most likely fed by
                    # the app's own server responses — keep it, but as low reach.
                    # A .blade.php <script> block is plain browser JS, not PHP emitting a handler.
                    if dom_source_in_file is None:     # once per file: it scans the whole text
                        dom_source_in_file = bool(_DOM_SOURCE_RE.search(content))
                    reachable = (is_php and not file_path.endswith(".blade.php")) or dom_source_in_file
                    findings.append(Finding(
                        vuln_type=VulnType.XSS,
                        severity=Severity.HIGH if reachable else Severity.LOW,
                        taint_status=None if reachable else "unknown",
                        confidence=1.0 if reachable else 0.3,
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
                if re.search(r"\$" + re.escape(var_name) + r"\b", expr):  # vulnscanner: ignore[LDAP-001]
                    # If the whole echo expression is wrapped in a sanitizing
                    # function the tainted value is sanitized at the echo point.
                    # e.g. echo htmlspecialchars($raw) — safe even if $raw is tainted.
                    if _PHP_XSS_CLEAN_RE.match(expr.strip()):
                        break
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
