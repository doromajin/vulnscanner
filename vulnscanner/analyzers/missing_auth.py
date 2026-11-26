"""
Missing Authorization detector (CWE-862).

Detects HTTP route handlers that accept state-changing requests
(POST / PUT / DELETE / PATCH) without authentication guards.

Python: Django · Flask · FastAPI · Django REST Framework
Java:   Spring MVC / Spring Boot
"""
from __future__ import annotations

import functools
import os
import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.csrf import _SESSION_USE_RE
from vulnscanner.models import Finding, Severity, VulnType

_MA = VulnType.MISSING_AUTHORIZATION

# ── Allow-lists ────────────────────────────────────────────────────────────────

# Route paths that are intentionally public (no auth needed)
_PUBLIC_PATH_RE = re.compile(
    r'/(?:login|logout|register|sign[_-]?(?:up|in)|auth(?:enticate|orize)?'
    r'|oauth\d*|callback|health(?:z|check)?|ping|status|ready|live'
    r'|actuator|metrics'
    r'|docs?|swagger|openapi|api[_-]?docs?|redoc|schema'
    r'|public|open|static|assets|favicon|robots)',
    re.IGNORECASE,
)

# Function / method names that are clearly public
_PUBLIC_FUNC_RE = re.compile(
    r'^(?:login|logout|register|signup|sign_in|sign_up|auth(?:enticate)?'
    r'|health(?:_check)?|ping|status|index|home|root|docs?|swagger|about'
    r'|forgot_password|reset_password|verify_email|send_verification'
    r'|create_account|new_account)$',
    re.IGNORECASE,
)

# ── Python patterns ────────────────────────────────────────────────────────────

# Shorthand state-changing decorators: @app.post, @router.delete, …
_PY_STATE_DEC_RE = re.compile(
    r'@\s*(?:\w+\.)*(?:post|put|delete|patch)\s*\(',
    re.IGNORECASE,
)

# @app.route / @blueprint.route / @api.route
_PY_ROUTE_DEC_RE = re.compile(r'@\s*(?:\w+\.)*route\s*\(', re.IGNORECASE)
_PY_METHODS_RE   = re.compile(r'methods\s*=\s*\[([^\]]+)\]', re.IGNORECASE)
_STATE_WORD_RE   = re.compile(r'\b(?:POST|PUT|DELETE|PATCH)\b')

# Django @require_POST / @require_http_methods
_DJANGO_REQ_POST_RE    = re.compile(r'@\s*require_POST\b', re.IGNORECASE)
_DJANGO_REQ_METHODS_RE = re.compile(r'@\s*require_http_methods\s*\(', re.IGNORECASE)

# DRF @api_view(['POST', …])
_DRF_APIVIEW_RE = re.compile(r'@\s*api_view\s*\(\s*\[([^\]]+)\]', re.IGNORECASE)

# Python auth decorators (function-level)
_PY_AUTH_DEC_RE = re.compile(
    r'@\s*(?:'
    r'login_required'
    r'|permission_required'
    r'|user_passes_test'
    r'|jwt_required'
    r'|fresh_jwt_required'
    r'|token_required'
    r'|requires_auth'
    r'|require_auth'
    r'|auth_required'
    r'|authenticated(?:_user)?'
    r'|verify_token'
    r'|admin_required'
    r'|staff_member_required'
    r'|superuser_required'
    r'|roles_required'
    r'|role_required'
    r'|permission_classes'
    r'|has_permission'
    r'|requires_permission'
    r')',
    re.IGNORECASE,
)

# Class-level auth: mixin names in class(…) or @permission_classes on the class
_PY_CLASS_MIXIN_RE = re.compile(
    r'class\s+\w+\s*\([^)]*(?:'
    r'LoginRequiredMixin'
    r'|PermissionRequiredMixin'
    r'|StaffRequiredMixin'
    r'|AdminRequiredMixin'
    r')',
    re.IGNORECASE,
)

# Function definition — group 1 = indent, group 2 = name
_PY_FUNC_RE = re.compile(r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\(')
# Anything that reads or writes stored data, sends something or touches the filesystem / shell.
_PY_DATA_ACCESS_RE = re.compile(
    r"\.objects\b|get_object_or_404|get_list_or_404|\.save\(|\.delete\(|\.update\(|\.create\("
    r"|\bcursor\b|\bsession\b|\.execute\(|send_mail|send_mass_mail|requests\.|httpx\.|urlopen|subprocess"
    r"|os\.system|\bopen\(|\.write\(|\.commit\(|\bdb\.|\.add\(|\.remove\(|\.send\("
)

# Class definition — group 1 = indent
_PY_CLASS_RE = re.compile(r'^(\s*)class\s+\w+')

# Fast-skip guard for Python files
_PY_GUARD_RE = re.compile(
    r'@(?:app|bp|api|router|blueprint|[\w]+)\.|@require_POST|@api_view',
    re.IGNORECASE,
)

# ── Java patterns ──────────────────────────────────────────────────────────────

# State-changing Spring mapping annotations
_JAVA_STATE_MAP_RE = re.compile(
    r'@\s*(?:PostMapping|PutMapping|DeleteMapping|PatchMapping'
    r'|RequestMapping\s*\([^)]*method\s*=\s*(?:RequestMethod\.)?(?:POST|PUT|DELETE|PATCH))',
    re.IGNORECASE,
)

# Spring auth annotations
_JAVA_AUTH_RE = re.compile(
    r'@\s*(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresPermissions)',
    re.IGNORECASE,
)

# Route path extraction
_JAVA_PATH_INLINE_RE = re.compile(r'@\w+Mapping\s*\(\s*"([^"]+)"')
_JAVA_PATH_VALUE_RE  = re.compile(r'(?:value|path)\s*=\s*"([^"]+)"')

# Java method definition (public/protected/private … name()
_JAVA_METHOD_RE = re.compile(
    r'(?:public|protected|private)\s+(?:static\s+)?(?:\w+(?:<[^>]+>)?\s+)+(\w+)\s*\('
)

# Fast-skip guard for Java files
_JAVA_GUARD_RE = re.compile(
    r'@(?:Post|Put|Delete|Patch)Mapping|@RequestMapping',
)


# ── Project-wide Spring Security ───────────────────────────────────────────────
# `http.authorizeRequests()...anyRequest().authenticated()` (or hasRole/hasAuthority/access) in a
# security configuration class protects every endpoint that is not explicitly opened with permitAll().
_SPRING_SEC_CFG_RE = re.compile(r"@EnableWebSecurity|SecurityFilterChain|WebSecurityConfigurerAdapter")
_SPRING_ANY_REQUEST_AUTH_RE = re.compile(
    r"\.anyRequest\(\)\s*\.\s*(?:authenticated\s*\(|hasAnyRole\s*\(|hasRole\s*\(|hasAuthority\s*\(|hasAnyAuthority\s*\()"
)
_JAVA_SRC_MARK = "/src/main/java/"


@functools.lru_cache(maxsize=64)
def _spring_project_requires_auth(root: str) -> bool:
    """True when a Spring Security config under *root*/src/main/java makes every request authenticated."""
    base = root + _JAVA_SRC_MARK.rstrip("/")
    try:
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                if not fn.endswith(".java") or not re.search(r"Security|Config|Auth|WebMvc", fn):
                    continue
                try:
                    with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as fh:
                        text = fh.read(200_000)
                except OSError:
                    continue
                if _SPRING_SEC_CFG_RE.search(text) and _SPRING_ANY_REQUEST_AUTH_RE.search(text):
                    return True
    except OSError:
        return False
    return False


def _project_root_of(file_path: str) -> str:
    norm = file_path.replace("\\", "/")
    i = norm.find(_JAVA_SRC_MARK)
    return norm[:i] if i > 0 else ""



class MissingAuthAnalyzer(BaseAnalyzer):
    supported_extensions = (".py", ".java")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if file_path.endswith(".py"):
            if not _PY_GUARD_RE.search(content):
                return []
            return self._analyze_python(file_path, content, repo_url)
        if file_path.endswith(".java"):
            if not _JAVA_GUARD_RE.search(content):
                return []
            return self._analyze_java(file_path, content, repo_url)
        return []

    # ── Python ─────────────────────────────────────────────────────────────────

    def _analyze_python(self, file_path: str, content: str, repo_url: str) -> list[Finding]:
        lines = content.splitlines()
        findings: list[Finding] = []

        # Forward scan with decorator-block accumulation.
        # paren_depth tracks multi-line decorators:
        #   @app.route(            ← depth becomes 1
        #       '/path',
        #       methods=['POST']
        #   )                      ← depth back to 0
        #   def view():            ← process dec_block
        dec_block: list[str] = []
        paren_depth: int = 0

        for i, line in enumerate(lines):
            lineno = i + 1
            stripped = line.strip()

            if not stripped or stripped.startswith('#'):
                continue

            # New decorator (paren_depth == 0 ensures we don't mistake
            # a line starting with '@' inside a decorator arg for a new decorator)
            if stripped.startswith('@') and paren_depth == 0:
                dec_block.append(stripped)
                paren_depth = stripped.count('(') - stripped.count(')')
                continue

            # Continuation of a multi-line decorator
            if paren_depth > 0:
                dec_block.append(stripped)
                paren_depth += stripped.count('(') - stripped.count(')')
                paren_depth = max(0, paren_depth)
                continue

            # Function / method definition
            fm = _PY_FUNC_RE.match(line)
            if fm:
                if dec_block:
                    func_indent = len(fm.group(1))
                    func_name   = fm.group(2)
                    f = self._check_py_func(
                        dec_block, func_indent, func_name,
                        lines, i, lineno, file_path, repo_url,
                    )
                    if f:
                        findings.append(f)
                dec_block   = []
                paren_depth = 0
                continue

            # Any other code resets the decorator block
            dec_block   = []
            paren_depth = 0

        return findings

    @staticmethod
    def _py_func_body(lines: list[str], func_idx: int, func_indent: int) -> str:
        """Source of the function starting at *func_idx* (up to the next line at or below its indent)."""
        out = [lines[func_idx]]
        for ln in lines[func_idx + 1: func_idx + 400]:
            if ln.strip() and len(ln) - len(ln.lstrip()) <= func_indent:
                break
            out.append(ln)
        return "\n".join(out)

    def _check_py_func(
        self,
        dec_block: list[str],
        func_indent: int,
        func_name: str,
        lines: list[str],
        func_idx: int,
        lineno: int,
        file_path: str,
        repo_url: str,
    ) -> Finding | None:
        dec_text = ' '.join(dec_block)

        # ---- Is this a state-changing route? ----
        is_state = False

        if _PY_STATE_DEC_RE.search(dec_text):
            is_state = True

        elif _PY_ROUTE_DEC_RE.search(dec_text):
            mm = _PY_METHODS_RE.search(dec_text)
            if mm and _STATE_WORD_RE.search(mm.group(1)):
                is_state = True

        elif _DJANGO_REQ_POST_RE.search(dec_text):
            is_state = True

        elif _DJANGO_REQ_METHODS_RE.search(dec_text):
            if _STATE_WORD_RE.search(dec_text):
                is_state = True

        else:
            drf_m = _DRF_APIVIEW_RE.search(dec_text)
            if drf_m and _STATE_WORD_RE.search(drf_m.group(1)):
                is_state = True

        if not is_state:
            return None

        # ---- Auth decorator present? ----
        if _PY_AUTH_DEC_RE.search(dec_text):
            return None

        # ---- Allow-lists ----
        if _PUBLIC_FUNC_RE.match(func_name):
            return None
        if _PUBLIC_PATH_RE.search(dec_text):
            return None

        # ---- Class-level auth? (method inside LoginRequiredMixin class) ----
        if func_indent > 0:
            for k in range(func_idx - 1, max(-1, func_idx - 300), -1):
                kline = lines[k]
                cm = _PY_CLASS_RE.match(kline)
                if cm and len(cm.group(1)) < func_indent:
                    # Found the enclosing class definition
                    if _PY_CLASS_MIXIN_RE.search(kline):
                        return None  # protected by mixin
                    # Also check for @permission_classes / auth decorator on the class
                    # (it appears 1-3 lines above the class keyword)
                    for m in range(max(0, k - 3), k):
                        if _PY_AUTH_DEC_RE.search(lines[m]):
                            return None
                    break

        # @csrf_exempt + never reading the session / current user = webhook or token- /
        # signature-authenticated endpoint: authentication is not session based, so a missing
        # login decorator is expected.
        severity, note = Severity.HIGH, ""
        body = self._py_func_body(lines, func_idx, func_indent)
        if "csrf_exempt" in dec_text and not _SESSION_USE_RE.search(body):
            severity = Severity.LOW
            note = " [low_reach: csrf_exempt endpoint that never uses the session — webhook / token-authenticated]"
        elif not _SESSION_USE_RE.search(body) and not _PY_DATA_ACCESS_RE.search(body):
            severity = Severity.LOW
            note = " [low_reach: handler touches no session, user or stored data — stateless computation]"

        return Finding(
            vuln_type=_MA,
            severity=severity,
            file_path=file_path,
            line_number=lineno,
            line_content=lines[func_idx].strip(),
            description=(
                f"Route handler '{func_name}' accepts state-changing requests "
                f"(POST/PUT/DELETE/PATCH) without an authentication guard. "
                f"Add @login_required, @permission_classes([IsAuthenticated]), or equivalent."
                + note
            ),
            rule_id="AUTH-001",
            repo_url=repo_url,
            snippet=self._extract_snippet(lines, lineno),
            cwe_id=862,
        )

    # ── Java ───────────────────────────────────────────────────────────────────

    def _analyze_java(self, file_path: str, content: str, repo_url: str) -> list[Finding]:
        lines = content.splitlines()
        findings: list[Finding] = []
        root = _project_root_of(file_path)
        project_auth = bool(root) and _spring_project_requires_auth(root)

        for i, line in enumerate(lines):
            lineno = i + 1

            if not _JAVA_STATE_MAP_RE.search(line):
                continue

            # Extract route path for allow-list
            pm = _JAVA_PATH_INLINE_RE.search(line) or _JAVA_PATH_VALUE_RE.search(line)
            path = pm.group(1) if pm else ""
            if path and _PUBLIC_PATH_RE.search(path):
                continue

            # Look ±25 lines for auth annotation
            win_start = max(0, i - 25)
            win_end   = min(len(lines), i + 6)
            window    = '\n'.join(lines[win_start:win_end])
            if _JAVA_AUTH_RE.search(window):
                continue

            # Find the method name (next few lines)
            func_name  = ""
            func_lineno = lineno
            for j in range(i, min(len(lines), i + 6)):
                mm = _JAVA_METHOD_RE.search(lines[j])
                if mm:
                    func_name   = mm.group(1)
                    func_lineno = j + 1
                    break

            if func_name and _PUBLIC_FUNC_RE.match(func_name):
                continue

            # Check class-level auth:
            # Walk backward to find the enclosing class definition,
            # then check 5 lines before it for @PreAuthorize/@Secured.
            if self._java_class_is_secured(lines, i):
                continue

            findings.append(Finding(
                vuln_type=_MA,
                severity=Severity.LOW if project_auth else Severity.HIGH,
                file_path=file_path,
                line_number=func_lineno,
                line_content=lines[func_lineno - 1].strip(),
                description=(
                    f"Spring endpoint{' ' + repr(path) if path else ''} handles "
                    f"state-changing requests without @PreAuthorize, @Secured, "
                    f"or @RolesAllowed."
                    + (" [low_reach: the project's Spring Security configuration requires authentication for "
                       "anyRequest(); this path is covered unless it is opened with permitAll()]"
                       if project_auth else "")
                ),
                rule_id="AUTH-002",
                repo_url=repo_url,
                snippet=self._extract_snippet(lines, func_lineno),
                cwe_id=862,
            ))

        return findings

    @staticmethod
    def _java_class_is_secured(lines: list[str], method_idx: int) -> bool:
        """Return True if the method's enclosing class has a class-level auth annotation."""
        brace_depth = 0
        for k in range(method_idx - 1, max(-1, method_idx - 600), -1):
            kstripped = lines[k].strip()
            brace_depth += kstripped.count('}') - kstripped.count('{')
            if brace_depth > 0:
                # Exited the enclosing class body
                break
            if 'class ' in kstripped:
                # Check 5 lines above the class definition for auth annotations
                for m in range(max(0, k - 5), k + 1):
                    if _JAVA_AUTH_RE.search(lines[m]):
                        return True
                break
        return False
