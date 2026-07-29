"""TypeScript-ecosystem vulnerability analyzer (tree-sitter).

Detects TypeScript framework-specific vulnerabilities not covered by TSASTAnalyzer
(which handles JSAST-* rules via the shared JS/TS taint engine):

  - TypeORM QueryBuilder raw string injection
  - Prisma $queryRaw / $queryRawUnsafe / $executeRaw / $executeRawUnsafe
  - Knex .whereRaw() / .havingRaw() / .orderByRaw() / .groupByRaw() / .joinRaw()
  - Sequelize Sequelize.literal(tainted) / sequelize.query(tainted)
  - React JSX dangerouslySetInnerHTML={{ __html: tainted }}
  - Next.js context.query.* / context.params.* taint sources
  - Next.js App Router useSearchParams() / useParams() hook sources

Rule IDs:
  TSAST-SQL-001  TypeORM QueryBuilder raw string fragment (where/andWhere/having/…)
  TSAST-SQL-002  Prisma $queryRaw* / $executeRaw* with user-controlled argument
  TSAST-SQL-003  Knex .*Raw() family with user-controlled SQL fragment
  TSAST-SQL-004  Sequelize literal() / sequelize.query() with tainted argument
  TSAST-XSS-001  React dangerouslySetInnerHTML={{ __html: tainted }}
"""
from __future__ import annotations

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

try:
    from vulnscanner.analyzers.ast_js import (
        _ts_parser,
        _tsx_parser,
        _TS_TS_AVAILABLE,
        _JSTaintState,
        _walk,
        _unwrap,
        _member_chain,
        _is_request_source,
        _is_sanitizer,
        _extract_destruct_local,
        _collect_declarations,
        _analyze_functions,
        _collect_nestjs_params,
        _emit,
    )
    _TSAST_AVAIL = _TS_TS_AVAILABLE
except (ImportError, Exception):
    _TSAST_AVAIL = False

_TS_EXTS = (".ts", ".tsx")

# ── TypeScript-specific taint source patterns ──────────────────────────────────

# Next.js getServerSideProps / API route context properties
_NEXTJS_CTX_PROPS = frozenset({"query", "params", "searchParams"})

# React / Next.js hooks that return user-controlled data
_TS_SOURCE_HOOKS = frozenset({
    "useSearchParams",   # Next.js App Router / React Router v6
    "useParams",         # React Router v6 / Next.js dynamic routes
})

# searchParams-like root variable names (Next.js App Router page prop)
_SEARCH_PARAM_ROOTS = frozenset({"searchParams"})

# ── TypeScript-specific sink definitions ───────────────────────────────────────

# TypeORM QueryBuilder methods that accept a raw SQL string as first arg.
# Safe form: .where("col = :param", { param: val }) — parameterized.
# Unsafe form: .where("col = '" + userInput + "'") — string concatenation.
_TYPEORM_QB_METHODS = frozenset({
    "where", "andWhere", "orWhere",
    "having", "andHaving", "orHaving",
    "addSelect",
    "orderBy", "addOrderBy",
    "groupBy", "addGroupBy",
})

# Prisma raw execution method names.
# $queryRaw / $executeRaw tagged template form is safe only with Prisma.sql helper.
# $queryRawUnsafe / $executeRawUnsafe are always dangerous.
_PRISMA_RAW_METHODS = frozenset({
    "$queryRaw",
    "$executeRaw",
    "$queryRawUnsafe",
    "$executeRawUnsafe",
})

# Knex raw SQL methods not in the generic _SQL_METHOD_SINKS set.
# (knex.raw() is already caught by JSAST-SQL-001 since "raw" is in _SQL_METHOD_SINKS.)
_KNEX_RAW_METHODS = frozenset({
    "whereRaw",
    "havingRaw",
    "orderByRaw",
    "groupByRaw",
    "joinRaw",
    "crossJoinRaw",
    "leftOuterJoinRaw",
    "rightOuterJoinRaw",
    "fromRaw",
    "whereWrapped",
})

# Sequelize root identifiers and dangerous methods
_SEQUELIZE_ROOTS = frozenset({"Sequelize", "sequelize", "DataTypes"})
_SEQUELIZE_RAW_METHODS = frozenset({"query", "literal", "fn"})


# ── TypeScript-specific source checker ────────────────────────────────────────


def _is_ts_source(node) -> bool:
    """Return True when node is a TypeScript-specific taint source.

    Handles patterns not covered by _is_request_source:
      - useSearchParams() / useParams() hook calls
      - searchParams.get('key'), searchParams['key'], searchParams.key
      - context.query.*, context.params.* (Next.js GSSP / API routes)
      - router.query.* (Next.js useRouter)
      - request.nextUrl.searchParams.* (Next.js Route Handlers)
    """
    node = _unwrap(node)

    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is None:
            return False
        # Direct hook: useSearchParams(), useParams()
        if fn.type == "identifier":
            return fn.text.decode("utf-8", errors="replace") in _TS_SOURCE_HOOKS
        # Method on searchParams root: searchParams.get('q'), searchParams.getAll('q')
        if fn.type == "member_expression":
            chain = _member_chain(fn)
            if (len(chain) >= 2
                    and chain[0] in _SEARCH_PARAM_ROOTS
                    and chain[1] in ("get", "getAll", "has")):
                return True
        return False

    if node.type in ("member_expression", "subscript_expression"):
        chain = _member_chain(node)
        if len(chain) < 2:
            return False
        root, prop = chain[0], chain[1]
        # context.query / context.params (Next.js getServerSideProps / API handler)
        if root == "context" and prop in _NEXTJS_CTX_PROPS:
            return True
        # searchParams.anyKey (Next.js App Router page component prop)
        if root in _SEARCH_PARAM_ROOTS:
            return True
        # router.query.x (Next.js Pages Router useRouter)
        if root == "router" and prop == "query":
            return True
        # request.nextUrl.searchParams.* (Next.js Route Handler)
        if root in ("request", "req") and len(chain) >= 3 and chain[1] == "nextUrl":
            return True

    return False


# ── TypeScript-extended taint state ───────────────────────────────────────────


class _TSTaintState(_JSTaintState):
    """_JSTaintState extended to recognise TypeScript-specific taint sources."""

    def is_tainted_node(self, node) -> bool:
        return super().is_tainted_node(node) or _is_ts_source(node)


def _ts_collect_extra_sources(root, state: _TSTaintState) -> bool:
    """Mark variables assigned from TypeScript-specific hook calls or context destructuring."""
    changed = False
    for node in _walk(root):
        if node.type != "variable_declarator":
            continue
        name_n = node.child_by_field_name("name")
        val_n = node.child_by_field_name("value")
        if name_n is None or val_n is None:
            continue
        val_u = _unwrap(val_n)
        line = name_n.start_point[0] + 1

        # const sp = useSearchParams()  /  const params = useParams()
        if val_u.type == "call_expression":
            fn = val_u.child_by_field_name("function")
            if fn is not None and fn.type == "identifier":
                fname = fn.text.decode("utf-8", errors="replace")
                if fname in _TS_SOURCE_HOOKS and name_n.type == "identifier":
                    var = name_n.text.decode("utf-8", errors="replace")
                    if state.mark(var, line, f"Next.js/React Router {fname}() return"):
                        changed = True
                    continue

        # const { query, params } = context   (Next.js getServerSideProps destructuring)
        if (val_u.type == "identifier"
                and val_u.text.decode("utf-8", errors="replace") == "context"
                and name_n.type == "object_pattern"):
            for child in name_n.named_children:
                local = _extract_destruct_local(child)
                if local and local in _NEXTJS_CTX_PROPS:
                    if state.mark(local, line, "Next.js context destructuring"):
                        changed = True

    return changed


def _build_ts_taint_state(root) -> _TSTaintState:
    """Fixed-point taint collection with TypeScript-specific source extensions."""
    state = _TSTaintState()
    _collect_nestjs_params(root, state)
    _ts_collect_extra_sources(root, state)
    for _ in range(8):
        c1 = _collect_declarations(root, state)
        c2 = _analyze_functions(root, state)
        if not c1 and not c2:
            break
    return state


# ── TypeScript-specific sink checker ──────────────────────────────────────────


def _check_ts_sinks(
    root,
    state: _TSTaintState,
    file_path: str,
    lines: list[str],
    repo_url: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for node in _walk(root):
        line = node.start_point[0] + 1

        # ── React JSX: dangerouslySetInnerHTML={{ __html: tainted }} ──────────
        if node.type == "jsx_attribute":
            nc = [c for c in node.children if c.is_named]
            if not nc or nc[0].text.decode("utf-8", errors="replace") != "dangerouslySetInnerHTML":
                continue
            # Walk into the attribute value looking for the __html pair
            for subnode in _walk(node):
                if subnode.type != "pair":
                    continue
                pair_nc = [c for c in subnode.children if c.is_named]
                if len(pair_nc) < 2:
                    continue
                key_txt = pair_nc[0].text.decode("utf-8", errors="replace").strip("\"'`")
                if key_txt != "__html":
                    continue
                val_n = _unwrap(pair_nc[1])
                if state.is_tainted_node(val_n):
                    _emit(findings, seen, file_path, line, lines, repo_url,
                          VulnType.XSS, Severity.HIGH,
                          "TSAST-XSS-001",
                          "User-controlled data in dangerouslySetInnerHTML.__html — DOM XSS risk")
                    break
            continue

        if node.type != "call_expression":
            continue

        func_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if func_node is None:
            continue

        # ── Prisma tagged template: prisma.$queryRaw`SELECT ${tainted}` ───────
        # Tagged templates: function = member_expr, arguments = template_string (no parens)
        if (func_node.type == "member_expression"
                and args_node is not None
                and args_node.type == "template_string"):
            prop_n = func_node.child_by_field_name("property")
            if prop_n is None:
                continue
            prop = prop_n.text.decode("utf-8", errors="replace")
            if prop not in _PRISMA_RAW_METHODS:
                continue
            for sub in _walk(args_node):
                if sub.type != "template_substitution":
                    continue
                for expr in sub.named_children:
                    if state.is_tainted_node(_unwrap(expr)):
                        sev = Severity.CRITICAL if "Unsafe" in prop else Severity.HIGH
                        _emit(findings, seen, file_path, line, lines, repo_url,
                              VulnType.SQL_INJECTION, sev,
                              "TSAST-SQL-002",
                              f"User-controlled data interpolated into Prisma {prop}`` "
                              "— SQL injection risk (use Prisma.sql helper for safe queries)")
                        break
            continue

        if args_node is None:
            continue

        named_args = list(args_node.named_children)

        def _t_args() -> list:
            return [c for c in named_args if state.is_tainted_node(c)]

        def _first_arg_tainted() -> bool:
            if not named_args:
                return False
            first = _unwrap(named_args[0])
            return (
                state.is_tainted_node(first)
                or (first.type in ("template_string", "binary_expression")
                    and state.is_tainted_node(first))
            )

        # ── Global call: literal(tainted) ─────────────────────────────────────
        if func_node.type == "identifier":
            fname = func_node.text.decode("utf-8", errors="replace")
            if fname == "literal" and _t_args():
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH,
                      "TSAST-SQL-004",
                      "User-controlled data in Sequelize literal() — SQL injection risk")
            continue

        if func_node.type != "member_expression":
            continue

        obj_node = func_node.child_by_field_name("object")
        prop_node = func_node.child_by_field_name("property")
        if obj_node is None or prop_node is None:
            continue
        prop = prop_node.text.decode("utf-8", errors="replace")
        obj_chain = _member_chain(obj_node)
        obj_root = obj_chain[0] if obj_chain else ""

        # ── Prisma method call: prisma.$queryRawUnsafe(tainted) ───────────────
        if prop in _PRISMA_RAW_METHODS:
            if not _t_args():
                continue
            # $queryRaw / $executeRaw with parameterized array [?] is safe
            if (len(named_args) >= 2
                    and named_args[1].type == "array"
                    and prop not in ("$queryRawUnsafe", "$executeRawUnsafe")):
                continue
            sev = Severity.CRITICAL if "Unsafe" in prop else Severity.HIGH
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SQL_INJECTION, sev,
                  "TSAST-SQL-002",
                  f"User-controlled data in Prisma {prop}() — SQL injection risk")

        # ── Knex raw methods: .whereRaw(tainted), .havingRaw(tainted), etc. ───
        elif prop in _KNEX_RAW_METHODS:
            if not _first_arg_tainted():
                continue
            # Safe: .whereRaw('col = ?', [value]) — second arg is bindings array
            if len(named_args) >= 2 and named_args[1].type == "array":
                continue
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SQL_INJECTION, Severity.HIGH,
                  "TSAST-SQL-003",
                  f"User-controlled data in Knex .{prop}() — SQL injection risk")

        # ── Sequelize: sequelize.query(tainted), Sequelize.literal(tainted) ───
        elif obj_root in _SEQUELIZE_ROOTS and prop in _SEQUELIZE_RAW_METHODS:
            if not _t_args():
                continue
            # sequelize.query(sql, { replacements: [...] }) — second arg is options object
            if len(named_args) >= 2 and named_args[1].type == "object":
                continue
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SQL_INJECTION, Severity.HIGH,
                  "TSAST-SQL-004",
                  f"User-controlled data in Sequelize.{prop}() — SQL injection risk")

        # ── TypeORM QueryBuilder: qb.where(tainted), qb.andWhere(tainted) ─────
        elif prop in _TYPEORM_QB_METHODS:
            if not _first_arg_tainted():
                continue
            # Safe: .where("col = :param", { param: val }) — second arg is binding object
            if len(named_args) >= 2 and named_args[1].type == "object":
                continue
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SQL_INJECTION, Severity.HIGH,
                  "TSAST-SQL-001",
                  f"User-controlled data in TypeORM QueryBuilder .{prop}() — SQL injection risk")

    return findings


# ── Main analysis function ─────────────────────────────────────────────────────


# Keywords that indicate TypeScript-specific inline sources (no variable assignment needed).
# Used as a fast guard to skip files with no relevant patterns.
_TS_INLINE_SOURCE_KWS = (
    "searchParams", "useSearchParams", "useParams",
    "context.query", "context.params",
    "dangerouslySetInnerHTML",
)


def _analyze_typescript(parser, file_path: str, content: str, repo_url: str) -> list[Finding]:
    try:
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:
        return []
    root = tree.root_node
    lines = content.splitlines()
    state = _build_ts_taint_state(root)
    # Skip if state has no tainted variables AND no TypeScript-specific inline source keywords.
    # (Inline sources like searchParams.html are checked directly in _check_ts_sinks via
    #  _TSTaintState.is_tainted_node → _is_ts_source, so they don't populate state.tainted.)
    if (not state.tainted and not state.tainted_funcs and not state.tainted_attrs
            and not any(kw in content for kw in _TS_INLINE_SOURCE_KWS)):
        return []
    return _check_ts_sinks(root, state, file_path, lines, repo_url)


# ── Analyzer class ────────────────────────────────────────────────────────────


class TypeScriptASTAnalyzer(BaseAnalyzer):
    """TypeScript-ecosystem AST taint analyzer (tree-sitter-typescript).

    Handles TypeScript framework patterns not covered by TSASTAnalyzer:
    TypeORM QueryBuilder injection, Prisma raw queries, Knex .*Raw() methods,
    Sequelize literal(), React dangerouslySetInnerHTML with user-controlled HTML,
    and Next.js framework taint sources (context.query, useSearchParams, useParams).

    Rule IDs: TSAST-SQL-001/002/003/004, TSAST-XSS-001
    """

    supported_extensions = _TS_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TSAST_AVAIL:
            return []
        if file_path.endswith(".tsx"):
            parser = _tsx_parser
        elif file_path.endswith(".ts"):
            parser = _ts_parser
        else:
            return []
        return _analyze_typescript(parser, file_path, content, repo_url)
