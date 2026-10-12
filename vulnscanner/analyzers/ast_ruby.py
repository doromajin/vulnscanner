"""Ruby AST taint analyzer (tree-sitter-ruby).

Detects user-controlled data flowing from Rails/Sinatra/Rack request
objects into dangerous sinks via fixed-point taint propagation.

Improvements over regex-based analysis:
  - True AST parsing: no false matches in comments or string literals
  - Multi-hop taint: params[:id] → q = "...#{id}" → Model.where(q)
  - String interpolation: "SELECT...#{id}" correctly tainted
  - Hash argument analysis: render plain: tainted detected
  - Interprocedural: methods returning params data propagate taint

Rule IDs (RBAST-*):
  RBAST-SQL-001   SQL injection (ActiveRecord raw SQL, SQLite3, PG)
  RBAST-CMD-001   Command injection (system, exec, spawn, IO.popen)
  RBAST-PATH-001  Path traversal (File.open/read/write, Dir.glob)
  RBAST-XSS-001   Reflected XSS (render plain:/html:/text:)
  RBAST-SSRF-001  SSRF (URI.open, Net::HTTP, HTTParty, open())
  RBAST-REDIR-001 Open redirect (redirect_to tainted)
  RBAST-DESER-001 Insecure deserialization (Marshal.load/restore with user input)
  RBAST-DESER-002 Insecure deserialization (YAML.load/unsafe_load with user input)
  RBAST-CMD-002   Command injection (Process.exec/spawn, PTY.spawn, Open3.capture*)
  RBAST-EVAL-001  Code execution (eval/instance_eval/class_eval with user input)
  RBAST-EVAL-002  Arbitrary dispatch via Object#send/public_send with tainted method name
  RBAST-MASS-001  Mass assignment (create/update with raw params hash)
  RBAST-SSTI-001  SSTI (ERB.new/Haml::Engine.new/Liquid::Template.parse with user input)
"""
from __future__ import annotations

try:
    import tree_sitter_ruby as _tsrb
    from tree_sitter import Language, Parser as _TSParser
    _RUBY_LANGUAGE = Language(_tsrb.language())
    _ruby_parser = _TSParser(_RUBY_LANGUAGE)
    _TS_RUBY_AVAILABLE = True
except Exception:
    _TS_RUBY_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_RUBY_EXTS = (".rb",)

# ── Taint source detection ────────────────────────────────────────────────────

# Rack/Rails request accessor methods returning user-controlled strings
_REQUEST_METHODS = frozenset({
    "params", "GET", "POST", "query_string", "path", "path_info",
    "url", "fullpath", "body", "env", "cookies",
})
# Root identifiers that represent the request/params object
# cookies/session are client-controlled (cookie store) → taint sources
_PARAM_ROOTS = frozenset({"params", "request", "env", "cookies", "session"})

# Sinatra DSL helpers that yield user data
_SINATRA_HELPERS = frozenset({"params", "env", "request"})


def _walk(node):
    """Yield node and all descendants in pre-order."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _call_receiver_method(node) -> tuple[str, str]:
    """Return (receiver_text, method_text) for a call node, or ('', '')."""
    if node.type != "call":
        return "", ""
    recv = node.child_by_field_name("receiver")
    meth = node.child_by_field_name("method")
    r = recv.text.decode("utf-8", errors="replace") if recv else ""
    m = meth.text.decode("utf-8", errors="replace") if meth else ""
    return r, m


def _is_request_source(node) -> bool:
    """True when node directly produces user-controlled data."""
    if node is None:
        return False

    # params[:id], params["name"], request.GET["key"], env["HTTP_..."]
    if node.type == "element_reference":
        nc = node.named_children
        if not nc:
            return False
        obj = nc[0]
        # Direct params[key]
        if obj.type == "identifier" and obj.text.decode() in _PARAM_ROOTS:
            return True
        # request.params["key"], request.GET["key"]
        if obj.type == "call":
            _, meth = _call_receiver_method(obj)
            if meth in _REQUEST_METHODS:
                recv = obj.child_by_field_name("receiver")
                if recv and recv.text.decode() in ("request", "env"):
                    return True

    # request.path, request.url, request.query_string, request.body
    if node.type == "call":
        recv_text, meth_text = _call_receiver_method(node)
        if recv_text in ("request", "req") and meth_text in _REQUEST_METHODS:
            return True

    return False


# ── Taint-propagating calls ───────────────────────────────────────────────────

# Methods that return a tainted string when given tainted args
_STRING_METHODS = frozenset({
    "to_s", "strip", "chomp", "chop", "downcase", "upcase", "squeeze",
    "gsub", "sub", "tr", "split", "join", "format", "sprintf",
    "encode", "force_encoding", "html_escape",
    "CGI.escape", "URI.encode",
})


# ── Taint state helpers ───────────────────────────────────────────────────────

def _is_tainted(node, tainted: set[str], tainted_methods: set[str],
                tainted_ivars: "frozenset | set" = frozenset()) -> bool:
    """Return True if this node carries taint."""
    if node is None:
        return False

    if node.type == "identifier":
        return node.text.decode("utf-8", errors="replace") in tainted

    # @instance_variable taint — Rails controllers use @var = params[:x]
    if node.type == "instance_variable":
        name = node.text.decode("utf-8", errors="replace").lstrip("@")
        return name in tainted_ivars

    if _is_request_source(node):
        return True

    # "SELECT...#{id}" — string with interpolation
    if node.type == "string":
        for child in node.children:
            if child.type == "interpolation":
                for expr in child.named_children:
                    if _is_tainted(expr, tainted, tainted_methods, tainted_ivars):
                        return True
        return False

    # "a" + b — binary concatenation
    if node.type == "binary":
        return any(_is_tainted(c, tainted, tainted_methods, tainted_ivars)
                   for c in node.named_children)

    # tainted_var.some_method  (propagates taint through most string methods)
    if node.type == "call":
        if _is_request_source(node):
            return True
        recv = node.child_by_field_name("receiver")
        meth = node.child_by_field_name("method")
        # Method on tainted receiver propagates (e.g. id.to_s, name.strip)
        if recv is not None and _is_tainted(recv, tainted, tainted_methods, tainted_ivars):
            return True
        # Named method whose body returns tainted data
        if meth is not None:
            mname = meth.text.decode("utf-8", errors="replace")
            if mname in tainted_methods:
                return True
        return False

    # element_reference: tainted[x]
    if node.type == "element_reference":
        if _is_request_source(node):
            return True
        nc = node.named_children
        return bool(nc) and _is_tainted(nc[0], tainted, tainted_methods, tainted_ivars)

    # Parenthesized / grouped expression
    if node.type == "parenthesized_statements" and node.named_children:
        return _is_tainted(node.named_children[0], tainted, tainted_methods, tainted_ivars)

    return False


# ── Taint collection ──────────────────────────────────────────────────────────

def _collect_assignments(root, tainted: set[str], tainted_methods: set[str],
                          tainted_ivars: set[str]) -> bool:
    """Walk assignment nodes and mark tainted variables. Returns True if changed."""
    changed = False
    for node in _walk(root):
        if node.type != "assignment":
            continue
        lhs = node.child_by_field_name("left")
        rhs = node.child_by_field_name("right")
        if lhs is None or rhs is None:
            continue
        if lhs.type == "identifier":
            var = lhs.text.decode("utf-8", errors="replace")
            if var not in tainted and _is_tainted(rhs, tainted, tainted_methods, tainted_ivars):
                tainted.add(var)
                changed = True
        # @var = tainted — instance variable assignment (Rails controllers)
        elif lhs.type == "instance_variable":
            ivar = lhs.text.decode("utf-8", errors="replace").lstrip("@")
            if ivar not in tainted_ivars and _is_tainted(rhs, tainted, tainted_methods, tainted_ivars):
                tainted_ivars.add(ivar)
                changed = True
    return changed


def _collect_method_taint(root, tainted: set[str], tainted_methods: set[str],
                           tainted_ivars: set[str]) -> bool:
    """Find method defs that return tainted data. Returns True if changed."""
    changed = False
    for node in _walk(root):
        if node.type != "method":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        mname = name_node.text.decode("utf-8", errors="replace")
        if mname in tainted_methods:
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        # Check explicit return statements and last expression
        for sub in _walk(body):
            if sub.type == "return":
                for child in sub.named_children:
                    if _is_tainted(child, tainted, tainted_methods, tainted_ivars):
                        tainted_methods.add(mname)
                        changed = True
                        break
    return changed


def _build_taint(root) -> tuple[set[str], set[str], set[str]]:
    """Fixed-point taint collection, max 8 passes."""
    tainted: set[str] = set()
    tainted_methods: set[str] = set()
    tainted_ivars: set[str] = set()
    for _ in range(8):
        c1 = _collect_assignments(root, tainted, tainted_methods, tainted_ivars)
        c2 = _collect_method_taint(root, tainted, tainted_methods, tainted_ivars)
        if not c1 and not c2:
            break
    return tainted, tainted_methods, tainted_ivars


# ── Sink definitions ──────────────────────────────────────────────────────────

# SQL sinks: receiver-less or class-method style
_SQL_METHODS = frozenset({
    "find_by_sql", "where", "having", "order", "group", "select",
    "execute", "exec", "query", "run",
})
# SQL sinks that are always dangerous (raw SQL methods)
_SQL_RAW_METHODS = frozenset({
    "find_by_sql", "execute", "exec", "query", "run",
})
# Command execution methods (no receiver needed)
_CMD_METHODS = frozenset({"system", "exec", "spawn", "popen", "popen2", "popen3"})
# File I/O methods on File/IO constants
_FILE_METHODS = frozenset({
    "open", "read", "write", "readlines", "foreach",
    "binread", "binwrite", "new",
})
# Dir methods
_DIR_METHODS = frozenset({"glob", "[]", "entries", "children"})
# SSRF: methods/functions that make HTTP requests
_HTTP_METHODS = frozenset({
    "open", "get", "post", "put", "delete", "patch", "head",
    "get_response", "start",
})
# XSS: render hash keys indicating unescaped output
_RENDER_UNSAFE_KEYS = frozenset({"plain", "html", "text", "body", "inline", "xml", "json"})
# Code eval methods that execute arbitrary Ruby
_EVAL_METHODS = frozenset({"eval", "instance_eval", "class_eval", "module_eval", "binding_eval"})
# SSTI: template engines that evaluate the template string itself
# ERB.new(tainted) — first arg is the template; .result evaluates it
# Haml::Engine.new(tainted), Liquid::Template.parse(tainted)
_SSTI_RECEIVERS = frozenset({"ERB", "Haml::Engine"})
_SSTI_PARSE_RECEIVERS = frozenset({"Liquid::Template", "Mustache"})
# Mass assignment sinks: AR/Mongoid methods that accept a hash of attributes
_MASS_ASSIGN_METHODS = frozenset({
    "create", "create!", "update", "update!", "update_all",
    "new", "build", "assign_attributes", "attributes=",
})


# ── Emit helper ──────────────────────────────────────────────────────────────

def _emit(
    findings: list[Finding],
    seen: set[tuple],
    file_path: str,
    line: int,
    lines: list[str],
    repo_url: str,
    vuln_type: VulnType,
    severity: Severity,
    rule_id: str,
    desc: str,
) -> None:
    key = (rule_id, line)
    if key in seen:
        return
    seen.add(key)
    content = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    findings.append(Finding(
        vuln_type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_number=line,
        line_content=content,
        description=desc,
        rule_id=rule_id,
        repo_url=repo_url,
        snippet="\n".join(lines[max(0, line - 3): min(len(lines), line + 2)]),
    ))


# ── Sink checking ─────────────────────────────────────────────────────────────

def _arg_nodes(call_node) -> list:
    """Return named argument nodes from a call's argument_list."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    return list(args.named_children)


def _check_sinks(
    root,
    tainted: set[str],
    tainted_methods: set[str],
    tainted_ivars: set[str],
    file_path: str,
    lines: list[str],
    repo_url: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple] = set()

    def taint(n):
        return _is_tainted(n, tainted, tainted_methods, tainted_ivars)

    for node in _walk(root):
        # ── Backtick / subshell execution: `ls #{user_input}` ────────────────
        if node.type == "subshell":
            line = node.start_point[0] + 1
            for child in node.children:
                if child.type == "interpolation":
                    for expr in child.named_children:
                        if taint(expr):
                            _emit(findings, seen, file_path, line, lines, repo_url,
                                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                                  "RBAST-CMD-001",
                                  "User-controlled data in backtick execution — OS command injection risk")
                            break

        if node.type != "call":
            continue

        recv = node.child_by_field_name("receiver")
        meth_node = node.child_by_field_name("method")
        if meth_node is None:
            continue

        recv_text = recv.text.decode("utf-8", errors="replace") if recv else ""
        meth_text = meth_node.text.decode("utf-8", errors="replace")
        line = node.start_point[0] + 1
        arg_nodes = _arg_nodes(node)

        # ── Command injection (checked before SQL: exec/system/spawn without receiver)
        # system("ls " + id), exec(cmd), spawn(cmd)
        if meth_text in _CMD_METHODS and not recv_text and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                  "RBAST-CMD-001",
                  f"User-controlled data flows into {meth_text}() — OS command injection risk")

        # ── SQL injection ─────────────────────────────────────────────────
        elif meth_text in _SQL_METHODS and arg_nodes \
                and recv_text not in ("Process", "PTY", "Open3"):
            first = arg_nodes[0]
            # `where` / `having` with Hash arg is safe; string or interpolation is not
            if first.type not in ("hash", "bare_hash") and taint(first):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SQL_INJECTION, Severity.HIGH,
                      "RBAST-SQL-001",
                      f"User-controlled data flows into .{meth_text}() — SQL injection risk")

        # IO.popen(cmd), Open3.popen3(cmd)
        elif meth_text in ("popen", "popen2", "popen3", "popen2e") and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                  "RBAST-CMD-001",
                  f"User-controlled data flows into {recv_text}.{meth_text}() — OS command injection risk")

        # Process.exec/spawn, PTY.spawn, Open3.capture2/2e/3
        elif recv_text == "Process" and meth_text in ("exec", "spawn") \
                and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                  "RBAST-CMD-002",
                  f"User-controlled data flows into Process.{meth_text}() — OS command injection risk")

        elif recv_text == "PTY" and meth_text == "spawn" \
                and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                  "RBAST-CMD-002",
                  "User-controlled data flows into PTY.spawn() — OS command injection risk")

        elif recv_text == "Open3" and meth_text in ("capture2", "capture2e", "capture3") \
                and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                  "RBAST-CMD-002",
                  f"User-controlled data flows into Open3.{meth_text}() — OS command injection risk")

        # ── Path traversal ────────────────────────────────────────────────
        elif recv_text in ("File", "IO") and meth_text in _FILE_METHODS:
            if arg_nodes and taint(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.HIGH,
                      "RBAST-PATH-001",
                      f"User-controlled path flows into {recv_text}.{meth_text}() — path traversal risk")

        elif recv_text in ("Dir", "FileUtils") and meth_text in _DIR_METHODS | {"cp", "rm", "mv"}:
            if arg_nodes and taint(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.PATH_TRAVERSAL, Severity.MEDIUM,
                      "RBAST-PATH-001",
                      f"User-controlled path flows into {recv_text}.{meth_text}() — path traversal risk")

        # ── XSS: render plain:/html:/text: ───────────────────────────────
        elif meth_text == "render" and not recv_text:
            for arg in arg_nodes:
                if arg.type == "pair":
                    key_node = arg.named_children[0] if arg.named_children else None
                    val_node = arg.named_children[1] if len(arg.named_children) > 1 else None
                    if key_node and val_node:
                        key_text = key_node.text.decode("utf-8", errors="replace").strip(": ")
                        if key_text in _RENDER_UNSAFE_KEYS and taint(val_node):
                            _emit(findings, seen, file_path, line, lines, repo_url,
                                  VulnType.XSS, Severity.HIGH,
                                  "RBAST-XSS-001",
                                  f"User-controlled data in render {key_text}: — XSS risk if HTML")

        # ── Open redirect: redirect_to tainted ───────────────────────────
        elif meth_text == "redirect_to" and not recv_text:
            if arg_nodes and taint(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.OPEN_REDIRECT, Severity.MEDIUM,
                      "RBAST-REDIR-001",
                      "User-controlled URL in redirect_to — open redirect risk")

        # ── SSRF: URI.open, Net::HTTP.get, HTTParty.get ──────────────────
        elif meth_text in _HTTP_METHODS and arg_nodes and taint(arg_nodes[0]):
            if recv_text in ("URI", "Net::HTTP", "HTTParty", "Faraday",
                             "RestClient", "Typhoeus", "HTTP", "Excon") or (
                not recv_text and meth_text == "open"
            ):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSRF, Severity.HIGH,
                      "RBAST-SSRF-001",
                      f"User-controlled URL flows into {recv_text or ''}.{meth_text}() — SSRF risk")

        # ── Insecure deserialization: Marshal.load / Marshal.restore ─────
        elif recv_text == "Marshal" and meth_text in ("load", "restore"):
            if arg_nodes and taint(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                      "RBAST-DESER-001",
                      "User-controlled data flows into Marshal.load() — deserialization / RCE risk")

        # ── Insecure deserialization: YAML.load(tainted) ─────────────────
        # YAML.load with user-controlled input enables arbitrary object instantiation (Psych gadgets)
        elif recv_text == "YAML" and meth_text in ("load", "unsafe_load") \
                and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.INSECURE_DESERIALIZATION, Severity.CRITICAL,
                  "RBAST-DESER-002",
                  "User-controlled data flows into YAML.load() — arbitrary object instantiation / RCE risk")

        # ── Code execution: eval(tainted) ─────────────────────────────────
        elif meth_text in _EVAL_METHODS and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                  "RBAST-EVAL-001",
                  f"User-controlled data flows into {meth_text}() — arbitrary code execution risk")

        # ── Arbitrary method dispatch: obj.send(tainted_method) ──────────
        # Object#send with a tainted method name allows calling any method on the receiver
        elif meth_text in ("send", "public_send") and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                  "RBAST-EVAL-002",
                  f"User-controlled method name in .{meth_text}() — arbitrary method dispatch / RCE risk")

        # ── SSTI: ERB.new(tainted), Haml::Engine.new(tainted) ────────────
        # Checked BEFORE mass-assignment since "new" appears in both and SSTI is more specific.
        elif recv_text in _SSTI_RECEIVERS and meth_text == "new":
            if arg_nodes and taint(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSTI, Severity.CRITICAL,
                      "RBAST-SSTI-001",
                      f"User-controlled data flows into {recv_text}.new() — SSTI/code execution risk")

        # ── SSTI: Liquid::Template.parse(tainted) ────────────────────────
        elif recv_text in _SSTI_PARSE_RECEIVERS and meth_text == "parse":
            if arg_nodes and taint(arg_nodes[0]):
                _emit(findings, seen, file_path, line, lines, repo_url,
                      VulnType.SSTI, Severity.CRITICAL,
                      "RBAST-SSTI-001",
                      f"User-controlled data flows into {recv_text}.parse() — SSTI risk")

        # ── ReDoS: Regexp.new(tainted) — user-controlled regex pattern ────
        # Checked BEFORE mass-assignment since "new" appears in _MASS_ASSIGN_METHODS.
        elif recv_text == "Regexp" and meth_text == "new" and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.REDOS, Severity.HIGH,
                  "RBAST-REDOS-001",
                  "User-controlled data flows into Regexp.new() — ReDoS / regex injection risk")

        # ── ReDoS: str.match(tainted_pattern) — receiver-less or tainted arg ─
        elif meth_text == "match" and arg_nodes and taint(arg_nodes[0]) and not recv_text:
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.REDOS, Severity.MEDIUM,
                  "RBAST-REDOS-001",
                  "User-controlled regex pattern in .match() — ReDoS risk")

        # ── Mass assignment: Model.create(params) / model.update(params) ─
        elif meth_text in _MASS_ASSIGN_METHODS and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.SQL_INJECTION, Severity.MEDIUM,
                  "RBAST-MASS-001",
                  f"User-controlled hash flows into .{meth_text}() — mass assignment risk")

        # ── XXE: Nokogiri::XML.parse(tainted) without NOENT option ──────────
        elif recv_text in ("Nokogiri::XML", "Nokogiri::HTML", "Nokogiri") \
                and meth_text in ("parse", "read", "from_memory") \
                and arg_nodes and taint(arg_nodes[0]):
            _emit(findings, seen, file_path, line, lines, repo_url,
                  VulnType.XXE, Severity.HIGH,
                  "RBAST-XXE-001",
                  f"User-controlled XML input to {recv_text}.{meth_text}() — XXE risk if external entities enabled")

    return findings


# ── Analyzer ──────────────────────────────────────────────────────────────────

class RubyASTAnalyzer(BaseAnalyzer):
    """Ruby AST taint analyzer (tree-sitter-ruby).

    Covers .rb files — Rails, Sinatra, and plain Rack handler patterns.
    """

    supported_extensions = _RUBY_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_RUBY_AVAILABLE:
            return []
        if not file_path.endswith(".rb"):
            return []
        try:
            tree = _ruby_parser.parse(content.encode("utf-8", errors="replace"))
        except Exception:
            return []

        lines = content.splitlines()
        tainted, tainted_methods, tainted_ivars = _build_taint(tree.root_node)
        # Do not bail out when tainted is empty — direct request-source-to-sink flows
        # (e.g. User.create(params[:user])) are still detected by _is_request_source
        # inside _is_tainted, so _check_sinks must run even with no variable assignments.
        return _check_sinks(
            tree.root_node, tainted, tainted_methods, tainted_ivars, file_path, lines, repo_url
        )
