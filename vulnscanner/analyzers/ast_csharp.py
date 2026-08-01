"""C# AST taint analyzer (tree-sitter-c-sharp).

Detects user-controlled data from ASP.NET controller parameters, HttpContext,
and WinForms input flowing into dangerous sinks via intra-function fixed-point
taint propagation.

Rule IDs (CSAST-*):
  CSAST-SQL-001  SQL injection (SqlCommand, Dapper, EF Core raw SQL, OleDb, Npgsql)
  CSAST-CMD-001  Command injection (Process.Start / ProcessStartInfo)
  CSAST-PATH-001 Path traversal (File.Read*/Write*, FileStream, StreamReader with user path)
  CSAST-DESER-001 Unsafe deserialization (BinaryFormatter, LosFormatter, ObjectStateFormatter)
"""
from __future__ import annotations

try:
    import tree_sitter_c_sharp as _tscs
    from tree_sitter import Language, Parser as _TSParser
    _CS_LANGUAGE = Language(_tscs.language())
    _cs_parser = _TSParser(_CS_LANGUAGE)
    _TS_CS_AVAILABLE = True
except Exception:
    _TS_CS_AVAILABLE = False

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_CS_EXTS = (".cs",)

# ── ASP.NET parameter attributes that mark user input ─────────────────────────
_ASPNET_PARAM_ATTRS: frozenset[str] = frozenset({
    "FromQuery", "FromRoute", "FromPath", "FromBody", "FromForm",
    "FromHeader", "FromServices",
    "BindRequired", "BindNever",
    # Razor Pages
    "BindProperty",
})

# ── ASP.NET method attributes that indicate action methods ───────────────────
_ASPNET_METHOD_ATTRS: frozenset[str] = frozenset({
    "HttpGet", "HttpPost", "HttpPut", "HttpPatch", "HttpDelete", "HttpHead",
    "Route", "NonAction",
    "WebMethod",  # ASMX Web Services
})

# ── Base class names that indicate controller classes ─────────────────────────
_CONTROLLER_BASE_TYPES: frozenset[str] = frozenset({
    "Controller", "ControllerBase", "ApiController",
    "AsyncController", "RazorPageBase",
})

# ── SQL command constructor types ──────────────────────────────────────────────
_SQL_CMD_CTOR_TYPES: frozenset[str] = frozenset({
    "SqlCommand", "OleDbCommand", "OdbcCommand", "NpgsqlCommand",
    "MySqlCommand", "SqliteCommand", "FbCommand",
    "SqlCeCommand", "OracleCommand",
})

# ── SQL execution methods on IDbCommand / variants ────────────────────────────
_SQL_EXEC_METHODS: frozenset[str] = frozenset({
    "ExecuteNonQuery", "ExecuteNonQueryAsync",
    "ExecuteScalar", "ExecuteScalarAsync",
    "ExecuteReader", "ExecuteReaderAsync",
    "ExecuteXmlReader", "ExecuteXmlReaderAsync",
})

# ── Dapper / direct SQL method calls ─────────────────────────────────────────
# (method_name, sql_arg_index)
_DAPPER_METHODS: dict[str, int] = {
    "Execute":    0, "ExecuteAsync":   0,
    "Query":      0, "QueryAsync":     0,
    "QueryFirst": 0, "QueryFirstAsync": 0,
    "QueryFirstOrDefault": 0,
    "QuerySingle": 0, "QuerySingleAsync": 0,
    "QuerySingleOrDefault": 0,
    "QueryMultiple": 0,
}

# ── EF Core raw SQL methods ────────────────────────────────────────────────────
_EF_RAW_METHODS: frozenset[str] = frozenset({
    "ExecuteSqlRaw", "ExecuteSqlRawAsync",
    "FromSqlRaw",
    "SqlQuery", "SqlQueryRaw",
})

# ── Command injection sinks ────────────────────────────────────────────────────
# Process.Start(filename) or Process.Start(filename, args)
_PROCESS_START_FUNCS: frozenset[str] = frozenset({"Start", "StartAsync"})
_PROCESS_CTX_TYPES: frozenset[str] = frozenset({"Process", "ProcessStartInfo"})

# ── Path traversal sinks ───────────────────────────────────────────────────────
# Static File methods (arg 0 = path)
_FILE_STATIC_METHODS: frozenset[str] = frozenset({
    "ReadAllText", "ReadAllTextAsync",
    "ReadAllBytes", "ReadAllBytesAsync",
    "ReadAllLines", "ReadAllLinesAsync",
    "WriteAllText", "WriteAllTextAsync",
    "WriteAllBytes", "WriteAllBytesAsync",
    "WriteAllLines", "WriteAllLinesAsync",
    "AppendAllText", "AppendAllTextAsync",
    "Open", "OpenRead", "OpenWrite",
    "Create", "CreateText",
    "Delete", "Exists",
    "Copy", "Move",
})
# Constructor types where arg 0 is path
_PATH_CTOR_TYPES: frozenset[str] = frozenset({
    "FileStream", "StreamReader", "StreamWriter",
    "FileInfo", "DirectoryInfo",
    "BinaryReader", "BinaryWriter",
})
# Directory static methods (arg 0 = path)
_DIR_STATIC_METHODS: frozenset[str] = frozenset({
    "GetFiles", "GetDirectories", "GetFileSystemEntries",
    "CreateDirectory", "Delete", "Move", "Exists",
    "EnumerateFiles", "EnumerateDirectories",
})

# ── SSRF sinks — HttpClient / WebClient / WebRequest ─────────────────────────
# Methods where arg[0] (or Uri) is a URL that should not be user-controlled.
_HTTP_CLIENT_ASYNC_METHODS: frozenset[str] = frozenset({
    "GetAsync", "PostAsync", "PutAsync", "PatchAsync", "DeleteAsync", "SendAsync",
    "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync",
})
_WEB_CLIENT_METHODS: frozenset[str] = frozenset({
    "DownloadString", "DownloadStringAsync", "DownloadStringTaskAsync",
    "DownloadData", "DownloadDataAsync", "DownloadDataTaskAsync",
    "DownloadFile", "DownloadFileAsync", "DownloadFileTaskAsync",
    "UploadString", "UploadStringAsync", "UploadStringTaskAsync",
    "UploadData", "UploadDataAsync",
    "OpenRead", "OpenReadAsync", "OpenReadTaskAsync",
})
_WEB_REQUEST_CREATE: frozenset[str] = frozenset({"Create", "CreateDefault", "CreateHttp"})
# URI wrapper types whose constructor propagates taint
_URI_CTOR_TYPES: frozenset[str] = frozenset({"Uri", "UriBuilder", "HttpRequestMessage"})

# ── Unsafe deserialization types ─────────────────────────────────────────────
_UNSAFE_DESER_TYPES: frozenset[str] = frozenset({
    "BinaryFormatter", "LosFormatter", "ObjectStateFormatter",
    "SoapFormatter", "NetDataContractSerializer",
    "JavaScriptSerializer",  # .Deserialize() is unsafe with user-controlled JSON
})

# ── Propagating methods (receiver taint → return taint) ─────────────────────
_PROPAGATING_METHODS: frozenset[str] = frozenset({
    "ToString", "ToLower", "ToUpper", "Trim", "TrimStart", "TrimEnd",
    "Replace", "Substring", "Split", "ToCharArray",
    "Clone", "Copy",
    "Encode", "Decode",  # might not sanitize sufficiently
    "Format",  # String.Format(fmt, tainted) or string.Format(tainted, ...)
    "Concat",  # String.Concat(a, b)
    "Join",    # String.Join(sep, tainted)
    "Insert",  # str.Insert(index, tainted)
    "Remove",
    "PadLeft", "PadRight",
    "Normalize",
    "ToBase64String", "FromBase64String",
    "GetString",  # Encoding.UTF8.GetString(bytes)
    "GetBytes",
    # Nullable / conversion
    "Value",     # nullable.Value
    "GetValueOrDefault",
    # URL-related
    "UrlEncode", "UrlDecode", "HtmlEncode",  # NOT sanitizers for SQL/CMD
})


# ── AST helpers ───────────────────────────────────────────────────────────────

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _txt(node) -> str:
    if node is None:
        return ""
    try:
        return node.text.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _invocation_method_name(node) -> str:
    """Extract method name from invocation_expression.function."""
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    if fn.type == "member_access_expression":
        name = fn.child_by_field_name("name")
        return _txt(name) if name else ""
    if fn.type == "identifier":
        return _txt(fn)
    # Generic: last segment
    raw = _txt(fn)
    return raw.rsplit(".", 1)[-1].split("(")[0].strip()


def _invocation_receiver(node):
    """Return the receiver node for an invocation (the expression before the dot)."""
    fn = node.child_by_field_name("function")
    if fn is not None and fn.type == "member_access_expression":
        return fn.child_by_field_name("expression")
    return None


def _invocation_args(node) -> list:
    """Return the argument expression nodes of an invocation_expression."""
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return []
    result = []
    for child in args_node.named_children:
        if child.type == "argument":
            # In tree-sitter-c#, argument has no 'expression' field —
            # the value is directly named_children[0]
            if child.named_children:
                result.append(child.named_children[0])
        elif child.type not in (",", "(", ")"):
            result.append(child)
    return result


def _ctor_type_name(node) -> str:
    """Extract the type name from an object_creation_expression."""
    t = node.child_by_field_name("type")
    if t is None:
        return ""
    raw = _txt(t)
    # Strip generic type params: SqlCommand<T> → SqlCommand
    return raw.split("<")[0].rsplit(".", 1)[-1]


def _ctor_args(node) -> list:
    """Return constructor argument expression nodes."""
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return []
    result = []
    for child in args_node.named_children:
        if child.type == "argument":
            if child.named_children:
                result.append(child.named_children[0])
        elif child.type not in (",", "(", ")"):
            result.append(child)
    return result


def _is_literal(node) -> bool:
    return node is not None and node.type in (
        "string_literal", "verbatim_string_literal",
        "integer_literal", "real_literal", "character_literal",
        "boolean_literal", "null_literal",
    )


def _attr_name(attr_node) -> str:
    """Extract the attribute name from an attribute node."""
    name = attr_node.child_by_field_name("name")
    if name is None:
        return ""
    raw = _txt(name)
    return raw.rsplit(".", 1)[-1]


# ── Taint expression evaluator ────────────────────────────────────────────────

def _is_tainted(node, tainted: set[str]) -> bool:
    """Return True if the C# expression node carries tainted data."""
    if node is None or _is_literal(node):
        return False
    t = node.type

    if t == "identifier":
        return _txt(node) in tainted

    if t in ("parenthesized_expression",):
        inner = next((c for c in node.named_children), None)
        return _is_tainted(inner, tainted)

    if t == "cast_expression":
        # (Type)expr — tainted if inner is tainted
        expr = node.child_by_field_name("expression")
        return _is_tainted(expr, tainted)

    if t == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return _is_tainted(left, tainted) or _is_tainted(right, tainted)

    if t == "interpolated_string_expression":
        # $"...{userId}..." — tainted if any interpolation is tainted
        for child in node.named_children:
            if child.type == "interpolation":
                # named_children of interpolation: ['{', expr, '}']
                # find the non-brace named child
                for ic in child.named_children:
                    if ic.type != "interpolation_brace":
                        if _is_tainted(ic, tainted):
                            return True
        return False

    if t == "conditional_expression":
        # cond ? a : b — tainted if either branch tainted
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        return _is_tainted(cons, tainted) or _is_tainted(alt, tainted)

    if t == "member_access_expression":
        # obj.Property — tainted if obj is tainted (for simple property access)
        expr = node.child_by_field_name("expression")
        name = node.child_by_field_name("name")
        name_text = _txt(name) if name else ""
        # Propagating properties
        if name_text in ("Value", "Result", "Content", "Data", "Body",
                         "Name", "FileName", "Extension",
                         "QueryString", "RawUrl", "Url", "Path"):
            return _is_tainted(expr, tainted)
        return _is_tainted(expr, tainted)

    if t == "element_access_expression":
        # dict["key"] or list[0] — tainted if base is tainted
        expr = node.child_by_field_name("expression")
        return _is_tainted(expr, tainted)

    if t == "null_coalescing_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return _is_tainted(left, tainted) or _is_tainted(right, tainted)

    if t == "as_expression":
        # expr as Type
        expr = node.child_by_field_name("expression") or (
            node.named_children[0] if node.named_children else None
        )
        return _is_tainted(expr, tainted)

    if t == "invocation_expression":
        method = _invocation_method_name(node)
        recv = _invocation_receiver(node)
        args = _invocation_args(node)

        # Method on tainted receiver
        if method in _PROPAGATING_METHODS:
            if recv and _is_tainted(recv, tainted):
                return True
        # String.Format(tainted_fmt, ...) or String.Format("...", tainted_arg)
        if method == "Format":
            return any(_is_tainted(a, tainted) for a in args)
        # String.Concat / String.Join
        if method in ("Concat", "Join"):
            return any(_is_tainted(a, tainted) for a in args)
        # Encoding.UTF8.GetString(tainted_bytes)
        if method == "GetString" and args:
            return _is_tainted(args[0], tainted)
        return False

    if t == "object_creation_expression":
        ctor = _ctor_type_name(node)
        args = _ctor_args(node)
        # String / Uri wrapper ctors propagate taint from first argument
        if ctor in ("String",) or ctor in _URI_CTOR_TYPES:
            return bool(args) and _is_tainted(args[0], tainted)
        return False

    return False


# ── Parameter seeding ─────────────────────────────────────────────────────────

def _seed_method_params(method_node, tainted: set[str],
                        in_controller: bool) -> None:
    """Seed taint for ASP.NET action method parameters."""
    # Check if the method itself has an HTTP verb attribute
    method_is_action = in_controller  # all public methods in controllers are actions
    for child in method_node.named_children:
        if child.type == "attribute_list":
            for attr in child.named_children:
                if attr.type == "attribute" and _attr_name(attr) in _ASPNET_METHOD_ATTRS:
                    method_is_action = True

    params = method_node.child_by_field_name("parameters")
    if params is None:
        return

    for param in params.named_children:
        if param.type != "parameter":
            continue
        param_name = _txt(param.child_by_field_name("name"))
        if not param_name:
            continue

        # Check for [FromQuery]/[FromBody]/etc. attributes
        has_binding_attr = False
        for child in param.named_children:
            if child.type == "attribute_list":
                for attr in child.named_children:
                    if attr.type == "attribute" and _attr_name(attr) in _ASPNET_PARAM_ATTRS:
                        has_binding_attr = True

        if has_binding_attr or method_is_action:
            tainted.add(param_name)


def _class_is_controller(class_node) -> bool:
    """Return True if this class inherits from a controller base type."""
    base_list = next((c for c in class_node.named_children if c.type == "base_list"), None)
    if base_list is None:
        return False
    base_text = _txt(base_list)
    return any(bt in base_text for bt in _CONTROLLER_BASE_TYPES)


# ── Propagation pass ──────────────────────────────────────────────────────────

def _propagate(body_node, tainted: set[str]) -> bool:
    """One fixed-point propagation pass. Returns True if tainted set grew."""
    changed = False

    for node in _walk(body_node):
        t = node.type

        # var q = "..." + name;  OR  string q = "SELECT * FROM t WHERE n=" + name;
        if t == "variable_declarator":
            nc = node.named_children
            if len(nc) >= 2:
                var_name = _txt(nc[0])
                val_expr = nc[1]
                if var_name and _is_tainted(val_expr, tainted):
                    if var_name not in tainted:
                        tainted.add(var_name)
                        changed = True

        # q = "..." + name;  OR  cmd.CommandText = query;
        elif t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if right and _is_tainted(right, tainted):
                # Simple identifier: q = tainted
                if left and left.type == "identifier":
                    var_name = _txt(left)
                    if var_name not in tainted:
                        tainted.add(var_name)
                        changed = True
                # cmd.CommandText = tainted → mark cmd as tainted
                elif left and left.type == "member_access_expression":
                    prop = left.child_by_field_name("name")
                    recv_node = left.child_by_field_name("expression")
                    prop_text = _txt(prop) if prop else ""
                    if prop_text == "CommandText" and recv_node and recv_node.type == "identifier":
                        obj_name = _txt(recv_node)
                        if obj_name not in tainted:
                            tainted.add(obj_name)
                            changed = True

        # string q = new SqlCommand("SELECT * FROM t WHERE n=" + name).CommandText;
        # object_creation_expression — if SQL cmd type with tainted arg, mark result
        elif t == "object_creation_expression":
            ctor = _ctor_type_name(node)
            args = _ctor_args(node)
            # SqlCommand constructor: new SqlCommand(sql, conn) → if sql tainted, mark variable
            # (handled via variable_declarator / assignment)
            pass

    return changed


# ── Sink detection ────────────────────────────────────────────────────────────

def _detect_sinks(body_node, tainted: set[str], lines: list[str],
                  file_path: str, findings: list[Finding],
                  pinvoke_methods: "set[str] | None" = None) -> None:
    seen: set[tuple] = set()

    def emit(rule_id, vtype, sev, desc, line_no, line_text):
        key = (file_path, line_no, rule_id)
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                vuln_type=vtype, severity=sev,
                file_path=file_path, line_number=line_no,
                line_content=line_text, description=desc,
                rule_id=rule_id,
            ))

    for node in _walk(body_node):
        t = node.type
        line_no = node.start_point[0] + 1
        line_text = (lines[node.start_point[0]].strip()
                     if node.start_point[0] < len(lines) else "")

        # ── SQL via object_creation_expression: new SqlCommand(sql, conn) ──────
        if t == "object_creation_expression":
            ctor = _ctor_type_name(node)
            if ctor in _SQL_CMD_CTOR_TYPES:
                args = _ctor_args(node)
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-SQL-001", VulnType.SQL_INJECTION, Severity.CRITICAL,
                         f"SQL injection via new {ctor}() with user-controlled query string",
                         line_no, line_text)
            # Unsafe deserialization
            if ctor in _UNSAFE_DESER_TYPES:
                emit("CSAST-DESER-001", VulnType.INSECURE_DESERIALIZATION, Severity.HIGH,
                     f"Unsafe deserialization via {ctor} — use JsonSerializer or DataContractSerializer",
                     line_no, line_text)
            # ProcessStartInfo(tainted_filename)
            if ctor in _PROCESS_CTX_TYPES:
                args = _ctor_args(node)
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-CMD-001", VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                         f"Command injection via new {ctor}() with user-controlled command",
                         line_no, line_text)
            # Path traversal constructors: new FileStream(path, ...)
            if ctor in _PATH_CTOR_TYPES:
                args = _ctor_args(node)
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-PATH-001", VulnType.PATH_TRAVERSAL, Severity.HIGH,
                         f"Path traversal via new {ctor}() with user-controlled path",
                         line_no, line_text)

        # ── SQL/CMD/PATH via invocation_expression ─────────────────────────────
        elif t == "invocation_expression":
            method = _invocation_method_name(node)
            recv = _invocation_receiver(node)
            args = _invocation_args(node)
            recv_text = _txt(recv) if recv else ""

            # SQL: cmd.ExecuteNonQuery() when cmd is tainted (via CommandText =)
            if method in _SQL_EXEC_METHODS:
                if recv and recv.type == "identifier" and _txt(recv) in tainted:
                    emit("CSAST-SQL-001", VulnType.SQL_INJECTION, Severity.CRITICAL,
                         f"SQL injection: {method}() called on command with user-controlled CommandText",
                         line_no, line_text)

            # SQL: Dapper conn.Execute(sql) / conn.Query<T>(sql)
            if method in _DAPPER_METHODS:
                sql_idx = _DAPPER_METHODS[method]
                if sql_idx < len(args) and _is_tainted(args[sql_idx], tainted):
                    emit("CSAST-SQL-001", VulnType.SQL_INJECTION, Severity.CRITICAL,
                         f"SQL injection via Dapper {method}() with user-controlled query",
                         line_no, line_text)

            # SQL: EF Core raw SQL: context.Database.ExecuteSqlRaw(sql)
            if method in _EF_RAW_METHODS:
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-SQL-001", VulnType.SQL_INJECTION, Severity.CRITICAL,
                         f"SQL injection via EF Core {method}() with user-controlled query",
                         line_no, line_text)

            # CMD: Process.Start(tainted_filename) or Process.Start(tainted_filename, args)
            if method in _PROCESS_START_FUNCS:
                if "Process" in recv_text:
                    if args and _is_tainted(args[0], tainted):
                        emit("CSAST-CMD-001", VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                             "Command injection via Process.Start() with user-controlled filename",
                             line_no, line_text)
                    elif len(args) > 1 and _is_tainted(args[1], tainted):
                        emit("CSAST-CMD-001", VulnType.COMMAND_INJECTION, Severity.CRITICAL,
                             "Command injection via Process.Start() with user-controlled arguments",
                             line_no, line_text)

            # PATH: File.ReadAllText(path) / File.WriteAllText(path, ...) etc.
            if method in _FILE_STATIC_METHODS:
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-PATH-001", VulnType.PATH_TRAVERSAL, Severity.HIGH,
                         f"Path traversal via File.{method}() with user-controlled path",
                         line_no, line_text)

            # PATH: Directory.GetFiles(path) etc.
            if method in _DIR_STATIC_METHODS:
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-PATH-001", VulnType.PATH_TRAVERSAL, Severity.HIGH,
                         f"Path traversal via Directory.{method}() with user-controlled path",
                         line_no, line_text)

            # P/Invoke: calls to [DllImport]-annotated methods with tainted args
            if pinvoke_methods and method in pinvoke_methods:
                if any(_is_tainted(a, tainted) for a in args):
                    emit("CSAST-FFI-001", VulnType.TRUST_BOUNDARY_VIOLATION, Severity.HIGH,
                         f"{method}() is a P/Invoke method called with user-controlled data — "
                         "validate all arguments before crossing the managed/native boundary "
                         "(CWE-111); ensure buffer sizes and string encoding are correct",
                         line_no, line_text)

            # SSRF: HttpClient.*Async(url) with user-controlled URL
            if method in _HTTP_CLIENT_ASYNC_METHODS:
                # First arg is URL (string or Uri); check it for taint
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-SSRF-001", VulnType.SSRF, Severity.HIGH,
                         f"SSRF via HttpClient.{method}() with user-controlled URL — "
                         "validate scheme/host against an allowlist before making requests",
                         line_no, line_text)

            # SSRF: WebClient.DownloadString/DownloadData/etc. with user-controlled URL
            if method in _WEB_CLIENT_METHODS:
                if args and _is_tainted(args[0], tainted):
                    emit("CSAST-SSRF-001", VulnType.SSRF, Severity.HIGH,
                         f"SSRF via WebClient.{method}() with user-controlled URL — "
                         "validate scheme/host against an allowlist before making requests",
                         line_no, line_text)

            # SSRF: WebRequest.Create(url) / HttpWebRequest.Create(url)
            if method in _WEB_REQUEST_CREATE:
                recv_text_up = recv_text.upper()
                if "REQUEST" in recv_text_up or "WEBREQUEST" in recv_text_up:
                    if args and _is_tainted(args[0], tainted):
                        emit("CSAST-SSRF-001", VulnType.SSRF, Severity.HIGH,
                             f"SSRF via WebRequest.{method}() with user-controlled URL — "
                             "validate scheme/host against an allowlist before making requests",
                             line_no, line_text)


# ── Top-level analysis ────────────────────────────────────────────────────────

def _collect_pinvoke_methods(class_body_node) -> set[str]:
    """Return names of methods with [DllImport] attribute in a class body."""
    result: set[str] = set()
    try:
        for child in class_body_node.named_children:
            if child.type != "method_declaration":
                continue
            # Check for attribute_list containing DllImport
            has_dllimport = False
            for sub in child.children:
                if sub.type == "attribute_list":
                    for attr in sub.named_children:
                        if attr.type == "attribute":
                            name_node = attr.child_by_field_name("name")
                            attr_name = _txt(name_node) if name_node else ""
                            if attr_name in ("DllImport", "DllImportAttribute"):
                                has_dllimport = True
                                break
                if has_dllimport:
                    break
            if has_dllimport:
                name_node = child.child_by_field_name("name")
                if name_node:
                    result.add(_txt(name_node))
    except Exception:
        pass
    return result


def _analyze_method(method_node, lines: list[str], file_path: str,
                    findings: list[Finding], in_controller: bool,
                    pinvoke_methods: "set[str] | None" = None) -> None:
    tainted: set[str] = set()
    _seed_method_params(method_node, tainted, in_controller)

    body = method_node.child_by_field_name("body")
    if body is None:
        return

    for _ in range(10):
        if not _propagate(body, tainted):
            break

    _detect_sinks(body, tainted, lines, file_path, findings,
                  pinvoke_methods=pinvoke_methods or set())


def _analyze_content(content: str, file_path: str) -> list[Finding]:
    try:
        tree = _cs_parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:
        return []

    lines = content.splitlines()
    findings: list[Finding] = []

    for node in _walk(tree.root_node):
        if node.type == "class_declaration":
            in_ctrl = _class_is_controller(node)
            body = node.child_by_field_name("body")
            if body is None:
                continue
            pinvoke = _collect_pinvoke_methods(body)
            for child in body.named_children:
                if child.type == "method_declaration":
                    _analyze_method(child, lines, file_path, findings, in_ctrl,
                                    pinvoke_methods=pinvoke)

    return findings


# ── Analyzer class ────────────────────────────────────────────────────────────

class CSharpASTAnalyzer(BaseAnalyzer):
    """C# AST taint analyzer (.cs)."""

    supported_extensions = _CS_EXTS

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if not _TS_CS_AVAILABLE:
            return []
        return _analyze_content(content, file_path)
