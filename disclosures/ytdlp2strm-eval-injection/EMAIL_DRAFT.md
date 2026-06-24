# Responsible Disclosure Email Draft

> **送信先の探し方:**  
> 1. GitHub プロフィール (https://github.com/fe80Grau) のメールアドレス  
> 2. リポジトリの README / CONTRIBUTING に記載のコンタクト先  
> 3. 上記がなければ GitHub Security Advisory 経路を優先  
>
> **送信前に確認:** PoC コードを本文に含める場合、受信者確認前は省略し  
> 「PoC は要望があれば提供します」とするのが慣例。

---

**Subject:** [Security Disclosure] Unauthenticated RCE via Eval Injection in WebSocket Handler — ytdlp2STRM ≤ v1.1.1

---

Hello,

I am a security researcher and would like to report a **Remote Code Execution (RCE)**
vulnerability I discovered in ytdlp2STRM through static code analysis.

I am following responsible disclosure practices and am contacting you privately before
any public disclosure. I intend to keep this report confidential for **90 days**
(until **2026-09-15**) to allow time for a fix to be released.

---

## Summary

A Python `eval()` call in `cli.py` (line 65) receives an attacker-controlled value
from the WebSocket `execute_command` event without sanitisation. Since the web UI
has no authentication and uses `cors_allowed_origins="*"`, any client that can reach
the web port — including any host on the same network in a typical Docker deployment —
can execute arbitrary OS commands on the server.

- **CVE ID:** Pending (will be requested via GitHub Security Advisory)
- **CVSS v3.1:** 8.1 HIGH — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE:** CWE-95 (Eval Injection), CWE-306 (Missing Authentication)
- **Affected versions:** All versions ≤ 1.1.1

---

## Vulnerability Details

### Location

```
cli.py : line 65
ui/ui.py : lines 202–256 (handle_command)
ui/routes.py : lines 216–218 (WebSocket handler)
```

### Vulnerable Code

```python
# cli.py — line 65
r = eval("{}.{}.{}".format("plugins", method, "to_strm"))(*params)
```

`method` originates from the `--media` / `-m` CLI argument, which is set by the
web UI's `handle_command()` function when it spawns `cli.py` as a subprocess in
response to a WebSocket `execute_command` event. No input validation is applied
to this argument before it is used in `eval()`.

### Attack Flow

1. Attacker connects to the web UI WebSocket endpoint (no credentials required;
   `cors_allowed_origins="*"` is set).
2. Attacker emits an `execute_command` event with a crafted `--media` value
   containing a Python `__builtins__` attribute chain followed by `#` to suppress
   the trailing `.to_strm` fragment.
3. The server spawns `cli.py` with the attacker-controlled argument.
4. `eval()` executes the injected Python expression, which calls
   `__builtins__.eval()` with an arbitrary OS command.
5. Command output is streamed back to the attacker via the WebSocket.

**Note:** This affects Docker deployments where port 5005 is exposed, which is the
configuration shown in the official `docker-compose.yml`.

---

## Impact

- Full remote code execution as the process user
- Read/write access to all Docker volume mounts (including media and config files)
- Potential credential theft (API keys in `config/config.json`)
- Lateral movement to other services on the same network

---

## Recommended Fix

The `eval()` call can be replaced with `getattr()`, which is safe and achieves
the same plugin dispatch behaviour:

```python
# BEFORE (vulnerable)
r = eval("{}.{}.{}".format("plugins", method, "to_strm"))(*params)

# AFTER (safe) — one-line change
plugin_module = getattr(plugins, method, None)
if plugin_module is None or not hasattr(plugin_module, "to_strm"):
    raise ValueError(f"Unknown plugin: {method!r}")
r = plugin_module.to_strm(*params)
```

Additionally, I recommend:
- Adding token-based or session-based authentication to the WebSocket endpoint.
- Validating `method` against the known plugin name allowlist before dispatch.

---

## Proof of Concept

I have a working proof-of-concept that demonstrates command execution via the
WebSocket endpoint. I am happy to share it privately upon request to help with
reproduction and verification.

---

## Disclosure Timeline

| Date | Action |
|------|--------|
| 2026-06-17 | Vulnerability discovered; private disclosure to maintainer |
| 2026-09-15 | Planned public disclosure (90 days) |

I am flexible on the timeline if a patch is in progress and more time is needed.

---

## Reporter

Security Researcher  
Email: doromajin.kiri@gmail.com  
Discovery method: Open-source static analysis tool (AST-based eval injection detection)

---

Thank you for your attention to this matter. I look forward to working with you
toward a fix. Please let me know if you have any questions or need additional
technical details.

Best regards,
doromajin
