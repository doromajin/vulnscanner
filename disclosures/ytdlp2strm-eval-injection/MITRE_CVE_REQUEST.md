# MITRE CVE ID Request — ytdlp2STRM Eval Injection (RCE)

## 提出先・手順

### 方法A: Web フォーム（推奨）
1. https://cveform-legacy.mitre.org を開く
2. 以下「Web フォーム入力値」セクションを参照して各フィールドを入力
3. Submit → MITRE から確認メールが届く（数営業日）

### 方法B: メール直接送信（フォームが不安定な場合）
- **宛先**: cve-request@mitre.org
- **件名**: `CVE ID Request: RCE via Eval Injection in ytdlp2STRM <= 1.1.1 (CWE-95)`
- **本文**: 以下「Email 本文」セクションをそのまま使用

---

## Web フォーム入力値

| フィールド | 入力値 |
|-----------|--------|
| **Request Type** | `Report Vulnerability/Request CVE ID` |
| **Your e-mail address** | `doromajin.sec@proton.me` |
| **PGP Key** | （空欄で可） |

▼ Request Type 選択後に展開される追加フィールド:

| フィールド | 入力値 |
|-----------|--------|
| **Vulnerability Type** | `Code Execution` |
| **Attack Type** | `Remote` |
| **Vendor** | `fe80Grau` |
| **Product** | `ytdlp2STRM` |
| **Version** | `<= 1.1.1` |
| **Fixed Version** | `1.1.2` |
| **References** | `https://github.com/fe80Grau/ytdlp2STRM/issues/122` および `https://github.com/fe80Grau/ytdlp2STRM/commit/ca1afec2f947691224e4c57fea4dc690003096f5` |
| **Discoverer** | `doromajin` |

**Description フィールド** → 以下の「CVE Description」をそのまま貼り付け

---

## CVE Description（フォームの Description フィールドに貼り付け）

```
ytdlp2STRM through version 1.1.1 is vulnerable to Remote Code Execution (RCE)
via Eval Injection (CWE-95) in the CLI plugin dispatch mechanism combined with
an unauthenticated WebSocket command handler (CWE-306).

In cli.py line 65, the --media / -m argument (the plugin name) is concatenated
directly into a Python eval() call:

    r = eval("{}.{}.{}".format("plugins", method, "to_strm"))(*params)

The web UI exposes a Flask-SocketIO WebSocket endpoint (execute_command) with
no authentication (cors_allowed_origins="*") that spawns cli.py as a subprocess,
passing the -m argument unsanitized. An attacker who can reach the web UI port
can inject a Python expression into the -m value. By appending a '#' character
(a valid Python comment inside eval()) to suppress the trailing '.to_strm'
fragment, the attacker can construct an attribute chain through __builtins__ to
execute arbitrary OS commands:

    -m "youtube.__class__.__init__.__globals__['__builtins__'].eval(
        '__import__(\"os\").system(\"id\")') #"

The official Docker deployment (docker-compose.yml) maps port 5005:5000 and
defaults the Flask host to 0.0.0.0, making the web UI reachable from the LAN.
The sanitize() utility present in utils/sanitize.py was not applied to the
--media argument before the eval() call.

The vulnerability was fixed in version 1.1.2 (commit ca1afec) by replacing
eval() with a safe getattr()-based lookup (getattr(plugins, method, None)),
adding optional HTTP Basic Auth for admin WebSocket routes, and binding the
Flask host to 127.0.0.1 by default.

Two additional issues were addressed in the same fix:
  - Argument injection into yt-dlp via unvalidated media IDs in plugin routes
    (utils/validate_id.py was added with an allowlist regex)
  - The Flask app was previously always bound to 0.0.0.0 regardless of config
```

---

## Email 本文（方法Bで使用）

```
To: cve-request@mitre.org
Subject: CVE ID Request: RCE via Eval Injection in ytdlp2STRM <= 1.1.1 (CWE-95)

Dear MITRE CVE Team,

I am requesting a CVE ID for a Remote Code Execution vulnerability I discovered
in the open-source project ytdlp2STRM, hosted at:
https://github.com/fe80Grau/ytdlp2STRM

The vulnerability has been fixed by the maintainer in version 1.1.2 (released
2026-06-18). I reported the issue via GitHub Issue #122 on 2026-06-17. The
maintainer applied the fix without acknowledging the reporter or publishing a
security advisory. The project's GitHub Security Advisories feature is disabled
(returns 404), preventing submission through the standard GitHub CNA path.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VULNERABILITY DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Product:          ytdlp2STRM
Vendor/Author:    fe80Grau (https://github.com/fe80Grau)
Repository:       https://github.com/fe80Grau/ytdlp2STRM
Affected versions: All versions through 1.1.1 (inclusive)
Fixed version:    1.1.2
Fix commit:       ca1afec2f947691224e4c57fea4dc690003096f5
Fix date:         2026-06-18

CWE:   CWE-95  (Improper Neutralization of Directives in Dynamically
                Evaluated Code — Eval Injection)
       CWE-306 (Missing Authentication for Critical Function)

CVSS v3.1 Vector:  AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS v3.1 Score:   8.1 (HIGH)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TECHNICAL DESCRIPTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ytdlp2STRM is a Python application that downloads media from YouTube, Twitch,
and other platforms and serves them as STRM files for media servers (Jellyfin,
Emby, Kodi). It provides a Flask-SocketIO web UI for management.

--- Vulnerable Code ---

File: cli.py, line 65 (versions <= 1.1.1)

    r = eval("{}.{}.{}".format("plugins", method, "to_strm"))(*params)

The variable `method` is taken directly from the --media / -m command-line
argument without sanitization.

--- Attack Surface ---

The web UI exposes a Flask-SocketIO WebSocket endpoint:

    @socketio.on('execute_command')          # ui/routes.py:216-218
    def handle_command(command):
        _ui.handle_command(command)

No authentication is required (cors_allowed_origins="*"). handle_command()
uses shlex.split() to tokenize the received string and spawns cli.py as a
subprocess via Popen(), passing all arguments including -m as-is. The only
check performed is that the third token equals 'cli.py'; the -m argument
(token 4+) is not validated.

The official docker-compose.yml maps port 5005:5000 and the Flask host
defaults to 0.0.0.0, so any LAN host can reach the WebSocket endpoint.

--- Exploit Path ---

An attacker with network access to the web UI port:

  1. Connects to the WebSocket endpoint (no credentials required).
  2. Emits an execute_command event with payload:
       python cli.py \
         -m "youtube.__class__.__init__.__globals__['__builtins__'].eval(
               '__import__(\"os\").system(\"id\")') #" \
         -p dummy
  3. The server spawns: python -u cli.py -m "<payload>" -p dummy
  4. cli.py sets method = "<payload>"; the eval() constructs:
       plugins.youtube.__class__.__init__.__globals__['__builtins__'].eval(
           '__import__("os").system("id")') #.to_strm
                                             ^^^^^^^^ Python comment — ignored
  5. os.system("id") executes in the server process. Output is streamed back
     to the attacker via the WebSocket command_output event.

--- Fix Applied (commit ca1afec) ---

cli.py:
  - Replaced eval() with getattr(plugins, method, None)
  - Added callable() check before invocation
  - Unknown method names are logged and silently ignored

ui/routes.py:
  - Added _require_admin_auth() before_request hook
  - Optional HTTP Basic Auth for /general, /plugin, /crons, /log,
    /restart_service (activated when credentials set in config.json)

main.py:
  - Flask host made configurable via ytdlp2strm_host in config
  - Defaults to 127.0.0.1 (was hardcoded 0.0.0.0)

utils/validate_id.py (new file):
  - Allowlist regex ^[A-Za-z0-9_.-]+$ for media IDs passed to yt-dlp
  - Prevents yt-dlp argument injection (values starting with '-')

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REFERENCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[1] GitHub Issue (disclosure report):
    https://github.com/fe80Grau/ytdlp2STRM/issues/122

[2] Fix commit (ca1afec):
    https://github.com/fe80Grau/ytdlp2STRM/commit/ca1afec2f947691224e4c57fea4dc690003096f5

[3] Version 1.1.2 (fixed):
    https://github.com/fe80Grau/ytdlp2STRM/blob/main/version.py

[4] Vulnerable file (cli.py, archived):
    https://github.com/fe80Grau/ytdlp2STRM/blob/v1.1.1/cli.py

[5] CWE-95: Eval Injection
    https://cwe.mitre.org/data/definitions/95.html

[6] CWE-306: Missing Authentication for Critical Function
    https://cwe.mitre.org/data/definitions/306.html

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DISCOVERY INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Discoverer:        doromajin
Discovery method:  Static code analysis (AST-based eval injection detection)
Discovery date:    2026-06-17
Disclosure date:   2026-06-17 (GitHub Issue #122)
Fix date:          2026-06-18 (commit ca1afec, maintainer silent fix)
Contact:           doromajin.sec@proton.me

I request that doromajin be credited as the discoverer in the CVE record.

Thank you for your consideration.

doromajin
doromajin.sec@proton.me
```

---

## 技術補足：Issue #122 とサイレントフィックスについて

MITRE への説明として以下の点を追記しておくと審査がスムーズになります。

- 2026-06-17: GitHub Issue #122 で脆弱性を公開報告（メンテナーへの唯一の連絡手段）
- 2026-06-18: メンテナーがコメントなしで `ca1afec` をコミット、Issue をクローズ
- GitHub Security Advisories は当該リポジトリで無効（`/security/advisories/new` が 404）
- メンテナーからの返信・発見者クレジット・リリースノートへの記載なし
- MITRE 直接申請の理由: GitHub CNA 経路が利用不可、90日ルールの期限前に修正済み

これらの事実は Email 本文中の冒頭段落でカバーしています。

---

## 申請後の流れ

| ステップ | 内容 | 目安 |
|---------|------|------|
| MITRE 受理確認 | 確認メールが届く | 1〜3 営業日 |
| CVE ID 発行 | `CVE-2026-XXXXX` 形式で通知 | 1〜2 週間 |
| NVD 公開 | MITRE が CVE List に掲載 | CVE ID 発行後 数日〜数週間 |
| NVD CVSS 採点 | NVD アナリストが独自採点を追加 | 公開後 数週間 |
