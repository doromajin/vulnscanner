#!/usr/bin/env python3
"""
Claude Code Pushover notification hook.

Modes (pass as first argument):
  pre   PreToolUse  -- fires before the permission check
        * command matches DENY patterns  -> "will be blocked" warning
        * command not in ALLOW/DENY      -> "approval prompt" alert
        * command matches ALLOW          -> no notification (auto-approved)

  post  PostToolUse -- fires after execution (may fire for blocked tools too)
        * response indicates blocked     -> "was blocked" confirmation

Setup:
  1. Create .claude/pushover_config.json (already gitignored via *.json rule):
       { "token": "YOUR_APP_TOKEN", "user": "YOUR_USER_KEY" }
  2. Get token from https://pushover.net/apps/build
     Get user key from https://pushover.net (top of dashboard)
"""
from __future__ import annotations

import fnmatch
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

# ── Credentials ───────────────────────────────────────────────────────────────
_CFG = Path(__file__).parent / "pushover_config.json"


def _creds() -> tuple[str, str]:
    try:
        c = json.loads(_CFG.read_text(encoding="utf-8"))
        return c.get("token", ""), c.get("user", "")
    except Exception:
        return "", ""


# ── Pattern lists  (keep in sync with .claude/settings.json) ─────────────────
_ALLOW: list[str] = [
    # Bash
    "python*", "pytest*", "vulnscan*",
    "pip list*", "pip show*", "pip freeze*", "pip check*",
    "git add*", "git commit*", "git status*", "git log*",
    "git diff*", "git branch*", "git show*", "git mv*",
    "git apply*", "git clone*", "git push*",
    # PowerShell read-only cmdlets
    "get-childitem*", "get-content*", "select-object*",
    "where-object*", "sort-object*", "foreach-object*", "measure-object*",
]

_DENY: list[str] = [
    "rm*", "curl*", "wget*",
    "remove-item*", "new-item*", "set-content*",
    "out-file*", "copy-item*", "move-item*",
]


def _match(cmd: str, patterns: list[str]) -> bool:
    c = cmd.strip().lower()
    return any(fnmatch.fnmatch(c, p.lower()) for p in patterns)


# ── Pushover sender ───────────────────────────────────────────────────────────
def _send(title: str, msg: str, priority: int = 0) -> None:
    token, user = _creds()
    if not token or not user:
        return  # credentials not configured yet
    try:
        body = urllib.parse.urlencode({
            "token":    token,
            "user":     user,
            "title":    title,
            "message":  msg[:512],
            "priority": priority,
        }).encode()
        urllib.request.urlopen(
            urllib.request.Request(
                "https://api.pushover.net/1/messages.json",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            timeout=5,
        )
    except Exception:
        pass  # never let notification failure block Claude Code


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "pre"
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return

    tool = payload.get("tool_name", "")
    cmd  = payload.get("tool_input", {}).get("command", "")[:200]

    if mode == "pre":
        if _match(cmd, _DENY):
            # Guaranteed notification for deny-list commands (PostToolUse may not fire for denied tools)
            _send(
                title    = f"[deny] ブロック予定 ({tool})",
                msg      = f"$ {cmd}\n-> deny ルールで自動ブロックされます",
                priority = 1,
            )
        elif not _match(cmd, _ALLOW):
            _send(
                title    = f"[prompt] 承認待ち ({tool})",
                msg      = f"$ {cmd}\n-> Claude Code で承認 / 拒否してください",
                priority = 1,
            )

    elif mode == "post":
        # Confirmation if PostToolUse fires for denied tools (behavior may vary by Claude Code version)
        resp = payload.get("tool_response", {})
        text = (str(resp.get("content", "")) + str(resp.get("error", ""))).lower()
        blocked = (
            resp.get("blocked") is True
            or "permission denied" in text
            or "not allowed"       in text
            or "denied by"         in text
        )
        if blocked:
            _send(
                title = f"[blocked] ブロックされました ({tool})",
                msg   = f"$ {cmd}\n-> deny ルールで自動ブロック済み",
            )


if __name__ == "__main__":
    main()
