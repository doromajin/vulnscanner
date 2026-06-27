#!/usr/bin/env python3
"""VulnScanner 夜間自動改善ループ

提案生成は claude CLI (Claude Code 自身) を subprocess で呼び出す。
ANTHROPIC_API_KEY は不要（Claude Code のログイン認証を使用）。

環境変数 (必須):
  FUGU_API_KEY       FuguAI API キー

環境変数 (省略可):
  FUGU_API_BASE      FuguAI エンドポイント (デフォルト: https://api.fugu.sakana.ai/v1)
  FUGU_MODEL         FuguAI モデル名     (デフォルト: fugu-chat)

出力:
  improvement_proposals/proposal_N.py  各イテレーション提案コード
  proposal_best.py                     最良提案コード
  improvement_report.md                改善レポート
  token_usage.json                     FuguAI トークン使用量記録
"""

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Windows の cp932 エンコーディング問題を回避
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# プロジェクトルートの .env を環境変数へ反映（既にセットされた値は上書きしない）
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=False)
except ImportError:
    pass  # python-dotenv 未インストール時はシステム環境変数のみ使用

# ── 設定定数 ──────────────────────────────────────────────────────────────────
MAX_WINDOW_SECONDS  = 4 * 3600   # 実行ウィンドウ上限
FUGU_TOKEN_BUDGET   = 50_000     # FuguAI 1晩上限トークン
CLAUDE_HALF_WINDOW  = 2 * 3600   # 朝の作業用に 50% (2h) を残す
MIN_FUGU_RESERVE    = 2_000      # ループ1回残せない場合は中断
MAX_RETRIES         = 3          # 一時的エラー時の最大リトライ回数

PROPOSALS_DIR      = Path("improvement_proposals")
BEST_PROPOSAL_FILE = Path("proposal_best.py")
REPORT_FILE        = Path("improvement_report.md")
TOKEN_USAGE_FILE   = Path("token_usage.json")

FUGU_API_KEY      = os.environ.get("FUGU_API_KEY", "")
FUGU_API_BASE     = os.environ.get("FUGU_API_BASE", "https://api.fugu.sakana.ai/v1")
FUGU_MODEL        = os.environ.get("FUGU_MODEL", "fugu-chat")

BASELINE = {"precision": 100.0, "recall": 100.0, "f1": 100.0, "passed": 36}

ANALYZER_FILES = [
    "vulnscanner/analyzers/ssrf.py",
    "vulnscanner/analyzers/open_redirect.py",
    "vulnscanner/analyzers/ssti.py",
    "vulnscanner/analyzers/deserialization.py",
    "vulnscanner/analyzers/command_injection.py",
    "vulnscanner/analyzers/sql_injection.py",
    "vulnscanner/analyzers/path_traversal.py",
    "vulnscanner/analyzers/hardcoded_secrets.py",
    "vulnscanner/analyzers/prototype_pollution.py",
    "vulnscanner/analyzers/xss.py",
]


# ── 例外 ───────────────────────────────────────────────────────────────────────

class FatalError(Exception):
    """継続不可能なエラー。main() でキャッチしてフォアグラウンドに報告・停止する。"""


# ── ユーティリティ ─────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    # \r 進捗表示中の行を確定させてから新しい行を出力する
    print(f"\r[{ts}] {msg}                    ", flush=True)


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)


# ── フォアグラウンド進捗表示付きサブプロセス実行 ─────────────────────────────

def _run_with_ticker(
    cmd: list[str],
    input_text: str,
    encoding: str,
    timeout: float,
    label: str,
) -> subprocess.CompletedProcess:
    """subprocess を別スレッドで実行しながら \r で経過秒を表示する。

    完了後に空白付き改行を出力するので後続の log() と干渉しない。
    例外は呼び出し元へそのままバブルアップする。
    """
    holder: dict = {"result": None, "exc": None}

    def _worker() -> None:
        try:
            holder["result"] = subprocess.run(
                cmd,
                input=input_text,
                capture_output=True,
                text=True,
                encoding=encoding,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            holder["exc"] = exc

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    t_start = time.monotonic()

    while thread.is_alive():
        elapsed = int(time.monotonic() - t_start)
        print(f"\r  [{label}] 待機中... {elapsed}s", end="", flush=True)
        thread.join(timeout=1.0)

    elapsed_final = int(time.monotonic() - t_start)
    print(f"\r  [{label}] 完了 ({elapsed_final}s)                    ", flush=True)

    if holder["exc"] is not None:
        raise holder["exc"]
    return holder["result"]  # type: ignore[return-value]


# ── recall_check 実行 & パース ─────────────────────────────────────────────────

def run_recall_check() -> dict:
    """recall_check.py を実行してメトリクス dict を返す。"""
    if not Path("recall_check.py").exists():
        raise FatalError(
            "recall_check.py が見つかりません。\n"
            "  作業ディレクトリが VulnScanner のルートか確認してください。"
        )
    result = subprocess.run(
        [sys.executable, "recall_check.py"],
        capture_output=True, text=True, timeout=120,
    )
    raw = strip_ansi(result.stdout + result.stderr)

    metrics: dict = {
        "precision": 0.0, "recall": 0.0, "f1": 0.0,
        "passed": 0, "total": 36, "ok": False,
    }
    for key, pat in [
        ("precision", r'Precision:\s+([\d.]+)%'),
        ("recall",    r'Recall:\s+([\d.]+)%'),
        ("f1",        r'F1:\s+([\d.]+)%'),
    ]:
        m = re.search(pat, raw, re.IGNORECASE)
        if m:
            metrics[key] = float(m.group(1))

    if re.search(r'All \d+ checks passed', raw):
        metrics["passed"] = 36
        metrics["ok"]     = True
    else:
        m = re.search(r'(\d+) check\(s\) FAILED', raw)
        if m:
            metrics["passed"] = 36 - int(m.group(1))

    return metrics


# ── プロンプト構築 ─────────────────────────────────────────────────────────────

def _existing_rule_ids() -> list[str]:
    ids: list[str] = []
    for fp in ANALYZER_FILES:
        p = Path(fp)
        if p.exists():
            ids.extend(re.findall(r'"([A-Z]+-\d+)"', p.read_text(encoding="utf-8")))
    return sorted(set(ids))


def build_claude_prompt(target_file: str, previous_attempts: list[str]) -> str:
    content = Path(target_file).read_text(encoding="utf-8")
    existing = ", ".join(_existing_rule_ids())
    prev_note = ""
    if previous_attempts:
        prev_note = (
            "\n\nPrevious attempts this session (do NOT repeat rule IDs or the same approach):\n"
            + "\n".join(f"  - {a}" for a in previous_attempts[-5:])
        )
    return f"""You are a security engineer improving VulnScanner, a whitebox static analysis tool.

Current benchmark: Precision 100% / Recall 100% / F1 100% (36/36 checks passing).
Existing rule IDs: {existing}
{prev_note}

Target file to improve: {target_file}

--- CURRENT FILE CONTENT ---
{content}
--- END FILE CONTENT ---

Task: Propose EXACTLY ONE improvement. Options (pick the most impactful):
  A) Add a new detection rule for a real vulnerability pattern NOT yet covered.
  B) Tighten a rule's regex to eliminate a known false-positive class.

Hard constraints:
  1. Do NOT reduce Precision below 100% (no new FPs on safe code).
  2. Do NOT reduce Recall below 100% (no missed existing TP cases).
  3. New rule IDs must not duplicate any existing rule ID listed above.
  4. Use pre-compiled regex at module level: re.compile(r'...', flags).
  5. Follow the tuple format used in _RULES in the target file.
  6. Return the COMPLETE modified file content — every line, nothing omitted.

Output ONLY a single JSON object (no markdown fences, no explanation outside JSON):
{{
  "target_file": "{target_file}",
  "rule_id": "<RULE-NNN>",
  "change_summary": "<one sentence: what you added/changed and the real-world vulnerability it catches>",
  "new_content": "<complete file content after your change>"
}}"""


def build_fugu_eval_prompt(
    rule_id: str,
    change_summary: str,
    metrics: dict,
    code_snippet: str,
) -> str:
    status = "ALL PASS" if metrics["ok"] else "FAILED"
    return f"""You are a security static-analysis expert reviewing a rule improvement for VulnScanner.

Proposed change:
  Rule ID : {rule_id}
  Summary : {change_summary}

Benchmark result after applying this change:
  Status    : {status}
  Precision : {metrics['precision']:.1f}%
  Recall    : {metrics['recall']:.1f}%
  F1        : {metrics['f1']:.1f}%
  Checks    : {metrics['passed']}/36

Modified code excerpt (up to 2000 chars):
```python
{code_snippet[:2000]}
```

Rate the improvement quality on a scale of 0-10:
  9-10 : High-impact, catches a real, common vulnerability with high precision
  6-8  : Solid rule, no FPs introduced, realistic vulnerability pattern
  3-5  : Marginal — minor improvement, niche pattern, or precision risk
  0-2  : Benchmark regressed, trivial, or incorrect

Output ONLY a valid JSON object — no other text:
{{"quality_score": <integer 0-10>, "comments": "<one concise sentence>"}}"""


# ── API 呼び出し ───────────────────────────────────────────────────────────────

def _find_claude_cmd() -> list[str]:
    """OS に依存せず claude CLI の呼び出しコマンドリストを返す。

    Windows では shutil.which が .cmd を返す場合があり、
    .cmd/.bat は shell=False では直接実行できないため cmd /c 経由にする。
    見つからない場合は FatalError を送出する。
    """
    import shutil
    path = shutil.which("claude")
    if path:
        if sys.platform == "win32" and Path(path).suffix.lower() in (".cmd", ".bat"):
            return ["cmd", "/c", path]
        return [path]
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        for suffix in (".cmd", ".ps1"):
            candidate = Path(appdata) / "npm" / f"claude{suffix}"
            if candidate.exists():
                if suffix == ".ps1":
                    return ["powershell", "-NonInteractive", "-File", str(candidate)]
                return ["cmd", "/c", str(candidate)]
    raise FatalError(
        "claude コマンドが見つかりません。\n"
        "  Claude Code がインストール済みか、PATH が通っているか確認してください。\n"
        "  インストール: npm install -g @anthropic-ai/claude-code"
    )


# エラー分類パターン
_RETRYABLE_RE = re.compile(
    r'rate.?limit|too many requests|overloaded|503|502|529'
    r'|timed? ?out|network|connection|ECONNRESET|ETIMEDOUT',
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r'not logged in|unauthorized|unauthenticated|authentication'
    r'|401|invalid.{0,10}key|api.?key',
    re.IGNORECASE,
)


def _classify_claude_error(returncode: int, stderr: str) -> str:
    """'retryable' / 'fatal' のいずれかを返す。"""
    if _AUTH_RE.search(stderr):
        return "fatal"
    if _RETRYABLE_RE.search(stderr):
        return "retryable"
    return "fatal"


def call_claude(prompt: str) -> str | None:
    """claude CLI を呼び出す（進捗表示・自動リトライ付き）。

    Returns:
        Claude の応答テキスト。取得できなければ None。
    Raises:
        FatalError: 認証エラーなど継続不可能な場合。
    """
    cmd = _find_claude_cmd() + ["-p", "--output-format", "json"]
    retry_delays = [30, 60, 120]

    for attempt in range(MAX_RETRIES):
        try:
            result = _run_with_ticker(cmd, prompt, "utf-8", 300, "Claude")
        except FileNotFoundError as exc:
            raise FatalError(f"claude CLI が見つかりません: {exc}") from exc
        except subprocess.TimeoutExpired:
            log(f"  claude CLI タイムアウト (300s) [試行 {attempt + 1}/{MAX_RETRIES}]")
            if attempt < MAX_RETRIES - 1:
                delay = retry_delays[attempt]
                log(f"  {delay}秒待機後リトライ...")
                time.sleep(delay)
                continue
            log("  最大リトライに達しました — スキップ")
            return None

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                text = data.get("result", "")
                return text if text else None
            except json.JSONDecodeError as exc:
                log(f"  claude CLI JSON パースエラー: {exc}")
                log(f"  生出力 (先頭200文字): {result.stdout[:200]}")
                return None

        # エラー診断
        severity = _classify_claude_error(result.returncode, result.stderr)
        snippet = result.stderr[:300].strip()
        log(f"  [診断] claude CLI エラー (rc={result.returncode}): {snippet}")

        if severity == "fatal":
            raise FatalError(
                f"claude CLI 致命的エラー (rc={result.returncode}):\n{result.stderr[:600]}\n"
                "  ヒント: `claude auth login` でログイン状態を確認してください。"
            )

        # retryable: 待機してリトライ
        if attempt < MAX_RETRIES - 1:
            delay = retry_delays[attempt]
            log(f"  [診断] 一時的エラー → {delay}秒待機後リトライ ({attempt + 1}/{MAX_RETRIES})")
            time.sleep(delay)
        else:
            log("  最大リトライに達しました — スキップ")
            return None

    return None


def _ensure_openai() -> None:
    """openai パッケージを確認し、未インストールなら自動インストールする。

    インストール失敗は FatalError を送出する。
    """
    try:
        import openai  # noqa: F401
        return
    except ImportError:
        pass
    pkg = "openai==2.44.0"
    log(f"  [自動修正] openai 未インストール — pip install {pkg} を実行します")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise FatalError(
            f"openai パッケージのインストールに失敗しました:\n{r.stderr[:400]}\n"
            f"  手動で実行してください: pip install {pkg}"
        )
    log("  [自動修正] openai インストール完了")


def call_fugu(prompt: str) -> tuple[str | None, int]:
    """FuguAI を呼び出す（進捗表示付き）。戻り値: (response_text, total_tokens_used)"""
    _ensure_openai()
    try:
        from openai import OpenAI
        client = OpenAI(api_key=FUGU_API_KEY, base_url=FUGU_API_BASE)
        holder: dict = {"resp": None, "exc": None}

        def _worker() -> None:
            try:
                holder["resp"] = client.chat.completions.create(
                    model=FUGU_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=512,
                    temperature=0.2,
                )
            except Exception as exc:  # noqa: BLE001
                holder["exc"] = exc

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        t_start = time.monotonic()
        while thread.is_alive():
            elapsed = int(time.monotonic() - t_start)
            print(f"\r  [FuguAI] 待機中... {elapsed}s", end="", flush=True)
            thread.join(timeout=1.0)
        elapsed_final = int(time.monotonic() - t_start)
        print(f"\r  [FuguAI] 完了 ({elapsed_final}s)                    ", flush=True)

        if holder["exc"] is not None:
            raise holder["exc"]

        response = holder["resp"]
        tokens = response.usage.total_tokens if response.usage else 0
        return response.choices[0].message.content, tokens

    except Exception as exc:
        log(f"  FuguAI エラー: {exc}")
        return None, 0


# ── JSON パース ────────────────────────────────────────────────────────────────

def parse_claude_json(raw: str) -> dict | None:
    """Claude 出力から JSON を抽出する。"""
    cleaned = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r'\s*```$', '', cleaned, flags=re.MULTILINE)
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    m = re.search(r'\{.*\}', cleaned, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


def parse_fugu_json(raw: str | None) -> dict | None:
    if not raw:
        return None
    m = re.search(r'\{[^{}]*"quality_score"[^{}]*\}', raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


# ── ファイル操作 ───────────────────────────────────────────────────────────────

def validate_python_syntax(code: str, label: str) -> bool:
    """Python ソースの構文を検証する。エラー内容はログに出力する。"""
    try:
        ast.parse(code)
        return True
    except SyntaxError as exc:
        log(f"  [診断] 構文エラー ({label}): {exc}")
        return False


def apply_proposal(target_file: str, new_content: str) -> str | None:
    """target_file を new_content で上書きしバックアップ内容を返す。失敗時は None。"""
    p = Path(target_file)
    if not p.exists():
        log(f"  対象ファイルが見つかりません: {target_file}")
        return None
    backup = p.read_text(encoding="utf-8")
    try:
        p.write_text(new_content, encoding="utf-8")
    except Exception as exc:
        log(f"  ファイル書き込みエラー: {exc}")
        return None
    return backup


def rollback(target_file: str, backup: str) -> None:
    Path(target_file).write_text(backup, encoding="utf-8")


# ── 出力ファイル管理 ───────────────────────────────────────────────────────────

def save_token_usage(record: dict) -> None:
    TOKEN_USAGE_FILE.write_text(
        json.dumps(record, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_report(
    loop_results: list[dict],
    best_idx: int,
    best_score: float,
    fugu_tokens: int,
    elapsed_sec: float,
) -> None:
    date_str = datetime.now().strftime("%Y-%m-%d")
    mins = elapsed_sec / 60
    header = [
        "# VulnScanner 夜間自動改善レポート",
        "",
        f"- 実行日: {date_str}",
        f"- 経過時間: {mins:.1f} 分",
        f"- FuguAI トークン使用量: {fugu_tokens:,} / {FUGU_TOKEN_BUDGET:,}",
        f"- イテレーション数: {len(loop_results)}",
        "",
        "## ベースライン",
        "",
        "| 指標 | 値 |",
        "|---|---|",
        f"| Precision | {BASELINE['precision']:.1f}% |",
        f"| Recall    | {BASELINE['recall']:.1f}% |",
        f"| F1        | {BASELINE['f1']:.1f}% |",
        f"| チェック  | {BASELINE['passed']}/36 |",
        "",
        "## ループ結果",
        "",
        "| # | ルールID | 概要 | P | R | F1 | 品質 | 経過(s) | 採用 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    rows = []
    for r in loop_results:
        m  = r["metrics"]
        ok = "✓" if r.get("adopted") else "✗"
        summary = r.get("change_summary", "")[:45]
        rows.append(
            f"| {r['iteration']} | {r.get('rule_id','?')} | {summary} "
            f"| {m['precision']:.1f}% | {m['recall']:.1f}% | {m['f1']:.1f}% "
            f"| {r.get('quality_score', '-')} | {r.get('loop_sec', 0):.0f} | {ok} |"
        )
    footer: list[str] = []
    if best_idx >= 0:
        best = loop_results[best_idx]
        footer += [
            "",
            "## 最良改善案",
            "",
            f"- イテレーション: {best['iteration']}",
            f"- ルールID: {best.get('rule_id','?')}",
            f"- 概要: {best.get('change_summary','')}",
            f"- 品質スコア: {best.get('quality_score','-')}/10",
            f"- FuguAI コメント: {best.get('fugu_comment','')}",
            f"- ファイル: `{BEST_PROPOSAL_FILE}`",
        ]
    else:
        footer += ["", "## 最良改善案", "", "採用された提案はありませんでした。"]

    REPORT_FILE.write_text(
        "\n".join(header + rows + footer) + "\n",
        encoding="utf-8",
    )


# ── メインループ ───────────────────────────────────────────────────────────────

def _run_loop(args: argparse.Namespace) -> int:
    """改善ループ本体。終了コード (0/1) を返す。FatalError はバブルアップ。"""
    max_seconds = args.max_hours * 3600
    start_time  = time.monotonic()

    PROPOSALS_DIR.mkdir(exist_ok=True)
    log(f"夜間改善ループ開始 | 最大 {args.max_hours}h | FuguAI 上限 {FUGU_TOKEN_BUDGET:,} tokens")
    if args.dry_run:
        log("[DRY RUN モード] Claude / FuguAI API 呼び出しはスキップします")

    fugu_tokens_used: int         = 0
    iteration:        int         = 0
    best_idx:         int         = -1
    best_score:       float       = 0.0
    loop_results:     list[dict]  = []
    previous_attempts: list[str]  = []
    loop_times:       list[float] = []

    token_record: dict = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "sessions": [],
        "total_tokens": 0,
    }

    while True:
        elapsed = time.monotonic() - start_time

        avg_loop = sum(loop_times) / len(loop_times) if loop_times else 120.0
        if elapsed + avg_loop * 1.5 >= max_seconds:
            log(f"タイムバジェット残量不足 (経過 {elapsed/60:.1f}min, 平均ループ {avg_loop:.0f}s) → 終了")
            break

        if fugu_tokens_used >= FUGU_TOKEN_BUDGET - MIN_FUGU_RESERVE:
            log(f"FuguAI トークン上限に到達 ({fugu_tokens_used:,}/{FUGU_TOKEN_BUDGET:,}) → 終了")
            break

        if elapsed >= CLAUDE_HALF_WINDOW and not args.dry_run:
            log(f"Claude 半ウィンドウ上限 ({CLAUDE_HALF_WINDOW/3600:.1f}h) に到達 → 終了")
            break

        loop_start  = time.monotonic()
        target_file = ANALYZER_FILES[iteration % len(ANALYZER_FILES)]
        log(f"── イテレーション {iteration + 1} | 対象: {target_file} | 経過 {elapsed/60:.1f}min ──")

        # ── 1. Claude に提案を生成させる ────────────────────────────────────────
        if args.dry_run:
            log("[DRY RUN] Claude 呼び出しをスキップ -- 1 イテレーション実施して終了")
            log("recall_check.py 実行中 (dry-run)...")
            m = run_recall_check()
            log(f"  P={m['precision']:.1f}% R={m['recall']:.1f}% F1={m['f1']:.1f}% ({m['passed']}/36)")
            break

        log("Claude: 提案生成中...")
        prompt   = build_claude_prompt(target_file, previous_attempts)
        raw_resp = call_claude(prompt)  # FatalError はバブルアップ

        if not raw_resp:
            log("Claude 応答なし — スキップ")
            iteration += 1
            loop_times.append(time.monotonic() - loop_start)
            continue

        proposal = parse_claude_json(raw_resp)
        if not proposal:
            log("JSON パース失敗 — スキップ")
            previous_attempts.append(f"(json parse error on iteration {iteration + 1})")
            iteration += 1
            loop_times.append(time.monotonic() - loop_start)
            continue

        rule_id     = proposal.get("rule_id", "UNKNOWN")
        change_summ = proposal.get("change_summary", "")
        new_content = proposal.get("new_content", "")

        log(f"  提案: {rule_id}  — {change_summ[:70]}")

        if not new_content:
            log("  new_content が空 — スキップ")
            previous_attempts.append(f"{rule_id}: empty new_content")
            iteration += 1
            loop_times.append(time.monotonic() - loop_start)
            continue

        # Python 構文検証（ファイル書き込み前に弾く）
        if not validate_python_syntax(new_content, rule_id):
            log("  [自動診断] 構文エラーのためスキップ（ロールバック不要）")
            previous_attempts.append(f"{rule_id}: syntax error in proposal")
            iteration += 1
            loop_times.append(time.monotonic() - loop_start)
            continue

        # 提案ファイルを保存
        proposal_path = PROPOSALS_DIR / f"proposal_{iteration + 1:03d}.py"
        proposal_path.write_text(new_content, encoding="utf-8")

        # ── 2. 提案を適用してベンチマーク ────────────────────────────────────────
        backup = apply_proposal(target_file, new_content)
        if backup is None:
            log("  ファイル適用失敗 — スキップ")
            iteration += 1
            loop_times.append(time.monotonic() - loop_start)
            continue

        log("  recall_check.py 実行中...")
        metrics = run_recall_check()  # FatalError はバブルアップ
        log(f"  → P={metrics['precision']:.1f}% R={metrics['recall']:.1f}% "
            f"F1={metrics['f1']:.1f}% ({metrics['passed']}/36) {'OK' if metrics['ok'] else 'FAILED'}")

        # ── 3. FuguAI で品質評価 ─────────────────────────────────────────────────
        quality      = 0
        fugu_comment = ""
        fugu_tokens  = 0

        log("  FuguAI: 品質評価中...")
        fugu_prompt = build_fugu_eval_prompt(rule_id, change_summ, metrics, new_content)
        fugu_raw, fugu_tokens = call_fugu(fugu_prompt)
        fugu_tokens_used += fugu_tokens

        fugu_result = parse_fugu_json(fugu_raw)
        if fugu_result:
            quality      = int(fugu_result.get("quality_score", 0))
            fugu_comment = fugu_result.get("comments", "")
        log(f"  → 品質スコア: {quality}/10  ({fugu_comment[:70]})")

        token_record["sessions"].append({
            "iteration":   iteration + 1,
            "rule_id":     rule_id,
            "tokens":      fugu_tokens,
            "cumulative":  fugu_tokens_used,
            "quality_score": quality,
        })
        token_record["total_tokens"] = fugu_tokens_used
        save_token_usage(token_record)

        # ── 4. 採用判定 ───────────────────────────────────────────────────────────
        composite = quality * (metrics["f1"] / 100.0) if metrics["ok"] else 0.0
        adopted   = metrics["ok"] and composite > best_score and quality >= 5

        if adopted:
            best_score = composite
            best_idx   = len(loop_results)
            BEST_PROPOSAL_FILE.write_text(new_content, encoding="utf-8")
            log(f"  → ★ 採用 (composite={composite:.2f}) — 新ベスト!")
        else:
            reason = (
                "ベンチ失敗" if not metrics["ok"]
                else f"品質不足 ({quality}/10 < 5)" if quality < 5
                else f"スコア不足 ({composite:.2f} <= {best_score:.2f})"
            )
            log(f"  → 棄却 ({reason})")

        if not adopted:
            rollback(target_file, backup)
            log("  ロールバック完了")

        loop_sec = time.monotonic() - loop_start
        loop_times.append(loop_sec)
        log(f"  ループ時間: {loop_sec:.0f}s")

        loop_results.append({
            "iteration":      iteration + 1,
            "rule_id":        rule_id,
            "change_summary": change_summ,
            "target_file":    target_file,
            "metrics":        metrics,
            "quality_score":  quality,
            "fugu_comment":   fugu_comment,
            "adopted":        adopted,
            "loop_sec":       loop_sec,
        })

        previous_attempts.append(f"{rule_id}: {change_summ[:60]}")
        iteration += 1

    # ── 終了処理 ──────────────────────────────────────────────────────────────────
    elapsed_total = time.monotonic() - start_time
    log(
        f"ループ完了 | {iteration} イテレーション | "
        f"{elapsed_total/60:.1f}min | FuguAI {fugu_tokens_used:,} tokens"
    )

    write_report(loop_results, best_idx, best_score, fugu_tokens_used, elapsed_total)
    log(f"レポート出力: {REPORT_FILE}")

    if best_idx >= 0:
        best = loop_results[best_idx]
        log(f"最良提案: {BEST_PROPOSAL_FILE} | {best['rule_id']} (composite={best_score:.2f})")
    else:
        log("最良提案: なし — すべての提案が棄却されました")

    log("最終ベンチマーク確認...")
    final = run_recall_check()
    log(
        f"最終スコア: P={final['precision']:.1f}% R={final['recall']:.1f}% "
        f"F1={final['f1']:.1f}% ({final['passed']}/36) {'OK' if final['ok'] else 'FAILED'}"
    )
    return 0 if final["ok"] else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnScanner 夜間自動改善ループ")
    parser.add_argument("--max-hours", type=float, default=4.0,
                        help="実行ウィンドウ上限（時間, デフォルト 4.0）")
    parser.add_argument("--dry-run", action="store_true",
                        help="API を呼ばず動作確認のみ (recall_check は実行)")
    args = parser.parse_args()

    missing = [k for k in ("FUGU_API_KEY",) if not os.environ.get(k)]
    if missing and not args.dry_run:
        log(f"ERROR: 環境変数未設定: {', '.join(missing)}")
        sys.exit(1)

    try:
        exit_code = _run_loop(args)
    except FatalError as exc:
        print(flush=True)  # \r 進捗行を確定
        print("=" * 60, flush=True)
        print("[FATAL] 継続不可能なエラーが発生しました:", flush=True)
        print(str(exc), flush=True)
        print("=" * 60, flush=True)
        sys.exit(2)
    except KeyboardInterrupt:
        print(flush=True)
        log("中断 (Ctrl+C)")
        sys.exit(130)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
