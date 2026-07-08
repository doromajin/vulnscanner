#!/usr/bin/env python3
"""VulnScanner 改善ループ — Propose → Critique → Revise

1イテレーションの流れ:
  Step 1: Claude  → draft proposal 生成
  Step 2: recall_check (isolated) → draft ベンチマーク評価
  Step 3: FuguAI → 構造化レビュー (critique)
  Step 4: Claude  → FuguAI フィードバックを元に final proposal 生成
  Step 5: recall_check (isolated) → final ベンチマーク評価
  採用判定: P/R/F1 回帰ゲート + composite score

制約:
  - main working tree は絶対に変更しない
  - 評価は temp_eval/ 上の一時コピーでのみ実施
  - 自動 commit / push 禁止
  - 最良提案は improvement_runs/YYYYMMDD/proposal_best.patch に保存 → 朝に人間が git apply

FuguAI 不在時:
  - レビューなし → Revise ステップをスキップ
  - draft を candidate 扱いで保存するが採用しない
  - report に "FuguAI unavailable, no critique/revise performed" と明記

出力先: improvement_runs/YYYYMMDD/
  proposals/proposal_NNN_draft.py     draft 提案コード
  proposals/proposal_NNN_draft.patch  draft パッチ
  proposals/proposal_NNN_final.py     final 提案コード
  proposals/proposal_NNN_final.patch  final パッチ
  fugu_reviews/review_NNN.json        FuguAI 構造化レビュー
  eval_results/eval_NNN_draft.json    draft 評価結果
  eval_results/eval_NNN_final.json    final 評価結果
  proposal_best.py                    最良提案コード
  proposal_best.patch                 最良提案パッチ (朝の承認用)
  improvement_report.md               改善レポート
  token_usage.json                    FuguAI トークン使用量
  claude_usage_state.json             Claude 使用量状態
"""

import argparse
import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=False)
except ImportError:
    pass

# ── 定数 ──────────────────────────────────────────────────────────────────────

# Claude 5h quota guard (5h window, 70% limit = 12600s)
CLAUDE_QUOTA_WINDOW_MIN  = 300
CLAUDE_MAX_USAGE_RATIO   = 0.70
CLAUDE_CALL_OVERHEAD_SEC = 60
CLAUDE_DEFAULT_CALL_SEC  = 60.0
MAX_CLAUDE_USAGE_SEC     = CLAUDE_QUOTA_WINDOW_MIN * 60 * CLAUDE_MAX_USAGE_RATIO  # 12600

# 1回の実行でのAPIコール上限。--max-hours に応じて main() で上書き可能。
# デフォルト80 = 1時間フルラン想定 (proposal+revise で~2call/iter × 40iter)
MAX_CLAUDE_CALLS_PER_RUN = 80

# FuguAI
FUGU_TOKEN_BUDGET        = 200_000
MIN_FUGU_RESERVE         = 2_000
MAX_RETRIES              = 3
FUGU_QUALITY_MIN         = 7          # 採用に必要な最低品質スコア
FUGU_CRITIQUE_MAX_TOKENS = 4096

# ディレクトリ (Task Scheduler から起動しても正しく解決されるよう絶対パスで定義)
BASE_DIR         = Path(__file__).parent
IMPROVEMENT_RUNS_DIR = BASE_DIR / "improvement_runs"
TEMP_EVAL_DIR    = BASE_DIR / "temp_eval"

# 環境変数
FUGU_API_KEY  = os.environ.get("FUGU_API_KEY", "")
FUGU_API_BASE = os.environ.get("FUGU_API_BASE", "https://api.sakana.ai/v1")
FUGU_MODEL    = os.environ.get("FUGU_MODEL", "fugu")

# task_type → Claude モデル対応表（CLI フォールバック用）
_TASK_MODEL_MAP: dict[str, str] = {
    "proposal":  "claude-sonnet-5",            # draft 生成（創造性・セキュリティ知識が必要）
    "report":    "claude-sonnet-5",            # レポート作成
    "revise":    "claude-sonnet-5",             # FuguAI 指示に従って複雑な改訂を行う
    "log":       "claude-haiku-4-5-20251001",  # ログ整理
    "diagnosis": "claude-haiku-4-5-20251001",  # エラー診断
}

# task_type → Anthropic API モデル対応表（ANTHROPIC_API_KEY が設定されている場合に使用）
_API_MODEL_MAP: dict[str, str] = {
    "proposal":  "claude-sonnet-4-6",          # Sonnet — 高精度タスク
    "report":    "claude-sonnet-4-6",
    "revise":    "claude-sonnet-4-6",            # Sonnet — revise は複雑なので軽量モデル不可
    "log":       "claude-haiku-4-5-20251001",
    "diagnosis": "claude-haiku-4-5-20251001",
}

BASELINE = {"precision": 100.0, "recall": 100.0, "f1": 100.0, "passed": 39}

ANALYZER_FILES = [
    # Python AST analyzer — highest improvement potential (#8 conditional taint, #6 framework models)
    "vulnscanner/analyzers/ast_python.py",
    # Java AST-based (taint-aware, FuguAI scores 7+)
    "vulnscanner/analyzers/ast_java.py",
    # Go (Layer-1 regex + Layer-2 taint-lite)
    "vulnscanner/analyzers/go_analyzer.py",
    # Java regex (JNDI, XXE, Spring patterns)
    "vulnscanner/analyzers/java_analyzer.py",
    # Multi-language regex analyzers ordered by improvement potential
    "vulnscanner/analyzers/ssrf.py",
    "vulnscanner/analyzers/deserialization.py",
    "vulnscanner/analyzers/command_injection.py",
    "vulnscanner/analyzers/sql_injection.py",
    "vulnscanner/analyzers/open_redirect.py",
    "vulnscanner/analyzers/path_traversal.py",
    "vulnscanner/analyzers/ssti.py",
    "vulnscanner/analyzers/hardcoded_secrets.py",
    "vulnscanner/analyzers/prototype_pollution.py",
    "vulnscanner/analyzers/xss.py",
    # Newer analyzers
    "vulnscanner/analyzers/weak_crypto.py",
    "vulnscanner/analyzers/ldap_injection.py",
    "vulnscanner/analyzers/nosql_injection.py",
    "vulnscanner/analyzers/csrf.py",
    "vulnscanner/analyzers/ast_php.py",
    "vulnscanner/analyzers/client_side.py",
]


class FatalError(Exception):
    """継続不可能エラー — main() でキャッチして表示・終了する。"""


# ── ユーティリティ ─────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r[{ts}] {msg}                    ", flush=True)


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)


# ── 実行ディレクトリ ───────────────────────────────────────────────────────────

def get_run_dir(started_at: datetime) -> Path:
    run_dir = IMPROVEMENT_RUNS_DIR / started_at.strftime("%Y%m%d")
    for sub in ("proposals", "fugu_reviews", "eval_results"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    return run_dir


# ── サブプロセス ───────────────────────────────────────────────────────────────

def _run_with_ticker(
    cmd: list[str], input_text: str, encoding: str,
    timeout: float, label: str,
) -> subprocess.CompletedProcess:
    holder: dict = {"result": None, "exc": None}

    def _worker() -> None:
        try:
            holder["result"] = subprocess.run(
                cmd, input=input_text, capture_output=True,
                text=True, encoding=encoding, timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            holder["exc"] = exc

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    t0 = time.monotonic()
    while thread.is_alive():
        print(f"\r  [{label}] 思考中... {int(time.monotonic()-t0)}s", end="", flush=True)
        thread.join(timeout=1.0)
    print(f"\r  [{label}] 完了 ({int(time.monotonic()-t0)}s)                    ", flush=True)
    if holder["exc"] is not None:
        raise holder["exc"]  # type: ignore[misc]
    return holder["result"]  # type: ignore[return-value]


_claude_cmd_cache: list[str] | None = None


def _find_claude_cmd() -> list[str]:
    global _claude_cmd_cache
    if _claude_cmd_cache is not None:
        return _claude_cmd_cache
    path = shutil.which("claude")
    if path:
        if sys.platform == "win32" and Path(path).suffix.lower() in (".cmd", ".bat"):
            _claude_cmd_cache = ["cmd", "/c", path]
            return _claude_cmd_cache
        _claude_cmd_cache = [path]
        return _claude_cmd_cache
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        for suffix in (".cmd", ".ps1"):
            candidate = Path(appdata) / "npm" / f"claude{suffix}"
            if candidate.exists():
                if suffix == ".ps1":
                    _claude_cmd_cache = ["powershell", "-NonInteractive", "-File", str(candidate)]
                else:
                    _claude_cmd_cache = ["cmd", "/c", str(candidate)]
                return _claude_cmd_cache
    raise FatalError(
        "claude コマンドが見つかりません。\n"
        "  インストール: npm install -g @anthropic-ai/claude-code"
    )


_RATE_LIMIT_RE = re.compile(
    r'rate.?limit|too many requests|overloaded|529',
    re.IGNORECASE,
)
_RETRYABLE_RE = re.compile(
    r'503|502|timed? ?out|network|connection|ECONNRESET|ETIMEDOUT',
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r'not logged in|unauthorized|unauthenticated|authentication'
    r'|401|invalid.{0,10}key|api.?key',
    re.IGNORECASE,
)


def _classify_claude_error(returncode: int, stderr: str) -> str:
    if _AUTH_RE.search(stderr):
        return "fatal"
    if _RATE_LIMIT_RE.search(stderr):
        return "rate_limit"
    if not stderr.strip() or _RETRYABLE_RE.search(stderr):
        return "retryable"
    return "fatal"


# ── API 呼び出し ───────────────────────────────────────────────────────────────

def call_claude(prompt: str, task_type: str = "proposal") -> tuple[str | None, float, bool]:
    """Claude を呼び出す。ANTHROPIC_API_KEY があれば API、なければ CLI。

    戻り値: (text, elapsed_seconds, rate_limited)
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return _call_claude_api(prompt, task_type)
    return _call_claude_cli(prompt, task_type)


def _call_claude_api(prompt: str, task_type: str = "proposal") -> tuple[str | None, float, bool]:
    """Anthropic Python SDK で Claude API を直接呼び出す。"""
    try:
        import anthropic as _anthropic
    except ImportError:
        raise FatalError("anthropic パッケージが未インストール: pip install anthropic")

    model   = _API_MODEL_MAP.get(task_type, "claude-sonnet-4-6")
    client  = _anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    t_start = time.monotonic()
    retry_delays = [30, 60, 120]

    for attempt in range(MAX_RETRIES):
        holder: dict = {"text": None, "exc": None}

        def _worker() -> None:
            try:
                msg = client.messages.create(
                    model=model,
                    max_tokens=4096,
                    messages=[{"role": "user", "content": prompt}],
                )
                holder["text"] = msg.content[0].text if msg.content else None
            except Exception as exc:  # noqa: BLE001
                holder["exc"] = exc

        t0     = time.monotonic()
        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        while thread.is_alive():
            print(f"\r  [Claude API] 思考中... {int(time.monotonic()-t0)}s", end="", flush=True)
            thread.join(timeout=1.0)
        print(f"\r  [Claude API] 完了 ({int(time.monotonic()-t0)}s)                    ", flush=True)

        exc = holder["exc"]
        if exc is None:
            return holder["text"], time.monotonic() - t_start, False

        err = str(exc)
        log(f"  [Claude API エラー] {err[:200]}")
        if "rate" in err.lower() or "429" in err:
            return None, time.monotonic() - t_start, True
        if attempt < MAX_RETRIES - 1:
            time.sleep(retry_delays[attempt])

    return None, time.monotonic() - t_start, False


def _call_claude_cli(prompt: str, task_type: str = "proposal") -> tuple[str | None, float, bool]:
    """claude CLI を呼び出す（フォールバック）。"""
    model        = _TASK_MODEL_MAP.get(task_type, "claude-sonnet-5")
    cmd          = _find_claude_cmd() + ["--model", model, "-p", "--output-format", "json"]
    retry_delays = [30, 60, 120]
    t_start      = time.monotonic()

    for attempt in range(MAX_RETRIES):
        try:
            result = _run_with_ticker(cmd, prompt, "utf-8", 600, "Claude")
        except FileNotFoundError as exc:
            raise FatalError(f"claude CLI が見つかりません: {exc}") from exc
        except subprocess.TimeoutExpired:
            log(f"  Claude タイムアウト (600s) [試行 {attempt+1}/{MAX_RETRIES}]")
            if attempt < MAX_RETRIES - 1:
                time.sleep(retry_delays[attempt])
                continue
            return None, time.monotonic() - t_start, False

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                text = data.get("result", "")
                return (text if text else None), time.monotonic() - t_start, False
            except json.JSONDecodeError:
                return None, time.monotonic() - t_start, False

        severity = _classify_claude_error(result.returncode, result.stderr)
        log(f"  [診断] Claude エラー (rc={result.returncode}): {result.stderr[:200].strip()}")

        if severity == "fatal":
            raise FatalError(
                f"Claude CLI 致命的エラー (rc={result.returncode}):\n{result.stderr[:600]}\n"
                "  ヒント: `claude auth login` でログイン状態を確認してください。"
            )
        if severity == "rate_limit":
            return None, time.monotonic() - t_start, True

        if attempt < MAX_RETRIES - 1:
            delay = retry_delays[attempt]
            log(f"  → {delay}秒待機後リトライ ({attempt+1}/{MAX_RETRIES})")
            time.sleep(delay)
        else:
            return None, time.monotonic() - t_start, False

    return None, time.monotonic() - t_start, False


def _ensure_openai() -> None:
    try:
        import openai  # noqa: F401
        return
    except ImportError:
        pass
    pkg = "openai==2.44.0"
    log(f"  [自動修正] pip install {pkg}")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise FatalError(f"openai インストール失敗:\n{r.stderr[:400]}")
    log("  [自動修正] openai インストール完了")


def call_fugu(prompt: str, max_tokens: int = 512) -> tuple[str | None, int]:
    max_tokens = max(16, max_tokens)  # Sakana API minimum
    """FuguAI を呼び出す。戻り値: (text, total_tokens)"""
    _ensure_openai()
    from openai import OpenAI
    client = OpenAI(api_key=FUGU_API_KEY, base_url=FUGU_API_BASE)
    retry_delays = [5, 15]

    for attempt in range(MAX_RETRIES):
        holder: dict = {"resp": None, "exc": None}

        def _worker(h: dict = holder) -> None:
            try:
                h["resp"] = client.chat.completions.create(
                    model=FUGU_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=0.2,
                )
            except Exception as exc:  # noqa: BLE001
                h["exc"] = exc

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        t0 = time.monotonic()
        while thread.is_alive():
            print(f"\r  [FuguAI] 思考中... {int(time.monotonic()-t0)}s", end="", flush=True)
            thread.join(timeout=1.0)
        print(f"\r  [FuguAI] 完了 ({int(time.monotonic()-t0)}s)                    ", flush=True)

        if holder["exc"] is not None:
            if attempt < MAX_RETRIES - 1:
                delay = retry_delays[attempt]
                log(f"  FuguAI エラー: {holder['exc']} → {delay}s後リトライ")
                time.sleep(delay)
                continue
            log(f"  FuguAI エラー: {holder['exc']} (最大リトライ到達)")
            return None, 0

        resp   = holder["resp"]
        tokens = resp.usage.total_tokens if resp.usage else 0
        return resp.choices[0].message.content, tokens

    return None, 0


# ── JSON パース ────────────────────────────────────────────────────────────────

def parse_claude_json(raw: str) -> dict | None:
    text = raw.strip()
    # Try 1: direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try 2: strip outer code fence only (first + last line) — handles ```json, ```python, etc.
    m_outer = re.match(r'^```[a-zA-Z]*\s*\n(.*)\n```\s*$', text, re.DOTALL)
    if m_outer:
        inner = m_outer.group(1).strip()
        try:
            return json.loads(inner)
        except json.JSONDecodeError:
            pass
    # Try 3: strip all fence lines (less precise but catches multi-fence responses)
    cleaned = re.sub(r'^```[a-zA-Z]*\s*$', '', text, flags=re.MULTILINE).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Try 4: extract outermost JSON object by brace matching
    start = text.find('{')
    if start != -1:
        depth, end = 0, -1
        for i, ch in enumerate(text[start:], start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end != -1:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass
    return None


def parse_fugu_critique(raw: str | None) -> dict | None:
    if not raw:
        return None
    # 正常パース
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        pass
    # 閉じ括弧なしの切れた JSON を補完してリトライ
    trimmed = raw.strip().rstrip(",")
    try:
        return json.loads(trimmed + "}")
    except json.JSONDecodeError:
        pass
    # 数値フィールドだけ正規表現で救出（テキストフィールドが途中で切れた場合）
    result: dict = {}
    for field, cast in [
        ("quality_score",   int),
        ("reliability",     int),
        ("speed_score",     int),
        ("coverage_score",  int),
        ("fp_reduction",    int),
        ("fn_reduction",    int),
        ("usability",       int),
    ]:
        m = re.search(rf'"{field}"\s*:\s*(\d+)', raw)
        if m:
            result[field] = cast(m.group(1))
    m_bool = re.search(r'"critical_fn_risk"\s*:\s*(true|false)', raw, re.IGNORECASE)
    if m_bool:
        result["critical_fn_risk"] = m_bool.group(1).lower() == "true"
    for field in ("implementation_issues", "missing_tests", "improvement_instructions"):
        m_str = re.search(rf'"{field}"\s*:\s*"((?:[^"\\]|\\.)*)', raw)
        if m_str:
            result[field] = m_str.group(1)
    return result if "quality_score" in result else None


# ── recall_check 実行 ──────────────────────────────────────────────────────────

def _parse_recall_output(raw: str) -> dict:
    metrics: dict = {
        "precision": 0.0, "recall": 0.0, "f1": 0.0,
        "passed": 0, "total": 0, "ok": False,
    }
    for key, pat in [
        ("precision", r'Precision:\s+([\d.]+)%'),
        ("recall",    r'Recall:\s+([\d.]+)%'),
        ("f1",        r'F1:\s+([\d.]+)%'),
    ]:
        m = re.search(pat, raw, re.IGNORECASE)
        if m:
            metrics[key] = float(m.group(1))
    m_all = re.search(r'All (\d+) checks passed', raw)
    if m_all:
        n = int(m_all.group(1))
        metrics["passed"] = n
        metrics["total"]  = n
        metrics["ok"]     = True
    else:
        m_fail = re.search(r'(\d+) check\(s\) FAILED', raw)
        m_tp   = re.search(r'recall\s+(\d+)/(\d+)', raw)
        if m_tp:
            metrics["passed"] = int(m_tp.group(1))
            metrics["total"]  = int(m_tp.group(2))
        elif m_fail:
            metrics["passed"] = 0
            metrics["total"]  = int(m_fail.group(1))
    return metrics


def run_recall_check() -> dict:
    """Main working tree での recall_check 実行（終了時の最終確認専用）。"""
    recall_script = BASE_DIR / "recall_check.py"
    if not recall_script.exists():
        raise FatalError("recall_check.py が見つかりません。")
    result = subprocess.run(
        [sys.executable, str(recall_script)],
        capture_output=True, text=True, timeout=120,
        cwd=str(BASE_DIR),
    )
    raw = strip_ansi(result.stdout + result.stderr)
    metrics = _parse_recall_output(raw)
    if not metrics["ok"] and result.returncode != 0:
        log(f"  [最終チェック失敗] rc={result.returncode} stderr: {result.stderr[:500].strip()}")
    return metrics


def run_recall_check_isolated(target_file: str, new_content: str, run_label: str = "") -> dict:
    """Main working tree を変更せずに提案を評価する。

    vulnscanner/ を temp_eval/<id>/ にコピーし、対象ファイルのみ差し替えて
    recall_check.py を実行する。評価後は一時ディレクトリを完全削除する。
    """
    recall_script = BASE_DIR / "recall_check.py"
    vulnscanner_dir = BASE_DIR / "vulnscanner"
    if not recall_script.exists():
        raise FatalError("recall_check.py が見つかりません。")
    if not vulnscanner_dir.is_dir():
        raise FatalError("vulnscanner/ が見つかりません。")

    suffix   = f"_{run_label}" if run_label else ""
    temp_dir = TEMP_EVAL_DIR / (datetime.now().strftime("%H%M%S_%f") + suffix)
    temp_dir.mkdir(parents=True, exist_ok=True)

    try:
        shutil.copytree(str(vulnscanner_dir), str(temp_dir / "vulnscanner"))
        (temp_dir / Path(target_file)).write_text(new_content, encoding="utf-8")

        # PYTHONPATH で temp_dir を優先させて recall_check.py を直接実行
        # (exec() 方式だと __file__ が未定義になり recall_check.py がクラッシュするため)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(temp_dir.resolve()) + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, str(recall_script)],
            capture_output=True, text=True, timeout=120,
            cwd=str(BASE_DIR), env=env,
        )
        raw = strip_ansi(result.stdout + result.stderr)
        metrics = _parse_recall_output(raw)
        if not metrics["ok"] and result.returncode != 0 and not result.stdout.strip():
            # サブプロセスがクラッシュした場合はエラー内容をログに出す
            log(f"  [isolated eval エラー] rc={result.returncode}: {result.stderr[:300].strip()}")
        return metrics
    finally:
        shutil.rmtree(str(temp_dir), ignore_errors=True)


# ── パッチ / 構文検証 ──────────────────────────────────────────────────────────

def generate_patch(original: str, modified: str, filepath: str) -> str:
    diff = list(difflib.unified_diff(
        original.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile=f"a/{filepath}",
        tofile=f"b/{filepath}",
    ))
    return "".join(diff)


def validate_python_syntax(code: str, label: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError as exc:
        log(f"  [診断] 構文エラー ({label}): {exc}")
        return False


# ── プロンプト ─────────────────────────────────────────────────────────────────

# ファイルコンテンツをプロンプトに埋め込む際の上限。
# これを超えるファイルは先頭75% + 末尾25% に分割してトークンを削減する。
# 精度への影響: アーキテクチャ全体が見えなくなる代わりに、冒頭の設計パターンと
# 末尾の追加挿入点が見えるので提案品質は維持できる。
_PROMPT_FILE_MAX_CHARS = 10_000

_rule_ids_cache: list[str] | None = None
# Rule IDs proposed in the current session — updated after each proposal to prevent
# same-session duplicates (important because cache is built once from disk state).
_proposed_this_session: set[str] = set()


def _existing_rule_ids() -> list[str]:
    """Return all rule IDs found in ANY analyzer file under vulnscanner/analyzers/,
    plus any IDs proposed earlier in the current session."""
    global _rule_ids_cache
    if _rule_ids_cache is not None:
        return sorted(set(_rule_ids_cache) | _proposed_this_session)
    ids: list[str] = []
    analyzers_dir = BASE_DIR / "vulnscanner" / "analyzers"
    for p in analyzers_dir.glob("*.py"):
        try:
            ids.extend(re.findall(r'"([A-Z]+-\d+)"', p.read_text(encoding="utf-8")))
        except Exception:
            pass
    _rule_ids_cache = sorted(set(ids))
    return sorted(set(_rule_ids_cache) | _proposed_this_session)


def _truncate_file_for_prompt(content: str, max_chars: int = _PROMPT_FILE_MAX_CHARS) -> str:
    """大きいファイルをプロンプト用に圧縮する。
    先頭75%（アーキテクチャ・既存パターン）+ 末尾25%（追加挿入点）を残す。
    精度への影響なし: Claude は全体像ではなく設計パターンと末尾を参照して提案する。
    """
    if len(content) <= max_chars:
        return content
    head = int(max_chars * 0.75)
    tail = max_chars - head
    omitted = len(content) - head - tail
    return (
        content[:head]
        + f"\n\n# ... [{omitted} chars omitted — same architecture continues] ...\n\n"
        + content[-tail:]
    )


def _relevant_rule_ids(target_file: str) -> str:
    """プロンプトに埋め込む existing rule IDs を対象ファイル関連に絞る。
    同ファイルにIDがある場合: そのIDを詳細表示 + 他は件数のみ（トークン節約）
    同ファイルにIDがない場合: 全IDを表示（AST系ファイル等）
    """
    all_ids = _existing_rule_ids()
    try:
        file_ids = sorted(set(re.findall(r'"([A-Z]+-\d+)"', Path(target_file).read_text(encoding="utf-8"))))
    except Exception:
        file_ids = []

    if not file_ids:
        # AST系など自ファイルにIDがない場合は全件表示
        return ", ".join(all_ids)

    other_ids = sorted(set(all_ids) - set(file_ids))
    parts = ["In this file: " + ", ".join(file_ids)]
    if other_ids:
        # 他ファイルのIDはプレフィックスごとにサマリーして短縮
        prefixes: dict[str, int] = {}
        for rid in other_ids:
            pfx = rid.rsplit("-", 1)[0]
            prefixes[pfx] = prefixes.get(pfx, 0) + 1
        summary = ", ".join(f"{p}-* ({n})" for p, n in sorted(prefixes.items()))
        parts.append(f"Other files: {summary} — all forbidden to reuse")
    return "\n  ".join(parts)


def _format_previous_attempts(previous_attempts: list[dict], target_file: str = "") -> str:
    if not previous_attempts:
        return ""

    # ファイル固有の試行を優先して見せる（最大7件）、残りは直近グローバル（最大3件）
    file_attempts  = [a for a in previous_attempts if a.get("target_file") == target_file][-7:]
    other_attempts = [a for a in previous_attempts if a.get("target_file") != target_file][-3:]
    combined = file_attempts + other_attempts

    if not combined:
        return ""

    lines = ["\n\nPrevious attempts this session (learn from these — do NOT repeat same approach):"]
    if file_attempts:
        lines.append(f"  [Same file: {target_file}]")
    for a in combined:
        dm = a.get("draft_metrics", {})
        fm = a.get("final_metrics", {})
        tag = f"[{a.get('target_file','?').split('/')[-1]}]" if a.get("target_file") != target_file else ""
        lines.append(
            f"\n  [{a['iteration']}]{tag} {a['rule_id']} — {a['change_summary'][:60]}"
        )
        lines.append(
            f"    Draft eval:  P={dm.get('P','?')}% R={dm.get('R','?')}% "
            f"{'OK' if dm.get('ok') else 'FAILED'}"
        )
        if a.get("fugu_status") == "available":
            lines.append(f"    FuguAI:      quality={a.get('fugu_quality','?')}/10  {a.get('fugu_comment','')[:80]}")
            lines.append(
                f"    Final eval:  P={fm.get('P','?')}% R={fm.get('R','?')}% "
                f"{'OK' if fm.get('ok') else 'FAILED'}"
            )
        elif a.get("fugu_status") == "unavailable":
            lines.append("    FuguAI:      unavailable — revise step was skipped")
        else:
            lines.append(f"    FuguAI:      {a.get('fugu_status','skipped')}")
        lines.append(f"    Decision:    {a['decision']} — {a.get('rejection_reason','')}")
        if a.get("next_hint"):
            lines.append(f"    Next hint:   {a['next_hint']}")
    return "\n".join(lines)


def build_draft_prompt(target_file: str, previous_attempts: list[dict], baseline: dict | None = None) -> str:
    raw_content = Path(target_file).read_text(encoding="utf-8")
    content  = _truncate_file_for_prompt(raw_content)   # トークン節約: 大ファイルは圧縮
    existing = _relevant_rule_ids(target_file)           # 同ファイルのIDを詳細表示、他は件数のみ
    prev     = _format_previous_attempts(previous_attempts, target_file)
    checks   = f"{baseline['passed']}/{baseline['total']}" if baseline and baseline.get("total") else "100%"

    is_ast_java = "ast_java" in target_file
    is_go       = "go_analyzer" in target_file

    lang_hint = ""
    if is_ast_java:
        lang_hint = """
File type: Java AST analyzer (javalang-based taint tracking — NOT regex).
Architecture: _collect_tainted() builds a set of tainted variable names by scanning
LocalVariableDeclaration nodes. _is_tainted() recurses into MemberReference/MethodInvocation.
Detection rules check tainted variables reaching sink MethodInvocations.

Priority additions (AST-level, real CVEs):
  - JAST-SSRF-002: Apache HttpClient/OkHttp execute() where URL arg is tainted
    → detect ClassCreator(type="HttpGet"/"HttpPost") or MethodInvocation(member="execute")
       with a tainted argument tracing to request.getParameter()
  - JAST-SQL-003: Spring JdbcTemplate.query/update with String.format or + concat of tainted
    → detect MethodInvocation(member="query"|"update") on qualifier "jdbcTemplate"
       where argument is BinaryOperation(operator="+") with tainted left/right
  - JAST-SSTI-001: Freemarker Template.process()/Velocity context.evaluate() with tainted vars
    → detect MethodInvocation(member="process"|"evaluate"|"merge") where any arg is tainted
  - JAST-PATH-003: ClassLoader.getResourceAsStream(tainted) / new File(tainted)
"""
    elif is_go:
        lang_hint = """
Language focus: Go (stdlib + Gin, Echo, Fiber, chi, GORM, sqlx)
File architecture: Layer 1 = regex _scan_lines(), Layer 2 = taint-lite _taint_lite().
To add a Layer-2 taint rule, extend _TAINT_SINKS with a new entry.
To add a Layer-1 regex rule, add a tuple to _RULES.

Priority patterns (real CVEs / bug-bounty findings NOT yet covered):
  - SQL taint-lite: GORM.Raw/Exec/Where with fmt.Sprintf(tainted) — extend _TAINT_SINKS
  - SSRF taint-lite: url.Parse + http.NewRequest where host variable comes from r.FormValue
  - Path traversal regex: filepath.Join/filepath.Abs calls where any arg contains ".."
  - Hardcoded creds: struct literal with field name "password"|"secret"|"token" = "..."
"""
    elif "java_analyzer" in target_file:
        lang_hint = """
Language focus: Java / Spring / JEE (regex-based analyzer for patterns javalang can't cover)
Priority patterns (real CVEs / bug-bounty findings):
  - JNDI injection: Spring JNDI lookups, Log4j-style ${jndi:} in logged user input
  - XXE: XMLStreamReader, TransformerFactory, SchemaFactory without feature disabling
  - Deserialization: XStream.fromXML, Jackson @JsonTypeInfo with user-controlled type
  - SSTI: Freemarker Template.getTemplate(userInput), Velocity context.evaluate(userInput)
"""
    elif "ast_python" in target_file:
        lang_hint = """
File type: Python AST analyzer (ast module-based taint tracking).
Architecture: _collect_tainted_names() builds taint set from function args / request.* calls.
_is_tainted_node() checks AST nodes. Sinks are checked in visit_Call().

STRATEGIC PRIORITIES for this file (backlog items):
  #8 Conditional branch taint: Detect guard patterns like `if user_input.isdigit():` before
     a sink call — when the guard uses .isdigit()/.isalpha()/re.match()/re.fullmatch() on
     the tainted variable, the sink inside the if-body should NOT fire.
     Implementation: in visit_If(), check if the test is a method call on a tainted var
     with a sanitizing method name; if so, un-taint that var in the if-body scope.
  #6 Framework-specific sink models: Django ORM `.filter(name=user_input)` is SAFE
     (parameterized), but `.extra(where=[...])`, `.raw(sql)`, `RawSQL()` are UNSAFE.
     Flask `render_template()` is SAFE, `render_template_string(user_input)` is UNSAFE.

Propose ONE new rule addressing either #8 or #6, or any other high-value Python taint rule.
"""

    if is_ast_java:
        constraint4 = (
            "4. IMPORTANT: This file uses javalang AST — do NOT add regex rules. "
            "Add JAST-* rules by extending the existing AST analysis pattern "
            "(javalang node filtering, _is_tainted checks on MethodInvocation arguments)."
        )
    elif is_go:
        constraint4 = (
            "4. For Layer-2 taint rules, extend _TAINT_SINKS dict. "
            "For Layer-1 regex rules, add a tuple to _RULES with re.compile(). "
            "Do NOT mix the two architectures in a single rule."
        )
    elif "ast_python" in target_file:
        constraint4 = (
            "4. This file uses Python ast module — extend the visitor pattern. "
            "For guard-based suppression (#8), modify visit_If() or _collect_tainted_names(). "
            "For safe-sink models (#6), add to the _SAFE_SINKS / _SAFE_METHODS sets. "
            "Do NOT add regex rules to this file."
        )
    else:
        constraint4 = "4. Use pre-compiled regex at module level: re.compile(r'...', flags)."

    return f"""You are a senior security researcher improving VulnScanner, targeting
ENTERPRISE-GRADE detection quality (Google/Microsoft OSS audit level, comparable to CodeQL/Semgrep).

GOAL: Add detection for real vulnerability patterns that have caused actual CVEs or bug-bounty
findings in production software. Prioritize Java and Go coverage, then expand existing analyzers.

Current benchmark: Precision 100% / Recall 100% / F1 100% ({checks} checks passing).
These scores are the REGRESSION GATE — you must not reduce any of them.
Existing rule IDs (ALL are forbidden — do not reuse any):
  {existing}
{prev}{lang_hint}
Target file: {target_file}

--- CURRENT FILE CONTENT ---
{content}
--- END FILE CONTENT ---

Task: Propose EXACTLY ONE new detection rule for a real vulnerability pattern NOT yet covered.
Focus on: real CVE/bug-bounty patterns, broad generality, low FP risk, low FN risk.

Hard constraints:
  1. Precision must stay at 100% (no new false positives on safe code).
  2. Recall must stay at 100% (no missed existing TP cases).
  3. Rule ID must not duplicate any existing ID above.
  {constraint4}
  5. Return the COMPLETE modified file — every line, nothing omitted.
  6. For Java/Go: ensure supported_extensions covers ONLY the target language.

NOTE: This is a DRAFT. A security expert will critique it and you will revise it.

Output ONLY a single JSON object (no markdown fences, no text outside JSON):
{{
  "target_file": "{target_file}",
  "rule_id": "<RULE-NNN>",
  "change_summary": "<one sentence: what you added and the real-world vulnerability it catches>",
  "new_content": "<complete file content after your change>"
}}"""


def build_fugu_critique_prompt(
    rule_id: str, change_summary: str, target_file: str,
    draft_content: str, metrics: dict,
) -> str:
    total  = metrics.get("total", 39)
    failed = total - metrics["passed"]
    status = "ALL PASS" if metrics["ok"] else f"FAILED ({failed} checks failed)"
    prec   = str(round(metrics["precision"], 1))
    rec    = str(round(metrics["recall"], 1))
    f1v    = str(round(metrics["f1"], 1))
    chk    = str(metrics["passed"]) + "/" + str(total)
    return f"""You are a security static-analysis expert performing a structured code review for VulnScanner.
Goal: enterprise-grade detection quality targeting Java, Go, Python, PHP, JS/TS codebases
at the level of Google/Microsoft OSS security audits (comparable to CodeQL/Semgrep precision).

A developer has proposed a new detection rule:
  Rule ID : {rule_id}
  Target  : {target_file}
  Summary : {change_summary}

Benchmark result ({total} existing checks, regression gate):
  Status    : {status}
  Precision : {prec}%
  Recall    : {rec}%
  F1        : {f1v}%
  Checks    : {chk}

Modified file (up to 5000 chars):
```python
{draft_content[:5000]}
```

Perform a thorough structured review across 6 improvement axes. Score each 0-5 (HIGHER = BETTER for all axes):
  - reliability    (確実性): accuracy and correctness - handles edge cases, no logic errors, deterministic
  - speed_score    (速度): runtime efficiency - low-overhead patterns, avoids catastrophic backtracking
  - coverage_score (検出範囲): breadth of real-world attack surface covered across vulnerability types and codebases
  - fp_reduction   (FP削減): how well false positives are avoided - HIGHER means fewer FPs
  - fn_reduction   (FN削減): how well false negatives are avoided - HIGHER means fewer FNs, better recall
  - usability      (業務利用性): report clarity, explanation quality, CI/CD integration readiness, regression safety

Output ONLY a valid JSON object - no other text, no markdown:
{{
  "quality_score": <integer 0-10>,
  "reliability": <integer 0-5>,
  "speed_score": <integer 0-5>,
  "coverage_score": <integer 0-5>,
  "fp_reduction": <integer 0-5>,
  "fn_reduction": <integer 0-5>,
  "usability": <integer 0-5>,
  "critical_fn_risk": <boolean: true only if the rule could suppress detection of real vulnerabilities>,
  "implementation_issues": "<specific technical problems with the regex or logic, or none>",
  "missing_tests": "<vulnerability patterns this rule would miss that it should catch, or none>",
  "improvement_instructions": "<concrete revision instructions - specify exactly what regex/pattern to change, what edge cases to cover, and why>",
  "comments": "<one sentence overall assessment>"
}}"""


def build_revise_prompt(
    target_file: str, original_content: str, draft_content: str,
    fugu_review: dict, draft_metrics: dict,
    rule_id: str, change_summary: str,
) -> str:
    total_chk = draft_metrics.get("total", 39)
    bench     = "ALL PASS" if draft_metrics["ok"] else f"FAILED ({total_chk - draft_metrics['passed']} checks)"
    diff_text = generate_patch(original_content, draft_content, target_file)
    return f"""You are a security engineer improving VulnScanner. You previously proposed a new rule,
and a security expert has reviewed it with specific critique. Revise your proposal to address all feedback.

Original proposal:
  Rule ID : {rule_id}
  Summary : {change_summary}

Draft benchmark: {bench}

Security Expert Review:
  Quality score  : {fugu_review.get('quality_score', '?')}/10
  Reliability    : {fugu_review.get('reliability', '?')}/5   (確実性)
  Speed          : {fugu_review.get('speed_score', '?')}/5   (速度)
  Coverage       : {fugu_review.get('coverage_score', '?')}/5   (検出範囲)
  FP reduction   : {fugu_review.get('fp_reduction', '?')}/5   (FP削減, higher=better)
  FN reduction   : {fugu_review.get('fn_reduction', '?')}/5   (FN削減, higher=better)
  Usability      : {fugu_review.get('usability', '?')}/5   (業務利用性)
  Implementation issues : {fugu_review.get('implementation_issues', 'none')}
  Missing test coverage : {fugu_review.get('missing_tests', 'none')}

IMPROVEMENT INSTRUCTIONS - address ALL of these in your revision:
{fugu_review.get('improvement_instructions', 'No specific instructions provided.')}

Overall assessment: {fugu_review.get('comments', '')}

--- DIFF (what your draft changed from the original) ---
{diff_text}
--- END DIFF ---

--- YOUR DRAFT (complete file - revise from this) ---
{draft_content}
--- END DRAFT ---

Revise the proposal to address every point in the improvement instructions.
Keep rule ID {rule_id} unless the critique says to change the vulnerability type entirely.
Return the COMPLETE revised file - every line, nothing omitted.

Output ONLY a single JSON object (no markdown fences, no text outside JSON):
{{
  "target_file": "{target_file}",
  "rule_id": "{rule_id}",
  "change_summary": "<updated one-sentence summary reflecting your revision>",
  "revision_notes": "<brief note: what specifically you changed based on the critique>",
  "new_content": "<complete revised file content>"
}}"""


# ── 保存関数 ───────────────────────────────────────────────────────────────────

def save_eval_result(run_dir: Path, n: int, stage: str, metrics: dict) -> None:
    path = run_dir / "eval_results" / f"eval_{n:03d}_{stage}.json"
    path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")


def save_fugu_review(run_dir: Path, n: int, review: dict) -> None:
    path = run_dir / "fugu_reviews" / f"review_{n:03d}.json"
    path.write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8")


def load_claude_usage_state(run_dir: Path) -> tuple[float, int]:
    """当日の state ファイルを読み込み、5h ウィンドウ内の使用量を引き継ぐ。

    Returns:
        (carried_used_sec, carried_call_count)
        ウィンドウ外または読み込みエラーの場合は (0.0, 0)
    """
    state_file = run_dir / "claude_usage_state.json"
    if not state_file.exists():
        return 0.0, 0
    try:
        state      = json.loads(state_file.read_text(encoding="utf-8"))
        started_at = datetime.fromisoformat(state.get("window_started_at", ""))
        age_sec    = (datetime.now() - started_at).total_seconds()
        # 5時間ウィンドウを超えていたら引き継がない（レート制限がリセットされている）
        if age_sec > CLAUDE_QUOTA_WINDOW_MIN * 60:
            return 0.0, 0
        return float(state.get("estimated_used_seconds", 0)), int(state.get("claude_call_count", 0))
    except Exception:
        return 0.0, 0


def save_claude_usage_state(
    run_dir: Path,
    window_started_at: datetime,
    claude_used_sec: float,
    total_call_count: int,
    claude_call_sec_list: list[float],
    stop_reason: str | None,
) -> None:
    count       = len(claude_call_sec_list)
    avg_sec     = sum(claude_call_sec_list) / count if count else 0.0
    usage_ratio = claude_used_sec / MAX_CLAUDE_USAGE_SEC if MAX_CLAUDE_USAGE_SEC > 0 else 0.0
    state = {
        "window_started_at":          window_started_at.isoformat(timespec="seconds"),
        "window_length_minutes":       CLAUDE_QUOTA_WINDOW_MIN,
        "max_usage_ratio":             CLAUDE_MAX_USAGE_RATIO,
        "max_allowed_usage_seconds":   MAX_CLAUDE_USAGE_SEC,
        "estimated_used_seconds":      round(claude_used_sec, 1),
        "estimated_usage_ratio":       round(usage_ratio, 4),
        "claude_call_count":           total_call_count,
        "average_claude_call_seconds": round(avg_sec, 1),
        "stop_reason":                 stop_reason,
    }
    (run_dir / "claude_usage_state.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8",
    )


def save_token_usage(run_dir: Path, record: dict) -> None:
    (run_dir / "token_usage.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8",
    )


# ── composite スコア ───────────────────────────────────────────────────────────

def compute_composite(fugu_review: dict) -> float:
    """
    6軸 composite スコア (全軸ポジティブ、高いほど良):
      reliability + speed_score + coverage_score + fp_reduction + fn_reduction + usability
    最大値 = 30、最小値 = 0
    """
    return (
        fugu_review.get("reliability", 0)
        + fugu_review.get("speed_score", 0)
        + fugu_review.get("coverage_score", 0)
        + fugu_review.get("fp_reduction", 0)
        + fugu_review.get("fn_reduction", 0)
        + fugu_review.get("usability", 0)
    )


# ── レポート ───────────────────────────────────────────────────────────────────

def write_report(
    run_dir: Path,
    loop_results: list[dict],
    best_idx: int,
    best_composite: float,
    fugu_tokens: int,
    elapsed_sec: float,
    window_started_at: datetime,
    claude_call_count: int,
    stop_reason: str,
    fugu_ever_available: bool,
) -> None:
    date_str = window_started_at.strftime("%Y-%m-%d")

    lines = [
        "# VulnScanner 改善ループ レポート",
        "",
        f"- 実行日: {date_str}",
        f"- 経過時間: {elapsed_sec/60:.1f} 分",
        f"- イテレーション数: {len(loop_results)}",
        f"- FuguAI トークン使用量: {fugu_tokens:,} / {FUGU_TOKEN_BUDGET:,}",
        "",
        "## 重要: 実コード変更なし",
        "",
        "- **main working tree は一切変更していません**",
        "- 評価はすべて `temp_eval/` 上の一時コピーで実施しました",
        "- 自動 commit / push は実施していません",
        f"- FuguAI 接続状況: {'✓ 接続可能' if fugu_ever_available else '✗ **接続不可 (unavailable)**'}",
        "",
        "## Claude 実行情報",
        "",
        f"- Claude 呼び出し回数: {claude_call_count} calls",
        f"- stop_reason       : `{stop_reason}`",
        "",
        "## ベースライン (回帰ゲート)",
        "",
        "P/R/F1 は改善指標ではなく回帰ゲートとして使用。",
        "採用には P=100% / R=100% / F1=100% の維持が必須。",
        "順位付けは composite score (reliability + speed_score + coverage_score + fp_reduction + fn_reduction + usability, 最大30) で行う。",
        "",
        "## ループ結果 (Propose → Critique → Revise)",
        "",
        "| # | ルールID | 概要 | Draft OK | FuguAI 品質 | composite | Final OK | 結果 | 棄却理由 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    for r in loop_results:
        dm      = r.get("draft_metrics", {})
        fm      = r.get("final_metrics", dm)
        dok     = "✓" if dm.get("ok") else "✗"
        fok     = "✓" if fm.get("ok") else "✗"
        fq      = r.get("fugu_quality", "-")
        comp    = r.get("composite")
        cs      = f"{comp:.1f}" if isinstance(comp, float) else "-"
        tag     = "★ 採用" if r.get("adopted") else ("候補" if r.get("candidate") else "棄却")
        reason  = r.get("rejection_reason", "")[:40]
        summ    = r.get("change_summary", "")[:40]
        lines.append(
            f"| {r['iteration']} | {r.get('rule_id','?')} | {summ} "
            f"| {dok} | {fq} | {cs} | {fok} | {tag} | {reason} |"
        )

    # 棄却された案の詳細
    rejected = [r for r in loop_results if not r.get("adopted") and not r.get("candidate")]
    if rejected:
        lines += ["", "## 棄却された案と理由", ""]
        for r in rejected:
            lines.append(f"- **{r.get('rule_id','?')}** ({r.get('change_summary','')[:60]})")
            lines.append(f"  - 棄却理由: {r.get('rejection_reason','')}")
            nh = r.get("next_hint", "")
            if nh:
                lines.append(f"  - 次回へのヒント: {nh}")

    # 最良提案
    if best_idx >= 0:
        best = loop_results[best_idx]
        lines += [
            "",
            "## 最良改善案",
            "",
            f"- イテレーション : {best['iteration']}",
            f"- ルールID       : {best.get('rule_id','?')}",
            f"- 概要           : {best.get('change_summary','')}",
            f"- 改訂メモ       : {best.get('revision_notes','')}",
            f"- FuguAI 品質    : {best.get('fugu_quality','-')}/10",
            f"- composite      : {best.get('composite','-')}",
            f"- FuguAI コメント: {best.get('fugu_comment','')}",
            "",
            "### 朝の承認手順",
            "",
            "```bash",
            f"# 1. パッチ内容を確認",
            f"cat {run_dir}/proposal_best.patch",
            f"",
            f"# 2. 適用",
            f"git apply {run_dir}/proposal_best.patch",
            f"",
            f"# 3. 検証",
            f"pytest",
            f"python recall_check.py",
            f"",
            f"# 4. 問題なければコミット",
            f"git diff",
            f"git add -p",
            f"git commit -m \"feat: apply nightly proposal {best.get('rule_id','')}\"",
            "```",
        ]
    else:
        lines += ["", "## 最良改善案", "", "採用候補となる提案はありませんでした。"]

    if not fugu_ever_available:
        lines += [
            "",
            "## ⚠ FuguAI unavailable",
            "",
            "FuguAI API に接続できませんでした。",
            "**no critique/revise performed** — すべての提案は未レビューの draft です。",
            "candidate として保存された提案は、人間がレビューするまで `git apply` しないでください。",
        ]

    lines.append("")
    (run_dir / "improvement_report.md").write_text("\n".join(lines), encoding="utf-8")


# ── メインループ ───────────────────────────────────────────────────────────────

def _run_loop(args: argparse.Namespace) -> int:
    from datetime import timedelta
    max_seconds       = args.max_hours * 3600
    start_time        = time.monotonic()
    window_started_at = datetime.now()
    run_dir           = get_run_dir(window_started_at)

    # --stop-at HH:MM の絶対終了時刻を計算（翌日をまたぐ場合も考慮）
    stop_at_dt: datetime | None = None
    if args.stop_at:
        h, m      = map(int, args.stop_at.split(":"))
        stop_at_dt = window_started_at.replace(hour=h, minute=m, second=0, microsecond=0)
        if stop_at_dt <= window_started_at:
            stop_at_dt += timedelta(days=1)
        log(f"絶対終了時刻: {stop_at_dt.strftime('%H:%M')} ({(stop_at_dt - window_started_at).seconds // 60}分後)")

    # 前回クラッシュで残った一時評価ディレクトリを削除
    if TEMP_EVAL_DIR.exists():
        try:
            shutil.rmtree(str(TEMP_EVAL_DIR), ignore_errors=True)
        except Exception as exc:
            log(f"  [警告] temp_eval クリーンアップ失敗: {exc}")
    TEMP_EVAL_DIR.mkdir(parents=True, exist_ok=True)

    log(
        f"改善ループ開始 (Propose→Critique→Revise) | "
        f"最大 {args.max_hours}h"
        + (f" | 終了時刻 {args.stop_at}" if args.stop_at else "")
    )
    log(f"出力ディレクトリ: {run_dir}")
    if args.dry_run:
        log("[DRY RUN] API 呼び出しはスキップします")

    # ── ベースラインメトリクス（draft prompt に埋め込む） ────────────────────────
    try:
        baseline_metrics = run_recall_check()
    except Exception:
        baseline_metrics = {"passed": 0, "total": 0, "precision": 100.0, "recall": 100.0, "f1": 100.0, "ok": True}

    # ── 状態変数 ────────────────────────────────────────────────────────────────
    fugu_tokens_used:    int         = 0
    iteration:           int         = 0
    best_idx:            int         = -1
    best_composite:      float       = -999.0
    loop_results:        list[dict]  = []
    previous_attempts:   list[dict]  = []
    loop_times:          list[float] = []
    stop_reason:         str         = "time_limit"
    fugu_ever_available: bool        = False
    claude_call_count:   int         = 0   # 報告用カウンタ（制限には使わない）

    token_record: dict = {
        "date": window_started_at.strftime("%Y-%m-%d"),
        "sessions": [], "total_tokens": 0,
    }

    def _record_claude_call() -> None:
        nonlocal claude_call_count
        claude_call_count += 1

    def _wait_rate_limit() -> bool:
        """レートリミット時に30分待機する。stop_at を超える場合は False を返す。"""
        wait_sec = 30 * 60
        deadline = datetime.now() + timedelta(seconds=wait_sec)
        if stop_at_dt and deadline >= stop_at_dt:
            log(f"  レートリミット: 30分待つと終了時刻 {args.stop_at} を超えるため終了")
            return False
        log(f"  レートリミット検出 → {deadline:%H:%M} まで30分待機...")
        for remaining in range(30, 0, -1):
            if stop_at_dt and datetime.now() >= stop_at_dt:
                return False
            print(f"\r  レートリミット待機中... 残り {remaining}分", end="", flush=True)
            time.sleep(60)
        print(flush=True)
        log("  30分経過 → リトライ再開")
        return True

    while True:
        elapsed  = time.monotonic() - start_time
        avg_loop = sum(loop_times) / len(loop_times) if loop_times else 300.0

        # ── 絶対終了時刻 (--stop-at) ─────────────────────────────────────────
        if stop_at_dt and datetime.now() + timedelta(seconds=avg_loop * 1.5) >= stop_at_dt:
            log(f"絶対終了時刻 {args.stop_at} に到達 (次ループが間に合わない) → 終了")
            stop_reason = "stop_at_time"
            break

        # ── 時間バジェット ────────────────────────────────────────────────────
        if elapsed + avg_loop * 1.5 >= max_seconds:
            log(f"タイムバジェット残量不足 (経過 {elapsed/60:.1f}min) → 終了")
            stop_reason = "time_limit"
            break

        # ── FuguAI トークンバジェット ─────────────────────────────────────────
        if fugu_tokens_used >= FUGU_TOKEN_BUDGET - MIN_FUGU_RESERVE:
            log(f"FuguAI トークン上限 ({fugu_tokens_used:,}/{FUGU_TOKEN_BUDGET:,}) → 終了")
            stop_reason = "fugu_token_limit"
            break

        loop_start  = time.monotonic()
        if args.target:
            target_file = args.target
        else:
            target_file = ANALYZER_FILES[iteration % len(ANALYZER_FILES)]
        log(
            f"── イテレーション {iteration+1} | {target_file} | "
            f"経過 {elapsed/60:.1f}min | Claude {claude_call_count} calls ──"
        )

        original_content = Path(target_file).read_text(encoding="utf-8")

        iter_result: dict = {
            "iteration": iteration + 1, "target_file": target_file,
            "rule_id": "?", "change_summary": "", "revision_notes": "",
            "draft_metrics": {}, "fugu_status": "unavailable",
            "fugu_quality": None, "fugu_comment": "", "composite": None,
            "final_metrics": {}, "adopted": False, "candidate": False,
            "rejection_reason": "", "next_hint": "",
        }

        # ────────────────────────────────────────────────────────────────────
        # DRY RUN
        # ────────────────────────────────────────────────────────────────────
        if args.dry_run:
            log("[DRY RUN] recall_check 実行のみ (1 イテレーション後終了)")
            m = run_recall_check()
            log(f"  P={m['precision']:.1f}% R={m['recall']:.1f}% F1={m['f1']:.1f}% ({m['passed']}/{m['total']})")
            stop_reason = "dry_run"
            break

        # ────────────────────────────────────────────────────────────────────
        # Step 1: Claude → draft proposal
        # ────────────────────────────────────────────────────────────────────
        log("  [Step 1/5] Claude — draft proposal 生成...")
        draft_raw, draft_elapsed, draft_rate_limited = call_claude(
            build_draft_prompt(target_file, previous_attempts, baseline_metrics),
            task_type="proposal",
        )
        _record_claude_call()
        log(f"  → {draft_elapsed:.0f}s (累計 {claude_call_count} calls)")

        if draft_rate_limited:
            if not _wait_rate_limit():
                stop_reason = "rate_limit_stop_at"
                break
            continue  # 30分待機後、同じイテレーションを最初からやり直す

        def _skip(reason: str, hint: str = "") -> None:
            iter_result["rejection_reason"] = reason
            iter_result["next_hint"]        = hint
            loop_results.append(iter_result)
            previous_attempts.append({
                "iteration": iteration + 1, "rule_id": iter_result["rule_id"],
                "change_summary": iter_result["change_summary"],
                "target_file": target_file,
                "draft_metrics": {}, "fugu_status": "skipped",
                "decision": "rejected", "rejection_reason": reason, "next_hint": hint,
            })

        if not draft_raw:
            log("  draft 応答なし → スキップ")
            _skip("claude_draft_no_response")
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue

        draft_proposal = parse_claude_json(draft_raw)
        if not draft_proposal:
            log("  draft JSON パース失敗 → スキップ")
            _skip("draft_json_parse_error", "Return valid JSON only — no markdown fences")
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue

        rule_id       = draft_proposal.get("rule_id", "UNKNOWN")
        change_summ   = draft_proposal.get("change_summary", "")
        draft_content = draft_proposal.get("new_content", "")
        iter_result["rule_id"]        = rule_id
        iter_result["change_summary"] = change_summ
        log(f"  提案: {rule_id} — {change_summ[:70]}")

        # ── 重複ID チェック ──────────────────────────────────────────────────
        # 既存ルールIDと同じIDが提案された場合はスキップ（セッション内提案分も含む）
        if rule_id in set(_existing_rule_ids()):
            hint = (
                f"Rule ID {rule_id} already exists. Choose a NEW rule ID not in: "
                + ", ".join(_existing_rule_ids()[-10:]) + " ..."
            )
            log(f"  ⚠ 重複ルールID {rule_id} — スキップ")
            _skip("duplicate_rule_id", hint)
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue

        if not draft_content:
            _skip("draft_empty_content")
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue
        if not validate_python_syntax(draft_content, f"{rule_id} draft"):
            _skip("draft_syntax_error", "Fix syntax errors before returning")
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue

        # 保存
        draft_py    = run_dir / "proposals" / f"proposal_{iteration+1:03d}_draft.py"
        draft_patch = run_dir / "proposals" / f"proposal_{iteration+1:03d}_draft.patch"
        draft_py.write_text(draft_content, encoding="utf-8")
        draft_patch.write_text(generate_patch(original_content, draft_content, target_file), encoding="utf-8")

        # ────────────────────────────────────────────────────────────────────
        # Step 2: isolated eval (draft)
        # ────────────────────────────────────────────────────────────────────
        log("  [Step 2/5] recall_check (isolated, draft)...")
        try:
            draft_metrics = run_recall_check_isolated(target_file, draft_content, f"{iteration+1:03d}_draft")
        except Exception as exc:
            log(f"  評価エラー: {exc} → スキップ")
            _skip(f"eval_error: {exc}")
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue

        iter_result["draft_metrics"] = draft_metrics
        save_eval_result(run_dir, iteration + 1, "draft", draft_metrics)
        log(
            f"  → P={draft_metrics['precision']:.1f}% R={draft_metrics['recall']:.1f}% "
            f"F1={draft_metrics['f1']:.1f}% ({draft_metrics['passed']}/{draft_metrics['total']}) "
            f"{'OK' if draft_metrics['ok'] else 'FAILED'}"
        )

        if not draft_metrics["ok"]:
            log("  draft ベンチマーク失敗 → FuguAI レビューをスキップして棄却")
            hint = (
                f"Benchmark regression: P={draft_metrics['precision']:.1f}% "
                f"R={draft_metrics['recall']:.1f}%. Use a narrower regex to avoid FP/FN."
            )
            iter_result["rejection_reason"] = "benchmark_failed_on_draft"
            iter_result["next_hint"]        = hint
            loop_results.append(iter_result)
            previous_attempts.append({
                "iteration": iteration+1, "rule_id": rule_id, "change_summary": change_summ,
                "target_file": target_file,
                "draft_metrics": {"P": draft_metrics["precision"], "R": draft_metrics["recall"], "ok": False},
                "fugu_status": "skipped_benchmark_failed",
                "decision": "rejected", "rejection_reason": "benchmark_failed_on_draft", "next_hint": hint,
            })
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue

        # ────────────────────────────────────────────────────────────────────
        # Step 3: FuguAI critique
        # ────────────────────────────────────────────────────────────────────
        log("  [Step 3/5] FuguAI — 構造化レビュー...")
        fugu_prompt   = build_fugu_critique_prompt(rule_id, change_summ, target_file, draft_content, draft_metrics)
        fugu_raw, ftok = call_fugu(fugu_prompt, max_tokens=FUGU_CRITIQUE_MAX_TOKENS)
        fugu_tokens_used += ftok

        token_record["sessions"].append({
            "iteration": iteration+1, "stage": "critique",
            "rule_id": rule_id, "tokens": ftok, "cumulative": fugu_tokens_used,
        })
        token_record["total_tokens"] = fugu_tokens_used
        save_token_usage(run_dir, token_record)

        fugu_review = parse_fugu_critique(fugu_raw)

        if fugu_review is None:
            # パース失敗の原因を記録
            if fugu_raw:
                debug_path = run_dir / f"fugu_debug_{iteration+1}.txt"
                debug_path.write_text(fugu_raw, encoding="utf-8")
                log(f"  FuguAI パース失敗 — full raw → {debug_path.name} (先頭200文字: {fugu_raw[:200]!r})")
            else:
                log("  FuguAI raw が空 (API エラーまたはタイムアウト)")
            # FuguAI 接続不可 — revise をスキップして candidate 扱い
            log("  FuguAI 接続不可 → Revise スキップ, draft を unreviewed candidate として保存")
            iter_result["fugu_status"]      = "unavailable"
            iter_result["rejection_reason"] = "fugu_unavailable_no_critique"
            iter_result["candidate"]        = True
            iter_result["final_metrics"]    = draft_metrics
            save_eval_result(run_dir, iteration+1, "final", draft_metrics)
            loop_results.append(iter_result)
            previous_attempts.append({
                "iteration": iteration+1, "rule_id": rule_id, "change_summary": change_summ,
                "target_file": target_file,
                "draft_metrics": {"P": draft_metrics["precision"], "R": draft_metrics["recall"], "ok": True},
                "fugu_status": "unavailable",
                "decision": "candidate_no_fugu", "rejection_reason": "FuguAI unavailable",
                "next_hint": "FuguAI was down; retry when available for critique/revise",
            })
            iteration += 1; loop_times.append(time.monotonic() - loop_start); continue

        fugu_ever_available = True
        iter_result["fugu_status"]  = "available"
        iter_result["fugu_quality"] = int(fugu_review.get("quality_score", 0))
        iter_result["fugu_comment"] = fugu_review.get("comments", "")
        composite                   = compute_composite(fugu_review)
        iter_result["composite"]    = composite
        save_fugu_review(run_dir, iteration+1, fugu_review)
        log(
            f"  → quality={iter_result['fugu_quality']}/10  composite={composite:.1f}  "
            f"critical_fn={fugu_review.get('critical_fn_risk', False)}"
        )
        log(
            f"     確実性={fugu_review.get('reliability','?')}/5  "
            f"速度={fugu_review.get('speed_score','?')}/5  "
            f"検出範囲={fugu_review.get('coverage_score','?')}/5  "
            f"FP削減={fugu_review.get('fp_reduction','?')}/5  "
            f"FN削減={fugu_review.get('fn_reduction','?')}/5  "
            f"利用性={fugu_review.get('usability','?')}/5"
        )
        log(f"  [Fugu] {fugu_review.get('comments','')[:120]}")
        _issues = fugu_review.get("implementation_issues", "none") or "none"
        if _issues.lower() != "none":
            log(f"  [Fugu 実装問題] {_issues[:250]}")
        _instr = fugu_review.get("improvement_instructions", "")
        if _instr:
            # 長い場合は2行に分割して表示
            log(f"  [Fugu 改善指示] {_instr[:200]}")
            if len(_instr) > 200:
                log(f"                  ...{_instr[200:400]}")

        # ────────────────────────────────────────────────────────────────────
        # Step 4: Claude → revise (FuguAI フィードバックを渡す)
        # 以下のいずれかの場合は revise をスキップ（Claude 呼び出し節約）:
        #   a) improvement_instructions が "none" / 空
        #   b) quality >= 8 かつ implementation_issues が "none" / 空
        #      → 品質が既に高く改善余地が小さいため、revise のコストに見合わない
        # ────────────────────────────────────────────────────────────────────
        _instr_text  = (fugu_review.get("improvement_instructions") or "").strip().lower()
        _issues_text = (fugu_review.get("implementation_issues")    or "none").strip().lower()
        _no_instructions = _instr_text in ("", "none")
        _no_issues       = _issues_text in ("", "none")
        _quality_high    = (iter_result.get("fugu_quality") or 0) >= 8
        _skip_revise     = _no_instructions or (_quality_high and _no_issues)

        revise_raw          = None
        revise_rate_limited = False
        revision_notes      = "(FuguAI 改善指示なし — draft をそのまま final として使用)"

        if _skip_revise:
            if _quality_high and _no_issues and not _no_instructions:
                log(f"  [Step 4/5] 品質十分 (quality={iter_result.get('fugu_quality')}/10, 実装問題なし) → revise スキップ")
                revision_notes = f"(quality={iter_result.get('fugu_quality')}/10 かつ実装問題なし — revise スキップ)"
            else:
                log("  [Step 4/5] FuguAI 改善指示なし → revise スキップ")
        else:
            log("  [Step 4/5] Claude — FuguAI フィードバックを元に revise...")
            revise_prompt = build_revise_prompt(
                target_file, original_content, draft_content,
                fugu_review, draft_metrics, rule_id, change_summ,
            )
            revise_raw, revise_elapsed, revise_rate_limited = call_claude(
                revise_prompt,
                task_type="revise",
            )
            _record_claude_call()
            log(f"  → {revise_elapsed:.0f}s (累計 {claude_call_count} calls)")

        if revise_rate_limited:
            # revise がレートリミット → draft をそのまま final として使い、次回まで待機
            log("  revise レートリミット → draft を final として使用、30分待機")
            revise_raw = None
            if not _wait_rate_limit():
                stop_reason = "rate_limit_stop_at"
                # draft を final として処理を続ける（breakする前に保存まで行う）

        # revise 失敗または未実施の場合は draft を final として使う
        final_content  = draft_content
        final_summ     = change_summ
        if not _skip_revise and not revision_notes.startswith("("):
            revision_notes = "(revise 失敗 — draft をそのまま final として使用)"

        if revise_raw:
            rp = parse_claude_json(revise_raw)
            if rp and rp.get("new_content") and validate_python_syntax(rp["new_content"], f"{rule_id} final"):
                final_content  = rp["new_content"]
                final_summ     = rp.get("change_summary", change_summ)
                revision_notes = rp.get("revision_notes", "")
                log(f"  → revise 成功: {revision_notes[:80]}")
            else:
                log("  revise パース/構文エラー → draft を final として使用")
        elif not _skip_revise:
            log("  Claude revise 応答なし → draft を final として使用")

        iter_result["change_summary"] = final_summ
        iter_result["revision_notes"] = revision_notes

        # 保存
        final_py         = run_dir / "proposals" / f"proposal_{iteration+1:03d}_final.py"
        final_patch_text = generate_patch(original_content, final_content, target_file)
        final_patch      = run_dir / "proposals" / f"proposal_{iteration+1:03d}_final.patch"
        final_py.write_text(final_content, encoding="utf-8")
        final_patch.write_text(final_patch_text, encoding="utf-8")

        # ────────────────────────────────────────────────────────────────────
        # Step 5: isolated eval (final)
        # ────────────────────────────────────────────────────────────────────
        log("  [Step 5/5] recall_check (isolated, final)...")
        try:
            final_metrics = run_recall_check_isolated(target_file, final_content, f"{iteration+1:03d}_final")
        except Exception as exc:
            log(f"  最終評価エラー: {exc} → draft metrics を流用")
            final_metrics = draft_metrics

        log(
            f"  → P={final_metrics['precision']:.1f}% R={final_metrics['recall']:.1f}% "
            f"F1={final_metrics['f1']:.1f}% ({final_metrics['passed']}/{final_metrics['total']}) "
            f"{'OK' if final_metrics['ok'] else 'FAILED'}"
        )

        # ── Revise がベンチマークを壊した場合は draft にフォールバック ──────────────
        # Draft が合格 → Revise が破壊 → Draft を final として使い直す
        # (REDIR-011 のような「質7なのにReviseで棄却」を防ぐ)
        if not final_metrics["ok"] and draft_metrics["ok"]:
            log("  ⚠ revise がベンチマークを破壊 → draft にフォールバック (draft は合格済み)")
            final_content     = draft_content
            final_metrics     = draft_metrics
            revision_notes   += " [revise破損→draftフォールバック]"
            # フォールバック後のパッチを上書き保存
            fallback_patch = generate_patch(original_content, final_content, target_file)
            final_py.write_text(final_content, encoding="utf-8")
            final_patch.write_text(fallback_patch, encoding="utf-8")
            final_patch_text = fallback_patch
            log(
                f"  → フォールバック後: P={final_metrics['precision']:.1f}% "
                f"R={final_metrics['recall']:.1f}% OK"
            )

        iter_result["final_metrics"] = final_metrics
        save_eval_result(run_dir, iteration+1, "final", final_metrics)

        # ────────────────────────────────────────────────────────────────────
        # 採用判定
        # P/R/F1 = 回帰ゲート。通過した案を composite score で順位付け。
        # ────────────────────────────────────────────────────────────────────
        quality     = iter_result.get("fugu_quality", 0) or 0
        critical_fn = fugu_review.get("critical_fn_risk", False)
        bench_ok    = final_metrics["ok"]

        if not bench_ok:
            reason = "benchmark_failed_on_final"
            hint   = (
                f"Final benchmark regression: P={final_metrics['precision']:.1f}% "
                f"R={final_metrics['recall']:.1f}%. The revise introduced a new issue."
            )
        elif quality < FUGU_QUALITY_MIN:
            reason = f"fugu_quality_{quality}_lt_{FUGU_QUALITY_MIN}"
            hint   = fugu_review.get("improvement_instructions", "")[:120]
        elif critical_fn:
            reason = "critical_fn_risk_flagged_by_fugu"
            hint   = "Avoid patterns that may suppress detection of real vulnerabilities."
        elif composite <= best_composite:
            reason = f"composite_{composite:.1f}_not_better_than_best_{best_composite:.1f}"
            hint   = "Try a rule with higher coverage_score, fp_reduction, or fn_reduction."
        else:
            reason = ""
            hint   = ""

        adopted = bench_ok and quality >= FUGU_QUALITY_MIN and not critical_fn and composite > best_composite

        if adopted:
            best_composite = composite
            best_idx       = len(loop_results)
            (run_dir / "proposal_best.py").write_text(final_content, encoding="utf-8")
            (run_dir / "proposal_best.patch").write_text(final_patch_text, encoding="utf-8")
            log(f"  → ★ 採用 (composite={composite:.1f}) — 新ベスト!")
        # セッション内提案IDとして記録（採否に関わらず — 棄却案でもID重複を防ぐ）
        if rule_id and rule_id != "UNKNOWN":
            _proposed_this_session.add(rule_id)
        else:
            log(f"  → 棄却 ({reason})")

        iter_result["adopted"]          = adopted
        iter_result["rejection_reason"] = reason
        iter_result["next_hint"]        = hint

        previous_attempts.append({
            "iteration":      iteration + 1,
            "rule_id":        rule_id,
            "change_summary": final_summ,
            "target_file":    target_file,
            "draft_metrics":  {
                "P": draft_metrics["precision"], "R": draft_metrics["recall"], "ok": draft_metrics["ok"],
            },
            "fugu_status":    "available",
            "fugu_quality":   quality,
            "fugu_comment":   fugu_review.get("comments", "")[:80],
            "final_metrics":  {
                "P": final_metrics["precision"], "R": final_metrics["recall"], "ok": final_metrics["ok"],
            },
            "decision":          "adopted" if adopted else "rejected",
            "rejection_reason":  reason,
            "next_hint":         hint,
        })

        loop_sec = time.monotonic() - loop_start
        loop_times.append(loop_sec)
        iter_result["loop_sec"] = loop_sec
        log(f"  ループ時間: {loop_sec:.0f}s")
        loop_results.append(iter_result)
        iteration += 1

    # ── 終了処理 ──────────────────────────────────────────────────────────────
    elapsed_total = time.monotonic() - start_time
    log(
        f"ループ完了 | {iteration} イテレーション | {elapsed_total/60:.1f}min | "
        f"Claude {claude_call_count} calls | FuguAI {fugu_tokens_used:,} tokens"
    )

    try:
        write_report(
            run_dir, loop_results, best_idx, best_composite, fugu_tokens_used,
            elapsed_total, window_started_at, claude_call_count, stop_reason, fugu_ever_available,
        )
        log(f"レポート: {run_dir / 'improvement_report.md'}")
    except Exception as exc:
        log(f"  [警告] レポート書き込み失敗: {exc}")

    if best_idx >= 0:
        best = loop_results[best_idx]
        log(f"最良提案: {best.get('rule_id','?')} | {run_dir / 'proposal_best.patch'}")
        log(f"  承認手順: git apply {run_dir / 'proposal_best.patch'}")
    else:
        log("最良提案: なし")

    log("最終ベンチマーク確認 (main working tree は変更なし)...")
    try:
        final = run_recall_check()
        log(
            f"最終スコア: P={final['precision']:.1f}% R={final['recall']:.1f}% "
            f"F1={final['f1']:.1f}% ({final['passed']}/{final['total']}) "
            f"{'OK' if final['ok'] else '⚠ FAILED — main tree が変更されている可能性あり'}"
        )
        return 0 if final["ok"] else 1
    except Exception as exc:
        log(f"  [警告] 最終ベンチマーク確認失敗: {exc}")
        return 0


# ── エントリポイント ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="VulnScanner 改善ループ")
    parser.add_argument("--max-hours", type=float, default=4.0,
                        help="実行ウィンドウ上限（時間, デフォルト 4.0）")
    parser.add_argument("--stop-at", default=None, metavar="HH:MM",
                        help="絶対終了時刻 例: --stop-at 05:00 (翌日をまたぐ場合も可)")
    parser.add_argument("--dry-run", action="store_true",
                        help="API を呼ばず動作確認のみ (recall_check は実行)")
    parser.add_argument("--target", default=None, metavar="FILE",
                        help="特定のアナライザーファイルに集中 "
                             "例: vulnscanner/analyzers/ast_python.py  "
                             "(指定すると全イテレーションでそのファイルのみ対象にする)")
    args = parser.parse_args()

    if not os.environ.get("FUGU_API_KEY") and not args.dry_run:
        log("ERROR: FUGU_API_KEY が未設定です。.env ファイルを確認してください。")
        sys.exit(1)

    try:
        exit_code = _run_loop(args)
    except FatalError as exc:
        print(flush=True)
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
