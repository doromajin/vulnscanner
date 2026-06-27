#!/usr/bin/env python3
"""VulnScanner 夜間自動改善ループ

環境変数 (必須):
  ANTHROPIC_API_KEY  Claude API キー
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
import io
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

# Windows の cp932 エンコーディング問題を回避
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── 設定定数 ──────────────────────────────────────────────────────────────────
MAX_WINDOW_SECONDS  = 4 * 3600   # 実行ウィンドウ上限
FUGU_TOKEN_BUDGET   = 50_000     # FuguAI 1晩上限トークン
CLAUDE_HALF_WINDOW  = 2 * 3600   # 2時間を超えたら Claude 新規呼び出しを止める
MIN_FUGU_RESERVE    = 2_000      # ループ1回残せない場合は中断

PROPOSALS_DIR      = Path("improvement_proposals")
BEST_PROPOSAL_FILE = Path("proposal_best.py")
REPORT_FILE        = Path("improvement_report.md")
TOKEN_USAGE_FILE   = Path("token_usage.json")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
FUGU_API_KEY      = os.environ.get("FUGU_API_KEY", "")
FUGU_API_BASE     = os.environ.get("FUGU_API_BASE", "https://api.fugu.sakana.ai/v1")
FUGU_MODEL        = os.environ.get("FUGU_MODEL", "fugu-chat")

BASELINE = {"precision": 100.0, "recall": 100.0, "f1": 100.0, "passed": 36}

# ローテーション対象のアナライザー（改善余地が大きい順）
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


# ── ユーティリティ ─────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)


# ── recall_check 実行 & パース ─────────────────────────────────────────────────

def run_recall_check() -> dict:
    """recall_check.py を実行してメトリクス dict を返す。

    Returns:
        precision, recall, f1 (float), passed (int), total (int), ok (bool)
    """
    import subprocess
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
            failed = int(m.group(1))
            metrics["passed"] = 36 - failed

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

def call_claude(prompt: str) -> str | None:
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8192,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
    except Exception as exc:
        log(f"Claude API エラー: {exc}")
        return None


def call_fugu(prompt: str) -> tuple[str | None, int]:
    """FuguAI を呼び出す。戻り値: (response_text, total_tokens_used)"""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=FUGU_API_KEY, base_url=FUGU_API_BASE)
        response = client.chat.completions.create(
            model=FUGU_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.2,
        )
        tokens = response.usage.total_tokens if response.usage else 0
        return response.choices[0].message.content, tokens
    except Exception as exc:
        log(f"FuguAI エラー: {exc}")
        return None, 0


# ── JSON パース ────────────────────────────────────────────────────────────────

def parse_claude_json(raw: str) -> dict | None:
    """Claude 出力から JSON を抽出する。new_content に改行・特殊文字を含む場合も対応。"""
    # ```json ... ``` フェンスを除去
    cleaned = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r'\s*```$', '', cleaned, flags=re.MULTILINE)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # 部分的な JSON: {" から } までを貪欲に抽出して試みる
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

def apply_proposal(target_file: str, new_content: str) -> str | None:
    """
    target_file を new_content で上書きし、バックアップ内容を返す。
    失敗時は None を返す（ファイルは変更しない）。
    """
    p = Path(target_file)
    if not p.exists():
        log(f"対象ファイルが見つかりません: {target_file}")
        return None
    backup = p.read_text(encoding="utf-8")
    try:
        p.write_text(new_content, encoding="utf-8")
    except Exception as exc:
        log(f"ファイル書き込みエラー: {exc}")
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
        f"| 指標 | 値 |",
        f"|---|---|",
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
            f"## 最良改善案",
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

def main() -> None:
    parser = argparse.ArgumentParser(description="VulnScanner 夜間自動改善ループ")
    parser.add_argument("--max-hours", type=float, default=4.0,
                        help="実行ウィンドウ上限（時間, デフォルト 4.0）")
    parser.add_argument("--dry-run", action="store_true",
                        help="API を呼ばず動作確認のみ (recall_check は実行)")
    args = parser.parse_args()

    max_seconds = args.max_hours * 3600
    start_time  = time.monotonic()

    # 必須環境変数チェック
    missing = [k for k in ("ANTHROPIC_API_KEY", "FUGU_API_KEY") if not os.environ.get(k)]
    if missing and not args.dry_run:
        log(f"ERROR: 環境変数未設定: {', '.join(missing)}")
        sys.exit(1)

    PROPOSALS_DIR.mkdir(exist_ok=True)
    log(f"夜間改善ループ開始 | 最大 {args.max_hours}h | FuguAI 上限 {FUGU_TOKEN_BUDGET:,} tokens")
    if args.dry_run:
        log("[DRY RUN モード] Claude / FuguAI API 呼び出しはスキップします")

    # ── 状態変数 ────────────────────────────────────────────────────────────────
    fugu_tokens_used: int          = 0
    iteration:        int          = 0
    best_idx:         int          = -1
    best_score:       float        = 0.0
    loop_results:     list[dict]   = []
    previous_attempts: list[str]   = []
    loop_times:       list[float]  = []

    token_record: dict = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "sessions": [],
        "total_tokens": 0,
    }

    # ── メインループ ─────────────────────────────────────────────────────────────
    while True:
        elapsed = time.monotonic() - start_time

        # 時間バジェット: 平均ループ時間の 1.5 倍が残っているか確認
        avg_loop = sum(loop_times) / len(loop_times) if loop_times else 120.0
        if elapsed + avg_loop * 1.5 >= max_seconds:
            log(f"タイムバジェット残量不足 (経過 {elapsed/60:.1f}min, 平均ループ {avg_loop:.0f}s) → 終了")
            break

        # FuguAI トークンバジェット確認
        if fugu_tokens_used >= FUGU_TOKEN_BUDGET - MIN_FUGU_RESERVE:
            log(f"FuguAI トークン上限に到達 ({fugu_tokens_used:,}/{FUGU_TOKEN_BUDGET:,}) → 終了")
            break

        # Claude 呼び出し半ウィンドウ制限 (朝のために 50% を残す)
        if elapsed >= CLAUDE_HALF_WINDOW and not args.dry_run:
            log(f"Claude 半ウィンドウ上限 ({CLAUDE_HALF_WINDOW/3600:.1f}h) に到達 → 終了")
            break

        loop_start   = time.monotonic()
        target_file  = ANALYZER_FILES[iteration % len(ANALYZER_FILES)]
        log(f"── イテレーション {iteration + 1} | 対象: {target_file} | 経過 {elapsed/60:.1f}min ──")

        # ── 1. Claude に提案を生成させる ────────────────────────────────────────
        rule_id      = "UNKNOWN"
        change_summ  = ""
        new_content  = ""

        if args.dry_run:
            log("[DRY RUN] Claude 呼び出しをスキップ -- 1 イテレーション実施して終了")
            # dry-run では recall_check だけ実行して終了
            log("recall_check.py 実行中 (dry-run)...")
            m = run_recall_check()
            log(f"  P={m['precision']:.1f}% R={m['recall']:.1f}% F1={m['f1']:.1f}% ({m['passed']}/36)")
            break

        log("Claude: 提案生成中...")
        prompt   = build_claude_prompt(target_file, previous_attempts)
        raw_resp = call_claude(prompt)

        if not raw_resp:
            log("Claude 応答なし — スキップ")
            iteration += 1
            loop_times.append(time.monotonic() - loop_start)
            continue

        proposal = parse_claude_json(raw_resp)
        if not proposal:
            log("JSON パース失敗 — スキップ")
            previous_attempts.append(f"(json parse error on iteration {iteration+1})")
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
        metrics = run_recall_check()
        log(f"  → P={metrics['precision']:.1f}% R={metrics['recall']:.1f}% "
            f"F1={metrics['f1']:.1f}% ({metrics['passed']}/36) {'OK' if metrics['ok'] else 'FAILED'}")

        # ── 3. FuguAI で品質評価 ─────────────────────────────────────────────────
        quality      = 0
        fugu_comment = ""
        fugu_tokens  = 0

        log("  FuguAI: 品質評価中...")
        fugu_prompt = build_fugu_eval_prompt(
            rule_id, change_summ, metrics, new_content
        )
        fugu_raw, fugu_tokens = call_fugu(fugu_prompt)
        fugu_tokens_used += fugu_tokens

        fugu_result  = parse_fugu_json(fugu_raw)
        if fugu_result:
            quality      = int(fugu_result.get("quality_score", 0))
            fugu_comment = fugu_result.get("comments", "")
        log(f"  → 品質スコア: {quality}/10  ({fugu_comment[:70]})")

        # トークン記録を更新・保存
        token_record["sessions"].append({
            "iteration": iteration + 1,
            "rule_id":   rule_id,
            "tokens":    fugu_tokens,
            "cumulative": fugu_tokens_used,
            "quality_score": quality,
        })
        token_record["total_tokens"] = fugu_tokens_used
        save_token_usage(token_record)

        # ── 4. 採用判定 ───────────────────────────────────────────────────────────
        # composite = 品質スコア × (F1/100)  — ベンチ失敗は 0 固定
        composite = quality * (metrics["f1"] / 100.0) if metrics["ok"] else 0.0
        adopted   = (
            metrics["ok"]
            and composite > best_score
            and quality >= 5
        )

        if adopted:
            best_score = composite
            best_idx   = len(loop_results)   # 追加前のインデックス
            BEST_PROPOSAL_FILE.write_text(new_content, encoding="utf-8")
            log(f"  → ★ 採用 (composite={composite:.2f}) — 新ベスト!")
        else:
            reason = (
                "ベンチ失敗" if not metrics["ok"]
                else f"品質不足 ({quality}/10 < 5)" if quality < 5
                else f"スコア不足 ({composite:.2f} <= {best_score:.2f})"
            )
            log(f"  → 棄却 ({reason})")

        # 採用されなかった提案は元のファイルへロールバック
        if not adopted:
            rollback(target_file, backup)
            log("  ロールバック完了")

        loop_sec = time.monotonic() - loop_start
        loop_times.append(loop_sec)
        log(f"  ループ時間: {loop_sec:.0f}s")

        loop_results.append({
            "iteration":    iteration + 1,
            "rule_id":      rule_id,
            "change_summary": change_summ,
            "target_file":  target_file,
            "metrics":      metrics,
            "quality_score": quality,
            "fugu_comment": fugu_comment,
            "adopted":      adopted,
            "loop_sec":     loop_sec,
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

    # 最終 recall スコアを確認して出力
    log("最終ベンチマーク確認...")
    final = run_recall_check()
    log(
        f"最終スコア: P={final['precision']:.1f}% R={final['recall']:.1f}% "
        f"F1={final['f1']:.1f}% ({final['passed']}/36) {'OK' if final['ok'] else 'FAILED'}"
    )

    sys.exit(0 if final["ok"] else 1)


if __name__ == "__main__":
    main()
