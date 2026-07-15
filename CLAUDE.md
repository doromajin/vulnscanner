# VulnScanner

ホワイトハット静的解析ツール。OSS リポジトリ（GitHub URL / ローカルパス）を対象に脆弱性を検出する。
実サーバーへの攻撃・悪用は一切行わない。検出結果は responsible disclosure の目的にのみ使用する。

---

## 解析精度に関する方針

- `os.environ` はユーザー入力ではなくサーバー設定値なので taint 源としない
- テスト・フィクスチャ・ベンダーパスの finding は抑制する（`file_context.py` で分類）
- AST アナライザーの finding は同一 (file, line, vuln_type) の regex finding より優先する
- `# vulnscanner: ignore` アノテーションは必ずコード変更より上位の抑制手段として扱う

---

## コミットルール

- `--no-verify` / `--gpg-sign=false` は使わない
- `git amend` は既存コミットへの破壊的操作なので原則禁止（ユーザーが明示的に指示した場合のみ）
- コミットメッセージは英語、末尾に `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`

---

## git push 自動化ルール

### 自動 push の条件（全て満たした場合のみ確認不要）

以下の 6 条件を **全て** パスした場合のみ `git push` を実行してよい。
1 つでも失敗したら push せず、**どの条件で失敗したか**を明記してユーザーに報告し、判断を仰ぐこと。

1. **pytest 全通過** — `pytest tests/` がエラーなく完了する
2. **self-scan 正常終了** — `python -m vulnscanner.cli scan . --fail-on CRITICAL` が hang・クラッシュなしで終了する
   （Phase 3 hang バグの教訓：interprocedural 等の新機能追加後は必ずself-scanで無限ループ/タイムアウトがないことを確認）
3. **パフォーマンス** — 1000 行規模のファイルを 10 秒以内に解析できる
4. **機密情報チェック** — `git diff` に `.env` や秘密鍵らしき文字列が含まれていない
5. **変更量** — 1 コミットの変更行数が 5000 行を超えていない
6. **新規外部パッケージなし** — `requirements.txt` / `package.json` に新規の外部パッケージ追加がない

### 常に確認不要な操作

- `vulnscan` / `pytest` / `git add` / `git commit`
- `C:\VulnScanner` 配下での `cd` 操作
- 既存パッケージの `pip install`
- PowerShell の読み取り専用パイプライン（`Get-ChildItem`, `Select-String`, `Select-Object`, `ForEach-Object`, `Measure-Object`, `Where-Object`, `Sort-Object`, `Get-Content` 等の組み合わせで、ファイル一覧・内容検索・表示のみを行うもの）

### 常に確認必須な操作

- `rm`（ファイル削除）
- 外部通信（`curl` / `wget` 等）
- 新規パッケージの `pip install`
- ブラウザ操作
- `C:\VulnScanner` 外部へのあらゆる操作
- PowerShell で `Set-Content` / `Out-File` / `New-Item` / `Remove-Item` / `Copy-Item` / `Move-Item` 等の書き込み・削除系コマンドが含まれるもの

### 夜間自動ループ（improvement_loop.py）

push 禁止を維持する。最良提案は `proposal_best.patch` として保存し、朝に人間が `git apply` する運用のまま変更しない。

---

## ベンチマーク改善時の必須ルール

OWASP Benchmark 等の第三者ベンチマークのスコア改善作業を行う際は、以下を必ず守ること。

### 1. 改善の正当性チェック

新しい taint source / sink / ルールを追加する際は、以下を自問してから実装する：

- このパターンは実世界のフレームワーク（Django, Flask, Spring, Laravel 等）で実際に使われているか？
- ベンチマークの特定のクラス名・メソッド名・変数名だけに反応する実装になっていないか？
- もし「Benchmark 専用」の要素が必要な場合は、ハードコードせず設定ファイル（`custom_taint_sources.json` 等）で外部化すること

### 2. 進捗報告のルール

Score 改善の作業中、以下のペースで必ず中間報告すること（いずれか早い方）：

- Score 上昇が 0.05 を超えるごと
- 30 分ごと

報告内容には必ず以下を含める：

- 現在の OWASP Benchmark Score
- 直近の変更が実世界パターンか、ベンチマーク特化か
- recall_check.py（自作ベンチマーク）の現在の結果

### 3. 自動停止条件

以下のいずれかに該当したら、改善作業を自動的に停止し、ユーザーに確認を求めること：

- recall_check.py（自作ベンチマーク）の Precision / Recall / F1 が低下した
- 実 OSS スキャン（bludit, Lychee, kimai 等）での FP 件数が明らかに増加した
- 同一セッションで 2 時間を超えて連続実行している
- Score 上昇ペースが「なめらかに右肩上がり」で頭打ちの兆候がない（不自然な連続改善）

### 4. 完了時の必須検証

作業完了時、必ず以下 3 点をセットで報告すること：

1. 自作 recall_check.py の結果（退行がないか）
2. 追加／変更したルールが実世界フレームワークで妥当か（1 件ずつ判定）
3. 実 OSS での再スキャン結果（FP 件数の異常増加がないか）
