# Submission Checklist — ytdlp2STRM Eval Injection

## 推奨手順（優先順位順）

### Step 1: GitHub Security Advisory を送る（最優先）

1. https://github.com/fe80Grau/ytdlp2STRM/security/advisories/new を開く
2. "Report a vulnerability" ボタンをクリック
3. `GITHUB_SECURITY_ADVISORY.md` の **Advisory Draft** セクションの内容を貼り付ける
4. **"Request CVE ID"** チェックボックスにチェックを入れる
   - GitHub は CVE Numbering Authority (CNA) なので直接 CVE ID が発行される
   - 発行まで通常 1〜5 営業日
5. Submit → メンテナーに非公開で通知が届く

### Step 2: メール（GitHub への連絡と並行 or フォールバック）

- fe80Grau の GitHub プロフィール (https://github.com/fe80Grau) を確認
- メールアドレスがあれば `EMAIL_DRAFT.md` を送信
- 件名: `[Security Disclosure] Unauthenticated RCE via Eval Injection — ytdlp2STRM ≤ v1.1.1`

### Step 3: CVE 申請（GitHub Advisory 経由が最速）

GitHub Security Advisory で "Request CVE" を選んだ場合:
- GitHub が MITRE に代わり CVE ID を採番する（GHSA-xxxx-xxxx-xxxx も同時に発行）
- 採番後は NVD に自動登録される
- Public disclosure と同時に CVE ID を公開できる

### Step 4: 90日後の Public Disclosure

2026-09-15 までに修正がリリースされない場合:
- GitHub Advisory を "Publish" に切り替える
- CVE ID と共に公開
- 任意で VulnScanner の検出事例として README / Blog に掲載可能

---

## CVSS スコア詳細

```
Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
Score:  8.1 (HIGH)
```

| 理由 | 詳細 |
|------|------|
| AV:N | docker-compose.yml がポート 5005:5000 を公開、LAN 上から到達可能 |
| AC:H | `__builtins__` チェーンの構築が必要（自明な exploit ではない） |
| PR:N | WebSocket に認証なし、cors_allowed_origins="*" |
| UI:N | 被害者のアクション不要 |
| C/I/A:H | 任意コード実行 → ファイル読書き・サービス停止が可能 |

AC を Low に評価する場合 (Python 熟練者には自明な payload のため):
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (CRITICAL)
```
Advisory では保守的に AC:H (8.1) を使用。

---

## 注意事項

- PoC コードは Advisory 本文には含めず、「要望があれば提供」とする
- メンテナーから返信がない場合は 2 週間後に GitHub Issue でメンション可
  (ただし脆弱性の詳細は公開しない)
- 90日のタイムラインは延長交渉可能（修正中と連絡があれば柔軟に対応）
