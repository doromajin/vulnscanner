# Cross-File Taint Analysis — Design Document

## 問題

単一ファイル内の taint 追跡は Phase 1〜4 で対応済みだが、ファイルをまたぐ伝播は
現在 1-hop のみ（直接インポートした関数の引数パススルー）にとどまる。

### 未検出ケース

```python
# utils.py
def get_user_id():
    return request.args.get("id")          # taint source

# helpers.py
from utils import get_user_id

def fetch_user():
    uid = get_user_id()                    # cross-file 1-hop — 現在対応済み
    return uid

# views.py
from helpers import fetch_user
import sqlite3

def handle():
    uid = fetch_user()                     # cross-file 2-hop — 未対応 → FN
    conn.execute("SELECT * FROM users WHERE id=" + uid)
```

```python
# config.py
ALLOWED_HOST = request.META.get("HTTP_HOST")   # モジュール変数に taint を格納

# views.py
from config import ALLOWED_HOST
redirect(ALLOWED_HOST)                          # 変数経由 cross-file — 未対応
```

---

## 現在の実装（Phase 4）と限界

### 既存インフラ

| コンポーネント | 役割 |
|---|---|
| `set_cross_file_context(all_contents)` | スキャン前に全ファイル内容を登録 |
| `_resolve_module_to_file()` | `from utils import x` → `utils.py` のパスを解決 |
| `_build_remote_func_defs()` | インポート先の関数定義 AST を収集（1-hop） |
| `_cross_file_local.remote_func_defs` | `{imported_name: (FunctionDef, source_file)}` |
| `_cross_file_local.remote_class_methods` | `{method_name: [FunctionDef, ...]}` |
| Phase 4 in `_taint_of()` | `remote_func(tainted_arg)` の passthrough 検査 |
| inherent source merge | `utils.get_user_input()` 等を `_interprocedural_taint_sources` に統合 |

### 限界

1. **多段ホップ未対応**: `views.py → helpers.py → utils.py` の 2-hop 以上で切れる
2. **モジュール変数未追跡**: `from config import TAINTED_VAR` が UNKNOWN になる
3. **クラス属性 cross-file 未追跡**: 別ファイルで定義されたクラスの `self.x` が追跡できない
4. **インポート集約未対応**: `__init__.py` 経由の re-export が解決されないことがある
5. **循環インポート**: 検出はするが taint 情報が不完全になる

---

## 設計方針

### 基本原則

- **既存 Phase 4 インフラを拡張**する。スキャナーコアの再設計はしない
- **セキュリティ優先**: あるパスが tainted である可能性があれば TAINTED とみなす
- **パフォーマンス**: O(files²) にならないよう、事前計算したサマリーを再利用する
- **増分実装**: Phase A → B → C の順で独立して導入できる設計にする

---

## アーキテクチャ

### 2 パス構成

```
Pass 1 (Pre-scan):  全ファイルを解析 → CrossFileTaintSummary を構築
Pass 2 (Analysis):  各ファイルを解析（Summary を参照して cross-file taint を解決）
```

現在は Pass 1 なしで Pass 2 のみ実行している状態。

---

## データ構造

```python
@dataclass
class CrossFileTaintSummary:
    # モジュール変数（グローバル）の taint 状態
    # key: "module_path::var_name"  例: "config::ALLOWED_HOST"
    tainted_globals: frozenset[str]

    # 関数の taint 特性
    # key: "module_path::func_name"  例: "utils::get_user_id"
    inherent_sources: frozenset[str]          # 引数なしで tainted を返す
    passthrough_funcs: frozenset[str]         # tainted 引数を return に伝播する

    # クラスメソッドの taint 特性
    # key: "module_path::ClassName::method_name"
    tainted_methods: frozenset[str]           # inherent or passthrough
```

これをスキャン開始前に 1 度だけ構築し、スレッドローカルに格納する。

---

## 実装フェーズ

### Phase A: 多段ホップ（2〜3-hop 対応）

**目的:** `views.py → helpers.py → utils.py` の連鎖を検出する

**実装方針:**
`_build_remote_func_defs()` は現在 1 ファイル分の関数定義のみ収集する。
これを **推移閉包** に変える。

```python
def _build_transitive_remote_func_defs(
    file_path: str,
    all_contents: dict[str, str],
    max_depth: int = 4,
) -> dict[str, tuple[FunctionDef, str]]:
    """
    インポートチェーンを再帰的に辿り、推移的に到達可能な全関数定義を収集。
    seen_files で循環インポートを防止。
    """
    result: dict = {}
    seen: set[str] = set()
    _collect(file_path, all_contents, result, seen, depth=0, max_depth=max_depth)
    return result
```

**変更ファイル:** `ast_python.py` の `_build_remote_func_defs()` を拡張

**推定工数:** 小（既存関数の再帰化）

---

### Phase B: モジュール変数 taint 追跡

**目的:** `from config import TAINTED_VAR` で変数の taint 状態を引き継ぐ

**実装方針:**

Pre-scan で各ファイルのモジュールレベル変数を評価:
```python
def _scan_module_globals(
    file_path: str,
    content: str,
    known_sources: frozenset[str],      # 既知の taint source 関数
) -> frozenset[str]:
    """
    モジュールレベルの Assign 文を評価し、tainted な変数名を返す。
    例: ALLOWED_HOST = request.META.get("HTTP_HOST") → {"config::ALLOWED_HOST"}
    """
```

`_build_remote_func_defs()` を拡張してモジュール変数も収集し、
`_taint_of()` の `ast.Name` 解決でモジュール変数の taint を参照する。

**変更ファイル:** `ast_python.py`（`_taint_of` の Name 解決、`_build_remote_func_defs`）

**推定工数:** 中

---

### Phase C: Pre-scan による CrossFileTaintSummary

**目的:** Pass 1 でリポジトリ全体の taint サマリーを構築し、Pass 2 で参照

**実装方針:**

`scanner.py` に Pre-scan ステップを追加:
```python
# scanner.py の scan() 内
# Step 1: Pre-scan — CrossFileTaintSummary を構築
summary = build_cross_file_summary(all_contents)

# Step 2: 各ファイルを解析（summary を参照）
set_cross_file_context(all_contents, summary)
for file in files:
    analyzer.analyze(file, ...)
```

`build_cross_file_summary()` は固定点反復:
```
current_sources = {}
repeat:
    for each file:
        eval module globals with current_sources
        eval functions with current_sources
        add newly-found tainted symbols
    if no change: break
```

**変更ファイル:** `scanner.py`（Pre-scan 追加）、`ast_python.py`（Summary 参照）

**推定工数:** 大

---

## 実装順序（推薦）

```
Phase A（多段ホップ）  →  Phase B（変数追跡）  →  Phase C（Pre-scan）
    1〜2日                   2〜3日                    3〜5日
```

Phase A 単体でも「2-hop 連鎖の FN」の大部分を解消できる。
Phase B は Phase A と独立して実装可能。
Phase C は A+B の成果を統合する最終形。

---

## リスクと対策

| リスク | 対策 |
|---|---|
| 循環インポートで無限ループ | `seen_files: set` で訪問済みファイルを管理 |
| 巨大リポジトリでのパフォーマンス劣化 | max_depth=4 上限 + キャッシュで O(n×depth) に抑制 |
| FP 増加（過剰 taint 伝播） | recall_check.py + 実 OSS スキャンで各フェーズ後に検証 |
| Phase A 後の退行 | 既存 Phase 4 テストを全て維持し、新規テストを追加 |

---

## テスト計画

各 Phase 完了時に以下を確認:

1. **新規 TP テスト**: 多段ホップを含む taint チェーン（2-hop, 3-hop）
2. **既存テストの退行なし**: pytest 354 件全通過
3. **recall_check.py**: 56/56 維持
4. **実 OSS スキャン**: bludit / Lychee / kimai での FP 件数比較

---

## 未対応（今回の設計スコープ外）

- Java の cross-file taint（別設計が必要）
- `sys.modules` 動的インポート
- `importlib.import_module()` 動的インポート
- サードパーティライブラリの taint モデリング（pip パッケージ）
