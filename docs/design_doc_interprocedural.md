# Interprocedural Taint Analysis — Design Document

## 概要

単純な taint 解析はシンク（`conn.execute()`）の引数が直接 `request.args.get()` を参照するケースのみ検出できる。しかし実世界のコードでは入力値は複数の関数を経由してシンクに到達する。

```python
# 1-hop: 直接参照 — 従来の解析で検出可能
conn.execute("SELECT * FROM users WHERE id=" + request.args.get("id"))

# 2-hop: 関数境界を越える — 関数間解析がないと FN
def get_user_id():
    return request.args.get("id")   # taint source

def handle():
    uid = get_user_id()             # ← ここで taint が切れていた
    conn.execute("SELECT ... WHERE id=" + uid)
```

本機能は **ファイル内関数間追跡** と **ファイル間追跡** の両方を実装し、この FN を解消する。

---

## Python 実装（`vulnscanner/analyzers/ast_python.py`）

### 全体フロー

```
analyze(file) → _find_taint_source_funcs(tree)   # Pre-pass: 固定点反復
              → _VulnVisitor.visit(tree)           # Main visit
                  └─ _taint_of(node, ...) 内で
                       Pre-pass (inherent source)  → Phase 1
                       self.method() source        → Phase 3a
                       arg passthrough             → Phase 3 / 3b
                       cross-file passthrough      → Phase 4
```

---

### Pre-pass: `_find_taint_source_funcs()` — 固定点反復

**目的:** ファイル内の全関数を走査し、「taint された値を return する関数名」の集合を構築する。

**アルゴリズム:**

```
current = {}
repeat (最大 8 パス):
    _interprocedural_taint_sources = current   # 途中結果を _taint_of に公開
    for 各関数:
        if 任意の return path が TAINTED:
            current に追加
    if 追加なし: break
```

1 パスで直接 `request.args.get()` を return する関数を検出し、次のパスでその関数を呼び出して return する関数を検出する——これを固定点まで繰り返す。8 パス上限は O(n × 8) の計算量を保証し、現実的なネスト深度（2〜3 hop）を全てカバーする。

**セキュリティ原則:** いずれかの return パスが TAINTED であれば関数全体を taint source とみなす（false negative を避けるため）。

---

### `_taint_of()` 内の関数呼び出し解決フェーズ

#### Phase 1（Pre-pass 結果の参照）

```python
if full in _interprocedural_taint_sources:
    return TaintInfo(TAINTED, f"return of taint-source function '{full}'")
```

Pre-pass で確定した inherent taint source 関数の呼び出しは即座に TAINTED を返す。

#### Phase 3a: `self.method()` source

```python
if attr in _interprocedural_taint_sources:
    return TaintInfo(TAINTED, f"return of taint-source method '.{attr}()'")
```

`_full_name()` は `self.foo()` を `"self.foo"` と返すが、`_local_func_defs` のキーは `"foo"` なので、`attr`（短名）で別途照合する。

#### Phase 3: 引数パススルー（名前付き呼び出し）

```python
# func(tainted_arg) → callee 内で param → return に流れるか検査
if full in _local_func_defs:
    arg_taints = [_taint_of(a, ...) for a in node.args]
    if any TAINTED in arg_taints:
        param_assigns = {param: request_node for tainted params}
        if _callee_returns_tainted(func_def, param_assigns):
            return TAINTED
```

`_callee_returns_tainted()` は callee の全 return path を `_taint_of` で評価し、TAINTED な return が存在するかを bool で返す。

#### Phase 3b: `self.method(tainted_arg)` パススルー

Phase 3 は `full in _local_func_defs`（`"foo"` 等）でマッチするが、`self.foo()` は `full = "self.foo"` となりマッチしない。Phase 3b は `attr` で再照合し、`self` パラメータをスキップして引数マッピングを行う。

#### Phase 4: クロスファイルパススルー

```python
# 別ファイルからインポートされた関数が tainted arg を return するか
if full in remote_func_defs:
    if _callee_returns_tainted(remote_func_def, param_assigns):
        return TAINTED
```

`set_cross_file_context()` でファイル群の内容を登録しておくと、インポート先の関数定義を解析して taint 伝播を追跡できる。Inherent taint source（`request` を直接読む remote 関数）は Pre-pass と同じロジックで `_interprocedural_taint_sources` に統合済みなので Phase 4 は passthrough ケースのみ担当する。

---

### `_callee_returns_tainted()` vs `_callee_return_taint_status()`

| 関数 | 返り値 | 用途 |
|---|---|---|
| `_callee_returns_tainted()` | `bool` | Phase 3/3b/4 の passthrough 判定 |
| `_callee_return_taint_status()` | `TaintStatus` | クロスファイルクラスメソッド解決（CLEAN / UNKNOWN / TAINTED の 3 値が必要） |

`_callee_return_taint_status()` は CLEAN（リテラルを return）と UNKNOWN（外部 API を呼び出す）を区別するため、メソッド解決で「safe と仮定してよいか」を正確に判定できる。

---

### 深さ制限と循環防止

| パラメータ | 値 | 理由 |
|---|---|---|
| `_depth > 14` → UNKNOWN_UNRESOLVED | 14 | `_taint_of` 再帰の上限 |
| `_depth <= 12` (Phase 3/3b) | 12 | callee 評価のマージン確保 |
| `_depth <= 11` (Phase 4) | 11 | cross-file 評価のマージン確保 |
| Pre-pass 最大パス数 | 8 | O(n×8) で現実的な連鎖全対応 |
| `_call_stack: set[str]` | ― | 再帰関数の無限展開防止（visitor 側） |

---

## Java 実装（`vulnscanner/analyzers/ast_java.py`）

Java の interprocedural 解析は固定点反復ループ（`changed = True/False` フラグ）の中に組み込まれている。

### `method(args)` 呼び出し

```java
String id = getParam("id");   // → _analyze_local_method("getParam", args, tainted)
```

`_analyze_local_method()` でメソッド定義を探し、tainted な引数が return に流れるかを評価する。結果が `True` なら `tainted.add(decl.name)`, `changed = True`。

### `this.method(args)` 呼び出し

javalang の AST では `this.foo(args)` は `This(selectors=[MethodInvocation("foo", args)])` として表現される。通常の `MethodInvocation` とは構造が異なるため、専用の分岐で処理する。

```python
if isinstance(init, jt.This) and isinstance(init.selectors[0], jt.MethodInvocation):
    _this_sel = init.selectors[0]
    result = _analyze_local_method(tree, _this_sel.member, _this_sel.arguments, ...)
```

---

## 既知の制限

| 制限 | 内容 | バックログ |
|---|---|---|
| **クロスファイル（Python）** | 別ファイルの inherent source は対応済みだが、ファイル間の複数ホップ連鎖は未対応 | #2 |
| **クロスファイル（Java）** | 未実装 | #2 |
| **再帰関数** | `_call_stack` で検出するが UNKNOWN にフォールバックするのみ（taint の伝播を証明しない） | — |
| **可変引数 / kwargs** | 位置引数のみマッピング。`**kwargs` 経由の taint は未追跡 | — |
| **コールバック / lambda** | 関数オブジェクトを引数に渡すパターンは未対応 | — |

---

## 実装コミット履歴

| コミット | 内容 |
|---|---|
| `99b7c9c` | `_find_taint_source_funcs()` 固定点反復化（最大 8 パス、2-hop 連鎖対応） |
| `25087cd` | Phase 3a（`self.method()` inherent source）/ Phase 3b（`self.method(tainted_arg)` passthrough） |
| `a308a72` | Java `this.method()` — javalang `This` ノード対応 |
