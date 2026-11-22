# repos/ の記録（取り直し用）

作成日: 2026-11-19。URL とコミットの ID があれば、`git clone --depth 1` と `git fetch --depth 1 origin <ID>` で取り直せます。

## 取り直せるもの（外部の OSS）

| ディレクトリ | URL | コミット（12桁） | 備考 |
|---|---|---|---|
| Attendize | https://github.com/Attendize/Attendize | 9289acbab158 | PHP/Laravel。開示文書あり |
| BookStack | https://github.com/BookStackApp/BookStack | 1dab6bcaebce | PHP/Laravel |
| Cachet | https://github.com/CachetHQ/Cachet | 2b0fc6898830 | PHP/Laravel |
| Gerapy | https://github.com/Gerapy/Gerapy | 7c4eda875563 | Python/Django。開示文書あり |
| InvoicePlane | https://github.com/InvoicePlane/InvoicePlane | ef6fb981bf4f | PHP |
| Lychee | https://github.com/LycheeOrg/Lychee | 4df83b4b7dd5 | PHP/Laravel |
| akaunting | https://github.com/akaunting/akaunting | d0ac971b6128 | PHP/Laravel |
| bludit | https://github.com/bludit/bludit | 4b1288d30150 | PHP |
| datasette | https://github.com/simonw/datasette | bdc973174096 | Python |
| firefly-iii | https://github.com/firefly-iii/firefly-iii | e1a90bf8ee74 | PHP/Laravel |
| healthchecks | https://github.com/healthchecks/healthchecks | 69dbd2a0801d | Python/Django |
| kimai | https://github.com/kimai/kimai | aaff60bcb7c7 | PHP/Symfony |
| koel | https://github.com/koel/koel | 636eca8f01ec | PHP/Laravel |
| libhv | https://github.com/ithewei/libhv | f93db2dcb840 | C/C++ |
| miniaudio | https://github.com/mackron/miniaudio | 9634bedb5b5a | C。作業コピーの 5 件の変更は、未追跡の分割ファイル（`_*_impl.c`、`_chunks/`）。解析用に作ったもので、取り直しは可能 |
| monica | https://github.com/monicahq/monica | dab74273acc5 | PHP/Laravel |
| pyspider | https://github.com/binux/pyspider | 897891cafb21 | Python |
| quickjs | https://github.com/bellard/quickjs | 04be24600159 | C。作業コピーに 1 件の変更あり（削除前に内容を確認） |
| searxng | https://github.com/searxng/searxng | e3713717f24e | Python。作業コピーの 980 件は、ステージ済みの削除（`.coveragerc` など）。取得時の絞り込みの名残とみられる |
| snipe-it | https://github.com/snipe/snipe-it | be7d5ad012ec | PHP/Laravel |
| tortoise-orm | https://github.com/tortoise/tortoise-orm | ffc946ebd2d1 | Python |
| vulnerable-laravel-app | https://github.com/appelsiini/vulnerable-laravel-app | 12b6444cb896 | サンプル報告書の対象 |
| vulnerable-php-code-examples | https://github.com/rubennati/vulnerable-php-code-examples | e2af893e32fb | 再現率の測定用 |
| wallabag | https://github.com/wallabag/wallabag | 9f2e8aa111dc | PHP/Symfony。開示文書あり |
| webgoat | https://github.com/webgoat/webgoat | 651458671472 | Java。繰り返し使うベンチマーク（残す） |
| ytdlp2STRM | https://github.com/fe80Grau/ytdlp2STRM | bcc67af191dd | Python |

## 使い捨てで測定したもの（浅い clone、2026-11-19）

| ディレクトリ | URL | コミット（12桁） | 結果の要点 |
|---|---|---|---|
| pterodactyl | https://github.com/pterodactyl/panel | 60a100158158 | 12 件 → 7 件。確定した脆弱性なし |
| crater | https://github.com/crater-invoice-inc/crater | 05d5ce26fdd8 | 79 件 → 54 件。管理者指定 URL への接続（ExchangeRateProvider.php）を要確認として残した |
| bagisto | https://github.com/bagisto/bagisto | ac4bd606e7a5 | 76 件 → 75 件（XSS-001 の 9 件は HIGH→LOW）。既定の管理者パスワード、クライアント指定拡張子の保存を妥当な指摘とした |
| paperless-ngx | https://github.com/paperless-ngx/paperless-ngx | 14252054a150 | Python/Django。189 件 → 182 件（同名メソッドへの汚染の取り違えを修正し、HIGH 8 件が LOW へ）。分類器の pickle を妥当な指摘とした |
| netbox | https://github.com/netbox-community/netbox | f2a4a13b9632 | Python/Django。117 件 → 114 件（誤検出の XSS HIGH 2 件が消えた）。管理者スクリプトの exec、csrf_exempt の GraphQL を妥当な指摘とした |
| nodebb | https://github.com/NodeBB/NodeBB | 02180152d892 | Node.js/Express。135 件 → 126 件（res.render のデータ、req を先頭に取る呼び出し、固定接頭辞のリダイレクトの 9 件が誤検出）。確定した脆弱性なし |

| pygoat | https://github.com/adeyosemanputra/pygoat | 2aa4cc14f251 | 意図的に脆弱な Django 学習アプリ。再現率の測定用。危険な API の呼び出しはほぼ検出。実質の取りこぼしは Pillow `ImageMath.eval` のみ（追加済み） |
| django-nv | https://github.com/nVisium/django.nV | a48901f106da | 意図的に脆弱な Django 学習アプリ。SQL・コマンド・パスの 3 種はすべて検出 |

8 本とも、測定後に削除済み（pterodactyl、crater、bagisto は 2026-11-19、それ以外は 2026-11-22）。

取り直し: `git clone --depth 1 <URL>` のあと、`git fetch --depth 1 origin <ID>` と `git checkout <ID>`。

## 削除してはいけないもの

| ディレクトリ | 理由 |
|---|---|
| fugu-chat | 自分のリポジトリ（https://github.com/doromajin/fugu-chat）。ほかに、`fugu-chat-index.html` もある |
| zz_lara_probe | 自作の検出確認用（15 パターン）。取り直せない |
| zz_out | 自作スクリプトの出力 |
| fork, targets, rank_1k5k, rank_results | `.git` がなく、由来が不明。中身を確認するまで残す |
| webgoat, webgoat_report.json | 繰り返し使うベンチマークとその結果 |
