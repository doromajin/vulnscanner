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

## 削除してはいけないもの

| ディレクトリ | 理由 |
|---|---|
| fugu-chat | 自分のリポジトリ（https://github.com/doromajin/fugu-chat）。ほかに、`fugu-chat-index.html` もある |
| zz_lara_probe | 自作の検出確認用（15 パターン）。取り直せない |
| zz_out | 自作スクリプトの出力 |
| fork, targets, rank_1k5k, rank_results | `.git` がなく、由来が不明。中身を確認するまで残す |
| webgoat, webgoat_report.json | 繰り返し使うベンチマークとその結果 |
