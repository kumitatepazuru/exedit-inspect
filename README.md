# exedit-inspect

AviUtl 拡張編集 (`exedit.auf`) の標準エフェクトを静的解析し、**実装を式のレベルまで
復元して検算する**プロジェクト。対象は 32bit PE、`ImageBase = 0x10000000`。
本文中のアドレスはすべて VA(`RVA = VA - 0x10000000`)。

方針は「読んで分かったことを書く」ではなく、**主張ごとに検算スクリプトを置く**こと。
各 `verify_*.py` は逆アセンブルの該当命令に注釈を付けて出力するか、Python で
同じ計算を再実装して総当たりで一致を確認するかのどちらかをやっている。

## 実行方法

```
uv run main.py <スクリプト>            # inspect/ 配下はファイルパス
uv run main.py tools.<ツール>          # tools/ 配下はドット区切りのモジュール名
```

`main.py` は指定されたスクリプトに DLL パス(既定 `data/exedit.auf`)とヘッダー一覧
(既定 `data/filter.h`)を渡すだけの踏み台。`inspect` はパッケージ名にすると標準
ライブラリの `inspect` を隠してしまうので、`inspect/` 配下だけはファイルパスで
読み込む。

`data/` は `.gitignore` されている。`exedit.auf` と AviUtl SDK の `filter.h` を
各自で配置すること。

## 解析済みエフェクト

| ディレクトリ | エフェクト | 概要 |
|---|---|---|
| [`inspect/blur`](inspect/blur/README.md) | `ぼかし` | 4パス連鎖のボックス平均。軸ごとの2パスが三角形カーネルを合成する |
| [`inspect/boundary_blur`](inspect/boundary_blur/README.md) | `境界ぼかし` | アルファだけを操作する erosion + cosine イージングテーブル |
| [`inspect/glow`](inspect/glow/README.md) | `発光` | 明部抽出 + 6段マルチスケールぼかし。`拡散速度` は指数/対数空間でのぼかし |
| [`inspect/mozaic`](inspect/mozaic/README.md) | `モザイク` | ブロック平均と `タイル風` のハイライト |
| [`inspect/glint`](inspect/glint/README.md) | `閃光` | 中心へ向かう放射状の光線サンプリング。輝度をそのままアルファに移して出力 |

## 共通ツール (`tools/`)

エフェクト非依存の部分はここに集約してある。`inspect/` 配下のスクリプトはすべて
これらの上に乗っていて、pefile / capstone / angr を直接触るのは、CFG そのものを
一覧したい2箇所だけ。

| ツール | 役割 |
|---|---|
| `tools.get_func_address` | `FILTER_DLL` 配列(先頭 `0x100a3e28`)を1行/エフェクトでダンプ |
| `tools.filter_table` | 登録構造体の完全デコード。トラックバー・チェックボックス・`ex_data_def`・`+0x74` 拡張ブロック。`--name <名前>` で1エフェクト分を詳細表示 |
| `tools.track_scale` | `+0x74` 拡張ブロックの解読 ―― 表示スケール / スライダーのドラッグ範囲 / 多成分コントロールのグループ化マーカー。`--groups` で全エフェクト分の根拠を出力 |
| `tools.disasm` | capstone 逆アセンブル。絶対メモリオペランドの定数解決と、アドレス指定・ルール指定どちらの注釈にも対応 |
| `tools.decompile` | angr の範囲限定デコンパイル。`--calls` で直接呼び出し先を列挙 |
| `tools.xrefs` | 任意の VA への参照を全画像から検索し、どのエフェクトのコードかを推定 |
| `tools.pe_image` | (ライブラリ)PE を VA でアドレッシングする共通基盤 |
| `tools.cints` | (ライブラリ)C / x86 の整数意味論。`c_div`(0方向切り捨て)、`sar`(floor)、MSVC のマジックナンバー除算の逐語再現 |

`tools.pe_image` と `tools.cints` はライブラリなので `main.py` からは実行できない。

### なぜ `tools.cints` が要るか

Python の `//` は floor、C の `/` と x86 の `idiv` は0方向への切り捨てで、
負の被除数で結果が食い違う。exedit は固定小数のスケーリングに `sar`(= floor)を、
平均に `idiv`(= truncate)を、隣り合った行で使い分けている。色差 Cb/Cr は符号付き
なので、ここを取り違えたリファレンス実装は**グレースケールでは一致するのに色が
付いた瞬間ずれる**。
