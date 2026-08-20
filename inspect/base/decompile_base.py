"""8フィルタのうち、分岐が複雑な5つを angr でデコンパイルする。

`座標`/`回転`/`透明度` は分岐がほぼ無く disasm だけで十分なので対象外
(verify_deferred_params.py に生ログがある)。ここでは:

  * `拡大率`      ―― 分岐の形(2候補生成 + 3本のスキップ判定 + 末尾の大小比較)
  * `領域拡張`    ―― 4本のマージンのクランプ順序と 塗りつぶし ON/OFF の分岐
  * `リサイズ`    ―― 比率/ドット数の2モードとクランプ、早期リターン2種
  * `ローテーション` ―― mod4 のジャンプテーブルと3ハンドラの呼び分け
  * `反転`        ―― flag&0x20 の1回の分岐と、後続5+4本の check ループ

x87 は angr がリフトできないので `/* unsupported instruction */` になる
(param_scaling.md の変換や 拡大率 の内部計算)。分岐構造・呼び出し先・
触っているメモリを一覧するのが目的で、演算の中身は各 verify_*.py と
disasm の役目。

Run via main.py:
    uv run main.py inspect/base/decompile_base.py
    uv run main.py inspect/base/decompile_base.py --only 領域拡張
"""

from tools.decompile import decompile_cli

TARGETS = {
    "拡大率           0x100078c0": 0x100078C0,
    "領域拡張         0x10006c20": 0x10006C20,
    "リサイズ         0x100071c0": 0x100071C0,
    "ローテーション   0x100075b0": 0x100075B0,
    "反転             0x10082260": 0x10082260,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, span=0x1000)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
