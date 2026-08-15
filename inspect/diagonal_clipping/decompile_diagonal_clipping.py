"""`斜めクリッピング` の全3関数を angr で range 限定デコンパイルする。

エフェクト全体が `0x1005cab0`〜`0x1005cea7` の連続した1016バイトに収まって
いるので、CFG のウィンドウは `--span` から作らずに固定で与えている。前は
`ライト`(`0x1005ba30`〜)、後ろは無関係な cp932 文字列コピー
(`0x1005ceb0`、`アニメーション効果` 側から呼ばれる)なので、はみ出しても
遅くなるだけで得るものが無い。

出力は**形**を読むためのもので、式は [`disasm_params.py`](disasm_params.py)
の側にある。角度→ベクトルの変換と `fsqrt` は x87 なので angr は
`/* unsupported instruction */` としか言わない。それでも次の3点は
デコンパイル結果だけで独立に確認できる ―― 手で読んだ制御フローの裏取りに
なる:

  * `func_proc` は `g_101b20c8 = index[45]/2 + track[0]`(= `w/2 + 中心X`)
    のようにグローバル5個を書いてから、`幅<<15` のフラグで
    `sub_1005ccb0` / `sub_1005cb70` のどちらかを
    `exec_multi_thread_func` に渡して `return 1` する。**画素ループも
    早期リターンも無い。**
  * 両ワーカーとも `idx->field_ac`(= `*(fpip+0xAC)`)を 8バイト刻みで
    歩き、書くのは `field_6`(= アルファ)**だけ**。`y`/`cb`/`cr` は
    構造体のフィールドとしてすら現れない。
  * `sub_1005ccb0` は `if (g_101b20c4 > 0)` で丸ごと2つに割れていて、
    `hw - |s|` と `|s| + hw` という**符号だけが違う2本の式**を持つ。
    `幅` の符号が帯を残すか消すかを決めている、という読みの直接の根拠。

Run via main.py:
    uv run main.py inspect/diagonal_clipping/decompile_diagonal_clipping.py
    uv run main.py inspect/diagonal_clipping/decompile_diagonal_clipping.py --only band
"""

from tools.decompile import decompile_cli

REGION = (0x1005CA00, 0x1005CF00)

TARGETS = {
    "func_proc                     0x1005cab0": 0x1005CAB0,
    "worker: halfplane (幅 == 0)   0x1005cb70": 0x1005CB70,
    "worker: band      (幅 != 0)   0x1005ccb0": 0x1005CCB0,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
