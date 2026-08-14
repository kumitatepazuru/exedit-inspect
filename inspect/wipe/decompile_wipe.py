"""angr decompilation of ワイプ: func_init, func_proc, 5個の組み込みパターン
ワーカー、ぼかしの2軸パス、最終合成、カスタムPNGパターンの一式、func_WndProc。

`0x100903c0`(func_init)から `0x10091794`(func_WndProc の終端)まで、
ワイプのエフェクト固有コードはほぼ隙間なく1本の領域に収まっている ―― nop
パディングの数バイトを除けば `disasm_params.py` / `verify_*.py` が読んでいる
命令はすべてこの範囲の中。

進捗の秒->フレーム変換(x87)と各パターンのしきい値計算(x87の `fsqrt`/`fpatan`
を含む)は angr が lift できないので `/* unsupported instruction */` になる
―― それを埋めるのが `disasm_params.py` と `verify_patterns.py`。この
スクリプトは主に**制御フローの形**(分岐・呼び出し先・ループ境界)を、
手で読んだ内容と独立に確認する目的で使う。

`横`(`0x10090ec0`)と `縦`(`0x10090f90`)は angr がこの CFG 窓では関数として
認識できず("did not recover a function")、デコンパイル結果が出ない。
`verify_patterns.py` の Python 再実装と `tools.disasm` の生ダンプ(このファイル
の docstring および `inspect/wipe/README.md` に転記した抜粋)がそちらの根拠。

Run via main.py:
    uv run main.py inspect/wipe/decompile_wipe.py
    uv run main.py inspect/wipe/decompile_wipe.py --only proc
    uv run main.py inspect/wipe/decompile_wipe.py --only circle
"""

from tools.decompile import decompile_cli

REGION = (0x10090000, 0x10092000)

TARGETS = {
    "func_init                    0x100903c0": 0x100903C0,
    "func_proc                    0x10090490": 0x10090490,
    "blur: kernel split           0x10090640": 0x10090640,
    "blur: axis1 (V, ->scratch)   0x10090700": 0x10090700,
    "blur: axis2 (H, scratch->)   0x100908c0": 0x100908C0,
    "pattern: 時計 clock          0x10090a60": 0x10090A60,
    "pattern: 四角 square(L1)     0x10090c00": 0x10090C00,
    "pattern: 円 circle (既定)    0x10090d50": 0x10090D50,
    "pattern: 横 horizontal       0x10090ec0": 0x10090EC0,
    "pattern: 縦 vertical         0x10090f90": 0x10090F90,
    "final composite: obj*=mask   0x10091050": 0x10091050,
    "custom: load + guard + blit  0x10091100": 0x10091100,
    "custom: 3x3 smooth + apply   0x10091310": 0x10091310,
    "custom: threshold band       0x10091500": 0x10091500,
    "func_WndProc: combo select   0x10091710": 0x10091710,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
