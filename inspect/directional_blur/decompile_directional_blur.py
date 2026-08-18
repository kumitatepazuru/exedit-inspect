"""`方向ブラー` の4関数を angr で範囲限定デコンパイルする。

手読みした制御フローの独立な裏付け。x87(角度 → Q16 ベクトル)は angr が
リフトできないので `disasm_params.py` で読む。ここで見たいのは形:

  * オブジェクト版 `func_proc` が `サイズ固定` で**別のワーカーを選ぶ**こと
    (`ぼかし` と同じ構造。ただし2本だけ)
  * 2本のワーカーが最後の1点 ―― アルファの除数 ―― 以外は同じ形であること
  * フレーム版 `func_proc` にはキャンバスの矩形計算が**存在しない**こと

Run via main.py:
    uv run main.py inspect/directional_blur/decompile_directional_blur.py
    uv run main.py inspect/directional_blur/decompile_directional_blur.py --only worker
"""

from tools.decompile import decompile_cli

TARGETS = {
    "func_proc (オブジェクト効果, 0x1000c200)": 0x1000C200,
    "worker サイズ固定OFF (0x1000c4a0)": 0x1000C4A0,
    "worker サイズ固定ON  (0x1000c720)": 0x1000C720,
    "func_proc (フレームフィルタ, 0x1000c9b0)": 0x1000C9B0,
    "worker フレーム (0x1000cb10)": 0x1000CB10,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    # 0x1000c200-0x1000cd7d が方向ブラーの全実装。前は放射ブラー、後ろは
    # 画像ファイル(0x1000d5e0)なので窓をその間に切る。
    decompile_cli(dll_path, TARGETS, argv, span=0x200,
                  region=(0x1000C200, 0x1000D000))


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
