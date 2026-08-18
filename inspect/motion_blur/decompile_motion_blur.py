"""`モーションブラー` の `func_proc` とワーカー3本を範囲限定デコンパイル。

このエフェクトは画素より**時間**を触る量が多く、`fpip` の3つの時刻
フィールドを巻き戻しながら exedit のコア側ルーチンを繰り返し呼ぶ。
angr の出力で見たいのはその呼び出し構造:

  * `func_proc` が `分解能` 回まわるループを持ち、その中で
    `0x1004b200`(別オブジェクトとして描画)/ `0x1004ccf0`(フレーム版)を
    呼んでいること
  * ループの外に、`0x1004d7d0`(名前付きキャッシュ)と
    `[0x100b8c60]`(オフスクリーン描画)への呼び出しがあること
  * ワーカー3本がどれも「蓄積バッファと入力の2画素を混ぜて書き戻す」
    だけの単純な形であること

Run via main.py:
    uv run main.py inspect/motion_blur/decompile_motion_blur.py
    uv run main.py inspect/motion_blur/decompile_motion_blur.py --only worker
"""

from tools.decompile import decompile_cli

TARGETS = {
    "func_proc (0x1006bd30)": 0x1006BD30,
    "worker オブジェクト・残像 ON (0x1006c0d0)": 0x1006C0D0,
    "worker オブジェクト・残像 OFF (0x1006c2e0)": 0x1006C2E0,
    "worker フレーム (0x1006c500)": 0x1006C500,
}

EXTRA = {
    "0x1000ad80 (1画素を「下に」合成する。モーションブラー専用)": (0x1000AD80, 0x110),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, span=0x200,
                  region=(0x1006BD00, 0x1006C700), extra=EXTRA)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
