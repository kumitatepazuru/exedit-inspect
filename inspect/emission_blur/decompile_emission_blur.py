"""`放射ブラー` の4関数を angr で範囲限定デコンパイルする。

手読みした制御フローの独立な裏付けを取るのが目的。x87 は angr がリフト
できない(`/* unsupported instruction */` になる)ので、距離・サンプル数の
式は `disasm_params.py` 側で読む。ここで見たいのは形のほうである:

  * オブジェクト版 `func_proc` が **画素に一切触らず**、グローバル6個を
    書いてワーカーを1本起動し、そのあと `+0xAC`/`+0xB0` を入れ替えて
    `+0xB4`/`+0xB8`/`+0xD4`/`+0xD8` を書き換えるだけであること
  * フレーム版 `func_proc` が**中心が枠内かどうかで2つのワーカーを
    使い分ける**こと(枠内なら範囲判定が要らない)
  * ワーカーが `y` の二重ループ + サンプルループの3重ループで、
    内側に `call` が `_ftol` 以外に無いこと

Run via main.py:
    uv run main.py inspect/emission_blur/decompile_emission_blur.py
    uv run main.py inspect/emission_blur/decompile_emission_blur.py --only worker
"""

from tools.decompile import decompile_cli

TARGETS = {
    "func_proc (オブジェクト効果, 0x1000b310)": 0x1000B310,
    "worker オブジェクト (0x1000b660)": 0x1000B660,
    "func_proc (フレームフィルタ, 0x1000ba10)": 0x1000BA10,
    "worker フレーム・中心が枠内 (0x1000bb90)": 0x1000BB90,
    "worker フレーム・中心が枠外 (0x1000be30)": 0x1000BE30,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    # 0x1000b310-0x1000c0e4 の 3540 バイトが放射ブラーの全実装。次の関数
    # (方向ブラーの func_proc 0x1000c200) を巻き込まないよう窓を切る。
    decompile_cli(dll_path, TARGETS, argv, span=0x200,
                  region=(0x1000B000, 0x1000C200))


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
