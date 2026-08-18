"""`レンズブラー` の `func_proc` とワーカー、リサイズ4本を範囲限定デコンパイル。

`レンズブラー` は本プロジェクトで扱う中でも工程が多い(キャンバス拡張 →
輝度カーブ順変換 → 半径圧縮 → 縮小 → 円形カーネル → 逆変換 → 拡大)ので、
まず全体の呼び出し構造を angr で確認する。x87(円の半径²、色の除算)は
リフトできないので `disasm_params.py` で補う。

Run via main.py:
    uv run main.py inspect/lens_blur/decompile_lens_blur.py
    uv run main.py inspect/lens_blur/decompile_lens_blur.py --only func_proc
    uv run main.py inspect/lens_blur/decompile_lens_blur.py --only resize
"""

from tools.decompile import decompile_targets

MAIN = {
    "func_proc (0x10012420、オブジェクトとフレームで共有)": 0x10012420,
    "worker オブジェクト (0x10012880)": 0x10012880,
    "worker フレーム (0x10012b50)": 0x10012B50,
}

RESIZE = {
    "resize 縮小・オブジェクト (0x10071420)": 0x10071420,
    "resize 拡大・オブジェクト (0x100709a0)": 0x100709A0,
    "resize 縮小・フレーム (0x10072870)": 0x10072870,
    "resize 拡大・フレーム (0x10072000)": 0x10072000,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    only = None
    for i, a in enumerate(argv or []):
        if a == "--only" and i + 1 < len(argv):
            only = argv[i + 1]

    if only is None or "resize" not in only:
        targets = {k: v for k, v in MAIN.items() if only is None or only in k}
        if targets:
            decompile_targets(dll_path, targets, region=(0x10012400, 0x10013000))
    if only is None or "resize" in only:
        # リサイズ4本は 0x1007xxxx にまとまっている。ディスパッチャだけを見る
        # (実際の画素ループは 0x1006c650 経由で起動されるワーカー側)。
        decompile_targets(dll_path, RESIZE, region=(0x10070000, 0x10073000))


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
