"""angr decompilation of エッジ抽出's func_proc, its three workers and its UI code.

Everything the effect does lives in one contiguous stretch of .text,
`0x10022d60`-`0x10023c73`, so a single CFG window covers the lot. The window is
pinned rather than derived from `--span`: the neighbours on both sides
(`ディスプレイスメントマップ` below, `拡張描画` above) are unrelated filters and
letting angr wander into them only slows the run down.

Read the output for *shape*, not for arithmetic. Every worker finishes each
pixel with `fild`/`fsqrt`, which angr does not lift, so the magnitude comes out
as `/* unsupported instruction */`; verify_prewitt_taps.py and
verify_output_encoding.py supply the formulas. What this script is for:

  * func_proc has no pixel loop at all - it writes five globals, fires exactly
    one `exec_multi_thread_func` call chosen by two checkboxes, and swaps
    `*(fpip+0xAC)` with `*(fpip+0xB0)`,
  * the three workers are three independent code paths, not variations sharing
    a helper: the only `call` any of them makes is to the CRT's `_ftol`
    (`0x10091ad8`), three times in one and once in the other two,
  * `func_WndProc` never touches `fp->track[]`; it forces the two checkboxes to
    behave as radio buttons and opens the colour dialog.

Run via main.py:
    uv run main.py inspect/edge_extraction/decompile_edge_extraction.py
    uv run main.py inspect/edge_extraction/decompile_edge_extraction.py --only worker
"""

from tools.decompile import decompile_cli

REGION = (0x10022000, 0x10024000)

TARGETS = {
    "func_proc                        0x10022d60": 0x10022D60,
    "worker: 色エッジ (両チェック OFF) 0x10022e30": 0x10022E30,
    "worker: 輝度エッジ               0x100234c0": 0x100234C0,
    "worker: 透明度エッジ             0x10023880": 0x10023880,
    "func_WndProc                     0x10023af0": 0x10023AF0,
    "button label rebuild             0x10023c00": 0x10023C00,
    "FILTER+0x58 hook                 0x10023c60": 0x10023C60,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
