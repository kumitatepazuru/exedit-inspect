"""Decompile グロー (glow)'s func_proc and every worker it can dispatch to.

`tools.filter_table --name グロー` gives the entry point (0x10054db0, shared by
both registrations) and the four trackbars. Everything グロー owns lives in one
contiguous block 0x10054db0-0x10058ea0, immediately after 発光's, so a single
CFG window covers it.

The dispatch has two independent axes and it is worth having them in mind while
reading the output:

  * `ex_data.no_color` (bit24 of dword[0]) and `fp->flag & 0x20` pick one of
    four *bright-part extraction* workers, which fill the scratch buffer.
  * `ex_data.type` (dword[1], the 形状 combo) is a 6-way `switch` that picks
    which *shape* workers smear that scratch across the accumulation buffer.
    `通常` is a 4-pass separable box cascade; the other five are streak workers
    that walk one direction at three scales each.

Caveats, same as everywhere else in this repo:

  * angr does not lift x87. Here that costs almost nothing - グロー's only
    floating point is the `sqrt` at 0x10054e15 (disasm_params.py reads it) -
    but the workers are still 2-3 KB of near-identical unrolled sliding-window
    loops, so the decompilation is useful for *which buffer each loop touches*
    rather than for the arithmetic.
  * the switch at 0x100551a3 is an indirect `jmp [eax*4 + 0x1005551c]`; angr
    recovers the six cases, and verify_shapes.py prints the table itself.

Run via main.py:
    uv run main.py inspect/glow/decompile_glow.py
    uv run main.py inspect/glow/decompile_glow.py --only func_proc
"""

from tools.decompile import decompile_cli

FUNC_PROC = 0x10054DB0

TARGETS = {
    "func_proc (dispatcher)": FUNC_PROC,
    "extract: object, 光色=指定なし": 0x10055540,
    "extract: object, 光色=指定あり": 0x10055690,
    "extract: frame, 光色=指定なし": 0x100557A0,
    "extract: frame, 光色=指定あり": 0x100558E0,
    "通常: vertical box average (accum -> scratch)": 0x10055A10,
    "ぼかし tail: horizontal box average (scratch -> accum)": 0x10055C70,
    "通常: horizontal box sum + weighted accumulate": 0x10055ED0,
    "ライン(縦) streak, scale 1": 0x10056220,
    "ライン(縦) streak, scales 2 and 4": 0x10056700,
    "accumulate + saturate helper": 0x10056680,
    "ライン(横) streak, scale 1": 0x100569E0,
    "ライン(横) streak, scales 2 and 4": 0x10056E00,
    "斜め streak, direction (+1,+1), diagonals from the left edge": 0x100570D0,
    "斜め streak, direction (+1,+1), scales 2 and 4": 0x10057410,
    "斜め streak, direction (+1,+1), diagonals from the top edge": 0x10057730,
    "斜め streak, direction (+1,+1) top edge, scales 2 and 4": 0x10057A70,
    "斜め streak, direction (-1,+1), diagonals from the right edge": 0x10057D90,
    "斜め streak, direction (-1,+1), scales 2 and 4": 0x10058100,
    "斜め streak, direction (-1,+1), diagonals from the top edge": 0x10058430,
    "斜め streak, direction (-1,+1) top edge, scales 2 and 4": 0x10058780,
    "composite: object effect": 0x10058AA0,
    "composite: frame filter": 0x10058DE0,
    "func_WndProc": 0x10058EA0,
    "func_WndProc: rebuild the 光色の設定 button label": 0x10058F60,
    "settings-window update (FILTER+0x58)": 0x10058FE0,
}

# The only CRT stub func_proc calls directly; it lands there from the x87
# sqrt sequence, so it never appears as a call in the C output.
FP_HELPERS = {
    "double -> int truncation thunk (MSVC _ftol pattern)": (0x10091AD8, 0x30),
    "ex_data colour -> YCbCr (shared with 発光 / 閃光)": (0x1006FED0, 0x60),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    base = FUNC_PROC & ~0xFFF
    decompile_cli(dll_path, TARGETS, argv, region=(base, base + 0x5000), extra=FP_HELPERS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
