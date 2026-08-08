"""Decompile 縁取り (border)'s func_proc and every function it owns.

`tools.filter_table --name 縁取り` gives the entry point (0x100515d0, the
*only* registration - object effect only, `flag = 0x40000020`), two trackbars
(サイズ, ぼかし) and two checkboxes that are both really buttons
(縁色の設定, パターン画像ファイル).

All of 縁取り's private code is one contiguous block 0x100515d0-0x100522e3
(about 3.3 KB); フレームバッファ's func_proc starts at 0x100522f0 immediately
after, and the CFG window below stops short of it so its blocks never get
folded in.

The shape to keep in mind while reading the output is a **two-pass separable
box SUM over the object's alpha alone** - not an average, there is no divide
anywhere in the chain - feeding one of two encoders:

    pass 1  sub_10051ae0  vertical    fpip+0xAC (alpha) -> 16-bit scratch plane
    pass 2  sub_10051c80  horizontal  scratch plane     -> fpip+0xB0, flat colour
            sub_10051ea0  ... the same pass when a pattern image is loaded

Both passes multiply the running window sum by the same gain
`g_101b1f54 = round(1024 / (0.02*サイズ*ぼかし + 1))`, shift right 10 and
saturate at 4096, so with `ぼかし = 0` (gain = 1024) the chain degenerates to
`min(4096, sum)` twice - a dilation of the silhouette by サイズ - and larger
`ぼかし` scales the sum down so the edge ramps instead of stepping.

Three things the decompiler will not show, which is why disasm_params.py
exists alongside this file:

  * angr does not lift x87, and the gain is computed entirely in x87 - the
    `fild`/`fmul`/`fdivr`/`fadd`/`_ftol` sequence at 0x10051984-0x100519a5
    comes out as `/* unsupported instruction */`.
  * the geometry section of func_proc (the pre-pad that guarantees the object
    is at least one kernel wide, the growth by 2*サイズ, and the crop that
    undoes the pre-pad at the end) decompiles fine but reads as an
    undifferentiated wall of `esp+0x..` slots; the annotated disassembly is
    where those slots get names.
  * angr renders the saturating store as a plain if/else and loses that the
    multiply is a signed 32-bit `imul` - which is where the サイズ >= 256 /
    ぼかし = 0 overflow in verify_border_chain.py §5 lives.

Run via main.py:
    uv run main.py inspect/border/decompile_border.py
    uv run main.py inspect/border/decompile_border.py --only func_proc
"""

from tools.decompile import decompile_cli

FUNC_PROC = 0x100515D0

TARGETS = {
    "func_proc (parameters, canvas, pattern tiling, dispatch, composite)": FUNC_PROC,
    "pass 1: vertical box-sum of alpha -> 16-bit scratch plane": 0x10051AE0,
    "pass 2: horizontal box-sum + flat-colour encode -> fpip+0xB0": 0x10051C80,
    "pass 2 (pattern image loaded): multiply the pattern's own alpha instead": 0x10051EA0,
    "func_WndProc (縁色の設定 / パターン画像ファイル)": 0x10052070,
    "rebuild both button labels": 0x10052200,
    "settings-window update (FILTER+0x58)": 0x100522D0,
}

# Shared exedit/CRT helpers func_proc and func_WndProc reach directly. They sit
# far outside the CFG window above, so they are dumped as raw disassembly
# rather than decompiled - enough to see the argument shape without a second
# invocation.
HELPERS = {
    "ex_data colour -> YCbCr (shared with 発光 / グロー / 閃光 / ライト / シャドー)":
        (0x1006FED0, 0x60),
    "table[0x38] = image file loader (shared with 画像ファイル / シャドー)": (0x1004C8D0, 0x40),
    "table[0x3c] = resolve the stored path (shared with シャドー)": (0x1004CC40, 0x40),
    "modal-dialog wrapper behind the ファイル選択 button (shared with シャドー)":
        (0x10020900, 0x68),
    "CRT _ftol (truncate toward zero) - rounds the gain": (0x10091AD8, 0x20),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    base = FUNC_PROC & ~0xFFF
    # フレームバッファ's func_proc starts at 0x100522f0; stop short of it.
    decompile_cli(dll_path, TARGETS, argv, region=(base, 0x100522E4), extra=HELPERS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
