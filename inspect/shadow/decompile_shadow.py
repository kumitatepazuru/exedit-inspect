"""Decompile シャドー (shadow)'s func_proc and every function it owns.

`tools.filter_table --name シャドー` gives the entry point (0x10087fb0, the
*only* registration under that exact name - object effect only), four
trackbars (X, Y, 濃さ, 拡散) and three checkboxes, two of which are really
buttons (影色の設定, パターン画像ファイル).

All of シャドー's private code is one contiguous block 0x10087fb0-0x10089024
(about 4.2 KB), with シャープ's func_proc at 0x10089030 immediately after; the
CFG window below stops short of it so its blocks never get folded in.

The shape to keep in mind while reading the output is a **four-pass box-blur
chain over the object's alpha alone**, ending in one of two encoders:

    pass 1  sub_10088580  vertical   kernel B   fpip+0xAC (alpha) -> plane 1
    pass 2  sub_100886f0  horizontal kernel B   plane 1           -> plane 2
    pass 3  sub_10088840  vertical   kernel A   plane 2           -> plane 1
    pass 4  sub_100889a0  horizontal kernel A   plane 1           -> fpip+0xB0
            sub_10088bc0  ... the same pass when a pattern image is loaded

`kernel A = 2*trunc(拡散/2)+1` and `kernel B = 2*(拡散-trunc(拡散/2))+1`, i.e.
the same "split the radius in half and run two passes per axis" trick ぼかし
uses to synthesise a triangular kernel out of uniform boxes (box_blur.md §2).
The two intermediate planes are 16-bit alpha-only scratch, carved out of the
shared scratch buffer [0x101a5328] that 発光/グロー/クロマキー/ライト also
borrow.

Two things the decompiler will not show, which is why disasm_params.py exists
alongside this file:

  * angr does not lift x87, and pass 4's entire output encoding is x87 - the
    `fild`/`fdivp`/`fmul`/`_ftol` sequence that turns the blurred alpha into
    the shadow's alpha comes out as `/* unsupported instruction */`.
  * the geometry section of func_proc (canvas growth by |X| and |Y|, the
    centre-of-object correction written back into fpip+0xD4/+0xD8, and which
    of the two placements is the shadow's and which is the object's) is plain
    integer code that decompiles fine but reads as an undifferentiated wall of
    `esp+0x..` slots; the annotated disassembly is where those slots get names.

Run via main.py:
    uv run main.py inspect/shadow/decompile_shadow.py
    uv run main.py inspect/shadow/decompile_shadow.py --only func_proc
"""

from tools.decompile import decompile_cli

FUNC_PROC = 0x10087FB0

TARGETS = {
    "func_proc (parameters, geometry, dispatch, composite)": FUNC_PROC,
    "pass 1: vertical box-average of alpha, kernel B -> scratch plane 1": 0x10088580,
    "pass 2: horizontal box-average, kernel B, plane 1 -> plane 2": 0x100886F0,
    "pass 3: vertical box-average, kernel A, plane 2 -> plane 1": 0x10088840,
    "pass 4: horizontal box-average, kernel A + flat-colour encode -> fpip+0xB0": 0x100889A0,
    "pass 4 (pattern image loaded): multiply the pattern's own alpha instead": 0x10088BC0,
    "func_WndProc (影色の設定 / パターン画像ファイル)": 0x10088DA0,
    "rebuild both button labels": 0x10088F40,
    "settings-window update (FILTER+0x58)": 0x10089010,
}

# Shared exedit/CRT helpers func_proc and func_WndProc reach directly. They sit
# far outside the CFG window above, so they are dumped as raw disassembly
# rather than decompiled - enough to see the argument shape without a second
# invocation.
HELPERS = {
    "ex_data colour -> YCbCr (shared with 発光 / グロー / 閃光 / ライト)": (0x1006FED0, 0x60),
    "table[0x38] = image file loader (shared with 画像ファイル)": (0x1004C8D0, 0x40),
    "table[0x3c] = resolve the stored path (shared)": (0x1004CC40, 0x40),
    "modal-dialog wrapper behind the ファイル選択 button": (0x10020900, 0x68),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    base = FUNC_PROC & ~0xFFF
    # シャープ's func_proc starts at 0x10089030; stop well short of it.
    decompile_cli(dll_path, TARGETS, argv, region=(base, 0x10089028), extra=HELPERS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
