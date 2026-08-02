"""Decompile ライト (light)'s func_proc and every function it owns.

`tools.filter_table --name ライト` gives the entry point (0x1005ba30, the
*only* registration - object effect only, no frame-filter twin) and the three
trackbars (強さ, 拡散, 比率) plus two checkboxes (逆光, 色の設定 button).

All of ライト's private code lives in one small, contiguous block
0x1005ba30-0x1005caa4 (about 4.2 KB), immediately followed by 斜めクリッピング's
func_proc at 0x1005cab0 - `tools.decompile --calls` run over a window wide
enough to spill into that neighbour will list its callees too, which is a trap
this script's TARGETS dict deliberately stays inside of.

The dispatch has two independent axes worth having in mind while reading the
output:

  * `強さ` and `比率` (-100%..100%) combine into two Q12 coefficients, A and B
    (disasm_params.py has the exact instructions). B drives a pass that tints
    the *source object's own pixels* in place (`fpip+0xAC`), reading either the
    plain box-blurred alpha (逆光 off) or the inverted one (逆光 on) as a
    proxy for "how deep into the solid shape". A drives a second, unconditional
    pass that box-blurs the alpha into a *separate*, larger canvas and paints a
    flat light-coloured halo there, then draws the (already tinted) object back
    on top of it.
  * `check[0]` (逆光) picks between two near-identical pairs of workers
    (0x1005c520/0x1005c700 vs 0x1005c080/0x1005c250) that differ in one
    inverted read and one missing "+4096" offset - angr's decompiler renders
    both fine at the C-shape level, but the actual destination pointer
    (`fpip+0xAC` vs `fpip+0xB0`) and the add-vs-store distinction on the pixel
    write only show up in the raw disassembly (disasm_params.py), which is why
    that script exists alongside this one.

Caveats, same as everywhere else in this repo:

  * angr does not lift x87. The magic-number divides (`0x10624dd3` -> /1000,
    `0x2e8ba2e9` -> /11) show up as plain `imul`/`sar` and decompile just fine;
    it is the *pixel writes* inside the workers where the decompiler's
    struct-offset inference goes wrong (it types 0x1005c250's destination as
    "field_ac" *and* separately loses the `add` vs `mov` distinction on
    neighbouring stores), so those claims are re-checked against raw bytes in
    disasm_params.py / verify_shading.py rather than trusted from this output.

Run via main.py:
    uv run main.py inspect/light/decompile_light.py
    uv run main.py inspect/light/decompile_light.py --only func_proc
"""

from tools.decompile import decompile_cli

FUNC_PROC = 0x1005BA30

TARGETS = {
    "func_proc (dispatcher)": FUNC_PROC,
    "halo: vertical box-average of alpha -> scratch": 0x1005BCD0,
    "halo: horizontal box-average + amplify-multiply encode -> fpip+0xB0": 0x1005BE50,
    "gradient (逆光 off): vertical box-average of alpha -> scratch": 0x1005C080,
    "gradient (逆光 off): horizontal box-average + tint add -> fpip+0xAC": 0x1005C250,
    "gradient (逆光 on): vertical box-average of INVERTED alpha -> scratch": 0x1005C520,
    "gradient (逆光 on): horizontal box-average + tint add -> fpip+0xAC": 0x1005C700,
    "func_WndProc": 0x1005C9C0,
    "func_WndProc: rebuild the 色の設定 button label": 0x1005CA30,
    "settings-window update (FILTER+0x58)": 0x1005CA90,
}

# The shared CRT/exedit helpers func_proc calls directly; they never show up
# as "call 0x..." inside the workers, so they are worth reading as raw
# disassembly rather than decompiled (angr already renders them fine, this is
# just to have them side by side without a second invocation).
FP_HELPERS = {
    "ex_data colour -> YCbCr (shared with 発光 / グロー / 閃光)": (0x1006FED0, 0x60),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    base = FUNC_PROC & ~0xFFF
    # 斜めクリッピング's func_proc starts at 0x1005cab0; stop the CFG window
    # well short of it so its workers are never recovered as ライト's own.
    decompile_cli(dll_path, TARGETS, argv, region=(base, 0x1005CAB0), extra=FP_HELPERS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
