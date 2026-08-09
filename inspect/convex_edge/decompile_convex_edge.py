"""Decompile 凸エッジ (convex edge) - all two functions of it.

`tools.filter_table --name 凸エッジ` gives the entry point (0x10007a80, the
only registration - object effect, `flag = 0x20`), three trackbars
(幅, 高さ, 角度), no checkboxes, no ex_data and no func_WndProc. There is
nothing else to find: the effect is 0x10007a80-0x10007dcd, 846 bytes, and the
only other address in it is the worker at 0x10007b90.

The shape to keep in mind while reading the output is a **signed directional
difference of the alpha channel, added to luminance**:

    d(x,y) = trunc( K * SUM over k=1..steps of [ a(p + o_k) - a(p - o_k) ] )
    o_k    = ( floor(k*dx / 65536), floor(k*dy / 65536) )
    (dx, dy) = ( trunc(-sin(角度)*65536), trunc(cos(角度)*65536) )
    K      = 高さ_raw / (200 * steps)

so the edge facing (dx, dy) darkens and the opposite edge brightens, which is
a bevel. Alpha is copied through untouched, the canvas never moves, and no
neighbour's *colour* is ever read - only its alpha.

Three things the decompiler will not show, which is why disasm_params.py
exists alongside this file:

  * angr does not lift x87. The direction vector and the scale K are computed
    entirely in x87 (0x10007abb-0x10007ae8 and 0x10007b38-0x10007b59), and
    that whole block comes out as `/* unsupported instruction */` - including
    the multiply by -pi/1800 that fixes the sign convention.
  * the worker reuses the caller's argument slots `esp+0x48` / `esp+0x4c` as
    the source cursor and the running sum, so angr shows the sum being written
    into a variable it also calls `node` (its name for thread_num). The slot
    map in disasm_params.py is what makes that readable.
  * `>> 16` on the accumulators is `sar` (floor), and the backward sample is
    `-(ox, oy)` rather than a second floor - the two together are what make
    the sampling exactly point-symmetric (verify_direction.py §3).

angr does recover the encode correctly, including the divide
`v45 = v43 * 0x1000 / v42` that rescales chroma on the darkening path.

Run via main.py:
    uv run main.py inspect/convex_edge/decompile_convex_edge.py
    uv run main.py inspect/convex_edge/decompile_convex_edge.py --only worker
"""

from tools.decompile import decompile_cli

FUNC_PROC = 0x10007A80

TARGETS = {
    "func_proc (幅 clamp, 角度 -> Q16 direction, 高さ -> scale, dispatch, swap)": FUNC_PROC,
    "worker (row band, directional alpha difference, luminance encode)": 0x10007B90,
}

# The only shared code either function reaches. exec_multi_thread_func is an
# indirect call through fp->exfunc (+0xCC) so it has no address here.
HELPERS = {
    "CRT _ftol (truncate toward zero) - used 3x: dx, dy, and d per pixel":
        (0x10091AD8, 0x20),
    "方向ブラー's func_proc opening: the same angle convention, spelled with "
    "+pi/1800 and a negative 65536 (inspect/common/angle_vector.md)":
        (0x1000C200, 0x60),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    # 直前オブジェクト's func_proc is at 0x10007a70 and the shared blend
    # functions start at 0x10007dd0; keep the CFG window inside that gap plus
    # a little slack so neither gets folded in.
    decompile_cli(dll_path, TARGETS, argv, region=(FUNC_PROC & ~0xFFF, 0x10007DCE),
                  extra=HELPERS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
