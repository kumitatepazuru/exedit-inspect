"""Work out exactly how much bigger an object gets when ぼかし runs on it,
and what サイズ固定 changes besides the size.

There are two separate mechanisms that both end up growing the canvas by
(2*rx, 2*ry), and confusing them makes the サイズ固定 behaviour look
inconsistent:

  * The normal route. Each of the four passes uses a worker that writes
    2*radius extra rows (or columns) and func_proc then adds 2*radius to
    *(fpip+0xB8) / *(fpip+0xB4). Summed over the two passes per axis that is
    2*(r_hi + r_lo) = 2*r, and because each pass places its output shifted by
    its own radius, the object ends up centred in the new canvas.

  * The pre-expansion route, taken when a radius is at least half the canvas.
    The sliding-window workers cannot handle that (their middle phase runs
    `h - kernel` times, which would be <= 0), so func_proc first blits the
    object into the middle of an already-enlarged, cleared buffer, then sets
    its own copy of サイズ固定 to 1 so the four passes run the non-growing
    workers on that buffer instead.

The second route means サイズ固定 is read twice with different meanings: the
checkbox as the user set it decides whether expansion is allowed at all, and
the local copy - which the pre-expansion path overwrites - decides which
worker each pass calls. This script disassembles both, then reproduces the
size arithmetic in Python for a range of object sizes and 範囲 values.

Run via main.py:
    uv run main.py inspect/blur/verify_canvas_growth.py
"""

from tools.cints import c_div
from tools.disasm import dump_range
from tools.pe_image import PEImage

EXPANSION = (0x1000E3CF, 0x116)

ANNOTATIONS = {
    0x1000E3CF: "eax = the stashed check[0] = サイズ固定",
    0x1000E3D5: "サイズ固定 on -> jump past expansion AND past all clamping",
    0x1000E3DB: "--- is any radius too large for the sliding window? ---",
    0x1000E3E7: "2*rx_hi >= w  -> expand",
    0x1000E3F4: "2*ry_hi >= h  -> expand",
    0x1000E405: "2*rx_lo >= w  -> expand",
    0x1000E412: "2*ry_lo <  h  -> no expansion needed, jump to 0x1000e535",
    0x1000E418: "ecx = ry_lo + ry_hi = ry",
    0x1000E427: "ecx = rx_lo + rx_hi = rx",
    0x1000E434: "ecx = fp+0x64 = exedit's own helper table (0x100a41e0)",
    0x1000E441: "h + 2*ry",
    0x1000E44E: "w + 2*rx",
    0x1000E45C: "the LOCAL サイズ固定 flag := 1 (the checkbox itself is untouched)",
    0x1000E464: "table[0x48](buffer B, 0, 0, w+2rx, h+2ry, ..., flags=2)  <- clear",
    0x1000E473: "flags 0x13000003 for the blit below",
    0x1000E494: "dy = ry_lo + ry_hi = ry",
    0x1000E498: "dx = rx_lo + rx_hi = rx",
    0x1000E4A0: "table[0x44](B, rx, ry, A, 0, 0, w, h, ..., 0x13000003)  <- blit",
    0x1000E4B3: "*(fpip+0xAC) = B",
    0x1000E4BF: "*(fpip+0xB0) = A   (the two buffers swap roles)",
    0x1000E4CD: "*(fpip+0xB4) = w + 2*rx",
    0x1000E4DC: "*(fpip+0xB8) = h + 2*ry",
    0x1000E4E4: "--- frame path instead: clamp every radius to dim/2 ---",
}


def plan(w, h, rng, size_fixed, max_w=4096, max_h=4096):
    """func_proc 0x1000e364-0x1000e4e2 for the object path, in Python."""
    rx = ry = rng
    # max-canvas clamp (0x1000e367-0x1000e3a1) - applied whatever サイズ固定 is
    if w + 2 * rx > max_w:
        rx = c_div(max_w - w, 2)
    if h + 2 * ry > max_h:
        ry = c_div(max_h - h, 2)
    rx_hi, rx_lo = rx - c_div(rx, 2), c_div(rx, 2)
    ry_hi, ry_lo = ry - c_div(ry, 2), c_div(ry, 2)

    pre = False
    if not size_fixed:
        if (2 * rx_hi >= w or 2 * ry_hi >= h or 2 * rx_lo >= w or 2 * ry_lo >= h):
            pre = True
            w, h = w + 2 * rx, h + 2 * ry
            size_fixed = 1          # 0x1000e45c
    grew_w = 0 if size_fixed else 2 * rx_hi + 2 * rx_lo
    grew_h = 0 if size_fixed else 2 * ry_hi + 2 * ry_lo
    return {
        "radii": (rx, ry),
        "pre_expanded": pre,
        "workers": "size-fixed (renormalising)" if size_fixed else "growing (zero-padding)",
        "final": (w + grew_w, h + grew_h),
    }


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_range(PEImage(dll_path), *EXPANSION,
               label="func_proc: the サイズ固定 test and the canvas pre-expansion",
               resolve=False, annotations=ANNOTATIONS)

    print("\n--- resulting canvas size, object path (max canvas 4096x4096) ---")
    print("    w    h  範囲 固定 |    radii    | pre-expand | workers used"
          "                | final canvas")
    for w, h, rng, fixed in ((200, 100, 5, 0), (200, 100, 5, 1),
                             (200, 100, 40, 0), (200, 100, 60, 0),
                             (200, 100, 60, 1), (32, 32, 100, 0),
                             (4000, 100, 100, 0), (200, 100, 1000, 0)):
        p = plan(w, h, rng, fixed)
        print(f"  {w:4d} {h:4d} {rng:5d} {fixed:4d} | {str(p['radii']):11s} |"
              f" {str(p['pre_expanded']):10s} | {p['workers']:27s} | {p['final']}")

    print("""
Verdict:
  サイズ固定 off  the object grows to (w + 2*rx, h + 2*ry) and stays centred,
                  because the blur is allowed to spill outside the old canvas.
                  If a radius is already at least half the canvas, func_proc
                  does the whole expansion up front with a clear+blit and then
                  runs the non-growing workers on the enlarged buffer - the
                  final size is the same either way.
  サイズ固定 on   the canvas never changes and no clamping is applied to the
                  radii either; the workers renormalise at the border instead
                  (verify_box_average.py), so the object's own edges keep
                  their opacity rather than fading out.

  The max-canvas clamp is the only limit on 範囲 on the object path: rx is cut
  to (max_w - w)/2 so that w + 2*rx still fits. On the frame path there is no
  canvas to grow, so each of the four radii is clamped to dim/2 instead.
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
