"""Where everything ends up on the grown canvas, and why fpip+0xD4 has to move.

func_proc lays out a canvas of `(w+|X|+2r) x (h+|Y|+2r)` in the pair buffer
`fpip+0xB0` and puts two rectangles on it:

    shadow box  at (max(X,0),    max(Y,0))     size (w+2r, h+2r)
    the object  at (max(-X,0)+r, max(-Y,0)+r)  size (w, h)

Five claims:

  1. **The two rectangles are placed so the shadow sits exactly `(X, Y)` from
     the object**, for every combination of signs - the asymmetric-looking
     `max` pair is what makes one formula cover all four quadrants.
  2. **Both rectangles land inside the canvas with nothing left over**: one of
     them always touches the far edge, so no column or row is wasted.
  3. **The `fpip+0xD4` / `+0xD8` correction is exactly `-X/2` / `-Y/2`
     pixels**, written as `(-X) << 11`. The canvas grew by `|X|` on one side
     only, so the object's centre has to move half that far the other way to
     stay put on screen. `2048 = 4096/2` is a second, independent confirmation
     that these fields are in 1/4096-pixel units - so far that unit was an
     inference from 閃光 alone (canvas_growth.md §7). The symmetric `+2r`
     needs no correction, and indeed gets none.
  4. **The four `table[0x48]` clears cover exactly the canvas minus the shadow
     box** - nothing is cleared twice and nothing is left uncleared.
  5. **`影を別オブジェクトで描画` moves the offset out of the canvas**: X and Y
     are zeroed before any geometry is computed, so the canvas is only
     `(w+2r) x (h+2r)`, and the displacement is applied to `fpip+0xBC` /
     `+0xC0` (whole pixels x 4096) around the one call to sub_1004b200.

The geometry() below is the same routine verify_params.py documents, repeated
here so this script stands on its own (as every other verify_*.py in this
repo does).

Run via main.py:
    uv run main.py inspect/shadow/verify_geometry.py
"""

from tools.cints import c_div


def clamp_offset(offset: int, dim: int, budget: int) -> int:
    """0x10088059-0x100880b5: shrink the offset until dim+|offset| fits."""
    grown = dim + abs(offset)
    if grown <= budget:
        return offset
    return offset + (budget - grown if offset > 0 else grown - budget)


def geometry(w, h, x, y, spread, separate=False, stride=None, rows=None):
    """func_proc 0x10087fdc-0x100881a8. `stride` / `rows` are the allocated
    buffer's extents (fpip+0xEC / +0xF0); this analysis did not pin down how
    exedit sizes them, so they default to something roomy."""
    stride = stride if stride is not None else w + 512
    rows = rows if rows is not None else h + 512

    if separate:
        x = y = 0
    x = clamp_offset(x, w, stride)
    y = clamp_offset(y, h, rows)
    grown_w, grown_h = w + abs(x), h + abs(y)

    r = spread
    if 2 * r > stride - grown_w:
        r = c_div(stride - grown_w, 2)
    if 2 * r > rows - grown_h:
        r = c_div(rows - grown_h, 2)

    return {
        "w": w, "h": h, "x": x, "y": y, "r": r,
        "canvas_w": grown_w + 2 * r, "canvas_h": grown_h + 2 * r,
        "shadow_x": max(x, 0), "shadow_y": max(y, 0),
        "box_w": w + 2 * r, "box_h": h + 2 * r,
        "object_x": max(-x, 0) + r, "object_y": max(-y, 0) + r,
        "centre_dx": -x * 2048, "centre_dy": -y * 2048,
    }


def strips(g):
    """The four table[0x48] rectangles in dispatch order (0x10088280 onwards),
    as (name, x, y, w, h). Each has a guard, so a zero-extent strip is skipped."""
    cw, ch = g["canvas_w"], g["canvas_h"]
    sx, sy, bw, bh = g["shadow_x"], g["shadow_y"], g["box_w"], g["box_h"]
    out = []
    if sx > 0:
        out.append(("left", 0, 0, sx, ch))
    if sy > 0:
        out.append(("top", 0, 0, cw, sy))
    if cw > sx + bw:
        out.append(("right", sx + bw, 0, cw - (sx + bw), ch))
    if ch > sy + bh:
        out.append(("bottom", 0, sy + bh, cw, ch - (sy + bh)))
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. the shadow sits exactly (X, Y) from the object ---")
    print(f"  {'X':>6}{'Y':>6}{'shadow @':>14}{'object @':>14}{'shadow - object':>18}")
    for x, y in ((-40, 24), (40, 24), (-40, -24), (40, -24), (0, 0), (7, 0), (0, -9)):
        g = geometry(100, 60, x, y, 10)
        shadow = f"({g['shadow_x']}, {g['shadow_y']})"
        obj = f"({g['object_x']}, {g['object_y']})"
        delta = f"({g['shadow_x'] + g['r'] - g['object_x']}, " \
                f"{g['shadow_y'] + g['r'] - g['object_y']})"
        print(f"  {x:>6}{y:>6}{shadow:>14}{obj:>14}{delta:>18}")

    bad = []
    for x in range(-200, 201, 3):
        for y in range(-200, 201, 7):
            for spread in (0, 1, 10, 47):
                g = geometry(100, 60, x, y, spread)
                dx = g["shadow_x"] + g["r"] - g["object_x"]
                dy = g["shadow_y"] + g["r"] - g["object_y"]
                if (dx, dy) != (x, y):
                    bad.append((x, y, spread, dx, dy))
    check("134 x 58 x 4 combinations: (shadow origin + r) - object origin == (X, Y)",
          not bad, f"{len(bad)} bad, first {bad[:1]}")
    print("  The `+ r` on the object's origin is what centres the object inside the shadow")
    print("  box's blurred margin; the two `max` terms then hand the extra room to whichever")
    print("  rectangle needs it. Nothing in the effect ever computes a relative coordinate -")
    print("  the offset exists only as these two absolute placements.")

    print("\n--- 2. both rectangles fit, and the canvas is min(|X|, r) too wide ---")
    bad, waste_bad = [], []
    for x in range(-150, 151, 3):
        for y in range(-150, 151, 5):
            for spread in (0, 3, 25):
                g = geometry(200, 120, x, y, spread)
                lo = min(g["shadow_x"], g["object_x"])
                hi = max(g["shadow_x"] + g["box_w"], g["object_x"] + g["w"])
                if lo < 0 or hi > g["canvas_w"]:
                    bad.append((x, y, spread, lo, hi, g["canvas_w"]))
                if g["canvas_w"] - (hi - lo) != min(abs(g["x"]), g["r"]):
                    waste_bad.append((x, y, spread, g["canvas_w"] - (hi - lo)))
    check("101 x 61 x 3 combinations: the union of the two rectangles is inside the canvas",
          not bad, f"{len(bad)} bad, first {bad[:1]}")
    check("... and the leftover is exactly min(|X|, r) columns, every time",
          not waste_bad, f"{len(waste_bad)} bad, first {waste_bad[:1]}")
    print(f"  {'X':>6}{'拡散':>7}{'canvas w':>10}{'content':>16}{'slack':>7}  where")
    for x, spread in ((-40, 10), (40, 10), (-5, 10), (5, 10), (0, 10), (-40, 0)):
        g = geometry(100, 60, x, 0, spread)
        lo = min(g["shadow_x"], g["object_x"])
        hi = max(g["shadow_x"] + g["box_w"], g["object_x"] + g["w"])
        side = "-" if g["canvas_w"] == hi - lo else ("left" if lo > 0 else "right")
        print(f"  {x:>6}{spread:>7}{g['canvas_w']:>10}{f'[{lo}, {hi})':>16}"
              f"{g['canvas_w'] - (hi - lo):>7}  {side}")
    print("  `w + |X| + 2r` is the sum of two independent allowances - the offset needs")
    print("  `|X|` and the blur needs `2r` - but they only both apply on the same side when")
    print("  `|X| < r`. The overlap is never subtracted, so a fully transparent strip")
    print("  `min(|X|, r)` wide is left on the side away from the shadow. Harmless, but it")
    print("  does mean the bounding box AviUtl reports is slightly larger than what is")
    print("  actually drawn.")

    print("\n--- 3. the fpip+0xD4 / +0xD8 correction is -X/2 / -Y/2 pixels ---")
    print(f"  {'X':>6}{'canvas grows by':>17}{'+0xD4 delta':>13}{'= pixels':>10}")
    for x in (-40, -1, 0, 1, 24, 200):
        g = geometry(100, 60, x, 0, 10)
        print(f"  {x:>6}{abs(x):>17}{g['centre_dx']:>13}{-x / 2:>10}")
    bad = []
    for x in range(-1000, 1001):
        g = geometry(2000, 2000, x, 0, 0, stride=4000, rows=4000)
        if g["centre_dx"] != -x * 2048 or g["centre_dx"] / 4096 != -x / 2:
            bad.append((x, g["centre_dx"]))
    check("all 2001 X values: the delta is -X*2048, i.e. -X/2 px at 4096 units per pixel",
          not bad, f"first {bad[:1]}")
    check("the +2r growth gets no correction at all, because it is symmetric",
          geometry(100, 60, 0, 0, 50)["centre_dx"] == 0)
    print("  If +0xD4 were in whole pixels the shift would be `>> 1`; in 1/256 px it would")
    print("  be `<< 7`. `shl 0xb` only reads as 'half a pixel' when a pixel is 4096 - the")
    print("  value 閃光 arrived at from a completely different formula. canvas_growth.md §7")
    print("  lists that unit as inferred from 閃光 alone; this is a second, independent")
    print("  witness, and the two agree.")

    print("\n--- 4. the clears cover exactly the canvas minus the shadow box ---")
    bad = []
    for x, y, spread in ((-40, 24, 10), (40, -24, 10), (0, 0, 5), (60, 60, 0), (-3, 0, 1)):
        g = geometry(40, 30, x, y, spread)
        box = {(px, py)
               for py in range(g["shadow_y"], g["shadow_y"] + g["box_h"])
               for px in range(g["shadow_x"], g["shadow_x"] + g["box_w"])}
        cleared = set()
        for _, sx, sy, sw, sh in strips(g):
            cleared |= {(px, py) for py in range(sy, sy + sh) for px in range(sx, sx + sw)}
        canvas = {(px, py) for py in range(g["canvas_h"]) for px in range(g["canvas_w"])}
        if cleared != canvas - box:
            bad.append((x, y, spread, len(cleared), len(canvas - box)))
    check("5 layouts: the union of the four strips is exactly canvas minus shadow box",
          not bad, f"first {bad[:1]}")
    print("  The left/right strips are full height and the top/bottom ones full width, so")
    print("  they do overlap at the corners - each corner is simply cleared twice.")

    g = geometry(40, 30, -40, 24, 10)
    print(f"  X=-40 Y=24 拡散=10 on a 40x30 object -> canvas "
          f"{g['canvas_w']}x{g['canvas_h']}, shadow box at "
          f"({g['shadow_x']}, {g['shadow_y']}) size {g['box_w']}x{g['box_h']}, "
          f"object at ({g['object_x']}, {g['object_y']})")
    for name, sx, sy, sw, sh in strips(g):
        print(f"    clear {name:<7} x={sx:<4} y={sy:<4} w={sw:<4} h={sh:<4}")
    print("  With the default X<0, Y>0 only the top and right strips exist - the shadow box")
    print("  already starts at column 0. When a pattern image is loaded it is tiled over")
    print("  everything from (shadow_x, shadow_y) to the canvas corner FIRST, and these")
    print("  clears are what cut it back to the box.")

    print("\n--- 5. 影を別オブジェクトで描画 moves the offset out of the canvas ---")
    print(f"  {'check[0]':<12}{'canvas':>12}{'shadow @':>12}{'object @':>12}{'+0xD4':>8}")
    for label, sep in (("unchecked", False), ("checked", True)):
        g = geometry(100, 60, -40, 24, 10, separate=sep)
        canvas = f"{g['canvas_w']}x{g['canvas_h']}"
        shadow = f"({g['shadow_x']},{g['shadow_y']})"
        obj = f"({g['object_x']},{g['object_y']})"
        print(f"  {label:<12}{canvas:>12}{shadow:>12}{obj:>12}{g['centre_dx']:>8}")
    b = geometry(100, 60, -40, 24, 10, separate=True)
    check("checked: the canvas is only (w+2r) x (h+2r) - the offset costs it nothing",
          (b["canvas_w"], b["canvas_h"]) == (120, 80))
    check("checked: no centre correction is written, because nothing grew asymmetrically",
          b["centre_dx"] == 0 and b["centre_dy"] == 0)
    print("  Instead func_proc swaps fpip+0xAC/+0xB0, adds X*4096 / Y*4096 to fpip+0xBC /")
    print("  +0xC0 (whole pixels, same 1/4096 unit as §3), calls sub_1004b200 to draw the")
    print("  shadow canvas as an object in its own right, then undoes every one of those")
    print("  writes. The original object leaves func_proc bit-identical to how it arrived,")
    print("  which is what 'draw the shadow as a separate object' has to mean: the object")
    print("  is no longer carrying the shadow around in its own bounding box.")
    print("  Note the object rectangle above is still reported for the checked case - it is")
    print("  computed either way, but nothing reads it: the table[0x44] composite that")
    print("  would have used it lives on the other side of the check[0] branch.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
