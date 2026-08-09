"""An integer-faithful re-implementation of エッジ抽出, and what it shows.

Everything the other scripts in this directory established, written once as
running code:

    param conversion   verify_param_scaling.py
    the three modes    verify_dispatch.py
    premultiply        verify_alpha_weight.py
    Prewitt kernels    verify_prewitt_taps.py
    magnitude + tail   verify_output_encoding.py
    the border ring    verify_border.py

Integer semantics matter here and are spelled out with tools.cints: `>> 12` is
`sar` (floor) and `sqrt` is truncated by `_ftol`. Using Python's `int(x/4096)`
for the premultiply instead would agree on greys and drift by one on chroma
([`integer_semantics.md`](../common/integer_semantics.md)).

The demonstrations are chosen to be things a user would notice:

  1. a hard-edged opaque square - the outline lands *inside* the shape, one
     pixel wide, and saturates at the default 強さ,
  2. the same square with no luminance contrast at all against its surroundings
     - the alpha step alone still produces the full outline, because the taps
     are premultiplied,
  3. a soft (anti-aliased) edge - where 強さ and しきい値 actually do something,
  4. 透明度エッジ vs 輝度エッジ on a shape whose interior has detail.

Run via main.py:
    uv run main.py inspect/edge_extraction/simulate_edge_extraction_reference.py
"""

import math

from tools.cints import c_div, sar

MODE_LUMA = "輝度エッジを抽出"
MODE_ALPHA = "透明度エッジを抽出"
MODE_COLOUR = "両方オフ (色エッジ)"

PREWITT_X = ((-1, 0, 1), (-1, 0, 1), (-1, 0, 1))
PREWITT_Y = ((-1, -1, -1), (0, 0, 0), (1, 1, 1))


def params(strength_raw: int, threshold_raw: int) -> tuple[int, int]:
    """fp->track[] -> the two globals func_proc writes (0x10022d66..0x10022da8)."""
    return c_div(strength_raw * 4096, 1000), c_div(threshold_raw * 4096, 10000)


def _tap(px, channel):
    """One neighbour's contribution: premultiplied by its own alpha.

    `a >= 4096 -> c`, `0 < a < 4096 -> sar(c*a, 12)`, `a <= 0 -> nothing`
    (0x10023636..0x10023654 and the seven taps after it).
    """
    y, cb, cr, a = px
    if channel == "a":
        return a
    c = {"y": y, "cb": cb, "cr": cr}[channel]
    if a >= 4096:
        return c
    if a <= 0:
        return 0
    return sar(c * a, 12)


def _magnitude(img, w, x, y, channel) -> int:
    gx = gy = 0
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            if dy == 0 and dx == 0:
                continue
            v = _tap(img[(y + dy) * w + (x + dx)], channel)
            gx += PREWITT_X[dy + 1][dx + 1] * v
            gy += PREWITT_Y[dy + 1][dx + 1] * v
    return math.isqrt(gx * gx + gy * gy)      # fsqrt + _ftol, argument >= 0


def edge_extraction(img, w, h, mode, colour, strength_raw=1000, threshold_raw=0):
    """`img` is a list of (y, cb, cr, a) tuples, row-major, w*h long."""
    strength, T = params(strength_raw, threshold_raw)
    cy, ccb, ccr = colour
    out = [(cy, ccb, ccr, 0)] * (w * h)       # the whole border ring, up front
    channels = {MODE_LUMA: ("y",), MODE_ALPHA: ("a",),
                MODE_COLOUR: ("y", "cb", "cr")}[mode]
    for y in range(1, h - 1):
        for x in range(1, w - 1):
            mag = sum(_magnitude(img, w, x, y, c) for c in channels)
            e = sar((mag - T) * strength, 12)
            e = 0 if e < 0 else 4096 if e > 4096 else e
            out[y * w + x] = (cy, ccb, ccr, sar(img[y * w + x][3] * e, 12))
    return out


# ------------------------------------------------------------------ demos

WHITE = (4095, 0, 0)


def square(w, h, lo, hi, inside, outside):
    return [inside if lo <= x < hi and lo <= y < hi else outside
            for y in range(h) for x in range(w)]


def alpha_map(out, w, h) -> str:
    ramp = " .:-=+*#%@"
    rows = []
    for y in range(h):
        rows.append("".join(ramp[min(len(ramp) - 1, out[y * w + x][3] * len(ramp) // 4097)]
                            for x in range(w)))
    return "\n".join("   " + r for r in rows)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- 1. parameter conversion ---")
    print(f"  {'強さ raw':>9}{'しきい値 raw':>13}{'strength Q12':>14}{'T Q12':>8}")
    for s, t in ((1000, 0), (250, 0), (1000, 2500), (1000, -2500), (10000, 0)):
        st, T = params(s, t)
        print(f"  {s:>9}{t:>13}{st:>14}{T:>8}")

    w = h = 11
    opaque, clear = (4096, 0, 0, 4096), (0, 0, 0, 0)

    print("\n--- 2. a hard opaque square on nothing (輝度エッジ, defaults) ---")
    img = square(w, h, 3, 8, opaque, clear)
    out = edge_extraction(img, w, h, MODE_LUMA, WHITE)
    print(alpha_map(out, w, h))
    print("  The outline sits on the *last opaque* pixels, not outside them: the tail")
    print("  multiplies by the centre pixel's own alpha, which is 0 outside the square.")
    print("  Every lit pixel is at 4096 - one 4096-wide step across three taps gives a")
    print("  magnitude of at least 12288, and 強さ = 100.0 clamps that to 4096.")

    print("\n--- 3. what each mode reacts to ---")
    # an opaque square with a darker patch inside it, on a background of the
    # same luminance but zero alpha
    bw = bh = 15
    img = square(bw, bh, 2, 13, opaque, (4096, 0, 0, 0))
    for y in range(6, 9):
        for x in range(6, 9):
            img[y * bw + x] = (0, 0, 0, 4096)
    for mode in (MODE_LUMA, MODE_ALPHA):
        out = edge_extraction(img, bw, bh, mode, WHITE)
        print(f"  {mode}:")
        print(alpha_map(out, bw, bh))
    print("  The silhouette shows up in *both*, even though y never changes across it:")
    print("  the taps are premultiplied, so y*a falls to 0 outside the shape")
    print("  (verify_alpha_weight.py). 輝度エッジ is a usable default because it")
    print("  doubles as a silhouette tracer; 透明度エッジ is the one that ignores")
    print("  everything inside the shape.")

    print("\n--- 4. a soft edge is where 強さ and しきい値 start mattering ---")
    ramp = [(min(4096, x * 200), 0, 0, 4096) for _ in range(h) for x in range(w)]
    print("  a luminance ramp of 200 per column, fully opaque: Gx = 1200 everywhere")
    print(f"  {'強さ':>8}{'しきい値':>10}   alpha across one row")
    for s_raw, t_raw in ((1000, 0), (250, 0), (100, 0), (1000, 2500), (1000, -1000),
                         (4000, 0)):
        out = edge_extraction(ramp, w, h, MODE_LUMA, WHITE, s_raw, t_raw)
        row = [out[5 * w + x][3] for x in range(1, w - 1)]
        print(f"  {s_raw / 10:>8.1f}{t_raw / 100:>10.2f}   {row}")
    print("  しきい値 is a subtraction, not a gate: it shifts the whole response down")
    print("  (or up, when negative) before 強さ scales it and the clamp bites. A")
    print("  positive しきい値 with a large 強さ is the only way to get a *selective*")
    print("  hard outline; 強さ alone just fades everything together.")

    print("\n--- 5. 色エッジ, and when it is not the same as 輝度エッジ ---")
    img = square(w, h, 3, 8, opaque, clear)
    same = (edge_extraction(img, w, h, MODE_LUMA, WHITE)
            == edge_extraction(img, w, h, MODE_COLOUR, WHITE))
    print(f"  grey image: identical output = {same}  (cb = cr = 0, so two of the three")
    print("  magnitudes 色エッジ sums are zero)")
    # constant luminance, opposite chroma: invisible to 輝度エッジ
    hue = [(2048, 300 if x < w // 2 else -300, 0, 4096)
           for _ in range(h) for x in range(w)]
    for mode in (MODE_LUMA, MODE_COLOUR):
        out = edge_extraction(hue, w, h, mode, WHITE, strength_raw=1000)
        print(f"  hue step at constant luminance, {mode:<22} "
              f"row 5 = {[out[5 * w + x][3] for x in range(1, w - 1)]}")
    print("  That is the whole reason the third mode exists, and the reason it costs")
    print("  three square roots per pixel.")

    print("\n--- 6. the border ring is unconditional ---")
    img = [opaque] * (w * h)                    # a completely flat opaque field
    out = edge_extraction(img, w, h, MODE_LUMA, WHITE)
    edge_pixels = [out[y * w + x] for y in range(h) for x in range(w)
                   if y in (0, h - 1) or x in (0, w - 1)]
    print(f"  flat field, {len(edge_pixels)} border pixels, all alpha 0: "
          f"{all(p[3] == 0 for p in edge_pixels)}")
    print(f"  interior alpha: {out[5 * w + 5][3]} (no gradient anywhere)")
    print("  So an object that fills its bounding box loses its outermost pixel and")
    print("  gets no outline along that side at all; give it a margin first.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
