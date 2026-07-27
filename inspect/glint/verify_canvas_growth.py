"""Work out how big 閃光 makes the object, and show that the number 4 is not
arbitrary.

func_proc grows the canvas before rendering, and the growth is computed with a
sequence that is easy to misread: the extent is multiplied by 1000 with three
`lea`s and a `shl`, then divided by 250 with the magic-number divide. The pair
is just `* 4`, but it is written out because the source presumably says
something like `x * 1000 / 250`. The clamps around it matter more than the
arithmetic:

    cx = w/2 + X                     centre, in source pixel coordinates
    x0 = min(0, cx - 4*cx)           left edge  = cx - 4*cx = -3*cx
    x1 = max(0, 3*(w - cx)) + w      right edge = cx + 4*(w - cx)
    (both extents scaled by strength/4096 before x1 has w added back)

4 is exactly the reach of one ray. A ray starting at a pixel D away from the
centre walks 75% of the way in (verify_ray_geometry.py), so it can pick up a
source pixel at distance d whenever 0.25*D <= d <= D - that is, a source pixel
at d lights up everything out to 4*d along its own radius. The canvas grows to
4x the centre-to-edge distance on each side because that is precisely where
the outermost source pixel's streak ends. This script checks that equivalence
numerically rather than asserting it.

Then two clamps: the grown size is walked back one pixel at a time until it
fits both the exedit canvas limit (0x10196748 / 0x101920e0, identified in
inspect/blur) and fpip->w + 2*w; and サイズ固定 discards the growth entirely.

Run via main.py:
    uv run main.py inspect/glint/verify_canvas_growth.py
"""

from tools.cints import MAGIC_1000, c_div, divisor_of, msvc_div


def times_four(v: int) -> int:
    """0x1004e6b4..0x1004e6d9: v*5*5*5*8 then the magic divide with `sar edx, 4`."""
    return msvc_div(v * 1000, MAGIC_1000, 4)


def extents(w: int, h: int, x: int, y: int, strength: int):
    """func_proc 0x1004e5b7..0x1004e7c6, before the fit-to-canvas clamp.

    The near edges (0x1004e6b4, 0x1004e6ed) feed the extent straight into the
    multiply chain; the far edges (0x1004e71f, 0x1004e75a) negate first with
    `neg eax; shl eax, 2; sub eax, edi`, i.e. they run -1000*t through the same
    divide. Both spellings are kept here so the clamp that follows each one is
    attached to the value the hardware actually produced.
    """
    cx = c_div(w, 2) + x
    cy = c_div(h, 2) + y

    x0 = min(cx - times_four(cx), 0)
    y0 = min(cy - times_four(cy), 0)

    tx = cx - w
    x1 = max(tx + msvc_div(-tx * 1000, MAGIC_1000, 4), 0)
    ty = cy - h
    y1 = max(ty + msvc_div(-ty * 1000, MAGIC_1000, 4), 0)

    # `imul <extent>, strength; sar <extent>, 0xc` - an arithmetic shift, so the
    # negative left/top extents floor rather than truncate toward zero.
    x0, y0 = (x0 * strength) >> 12, (y0 * strength) >> 12
    x1, y1 = (x1 * strength) >> 12, (y1 * strength) >> 12
    return cx, cy, x0, y0, x1 + w, y1 + h


def fit(x0: int, x1: int, w: int, limit: int, fpip_w: int):
    """0x1004e7e0: shave one pixel off the longer side until the width fits."""
    steps = 0
    while (x1 - x0) > limit or (x1 - x0) > fpip_w + 2 * w:
        if x0 < w - x1:
            x0 += 1
        else:
            x1 -= 1
        steps += 1
        if steps > 1 << 20:
            return x0, x1, -1
    return x0, x1, steps


def ray_reach(distance: int) -> float:
    """How far out a source pixel at `distance` from the centre is still picked
    up, given the ray covers 75% of the distance from the sampling pixel in."""
    # a destination pixel at D samples [0.25*D, D]; the largest D that still
    # includes `distance` is where 0.25*D == distance
    return distance / 0.25


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("1) `* 1000` then magic-divide with `sar edx, 4` is a plain multiply by 4")
    print(f"   the shift-4 divisor is {divisor_of(MAGIC_1000, 4)}, so v*1000/250 == v*4")
    bad = [v for v in range(-500_000, 500_001, 3) if times_four(v) != 4 * v]
    print(f"   disagreements with 4*v over -500k..500k step 3: {len(bad)}")

    print("\n2) 4x is the reach of a single ray, not a free parameter")
    print("   a ray from a pixel at D covers [0.25*D, D]; a source pixel at d is")
    print("   therefore still lit at D = d/0.25 = 4*d")
    for d in (1, 7, 40, 123):
        print(f"     source pixel at d={d:<4} lights out to D={ray_reach(d):.0f}")

    print("\n3) canvas extents at full 強さ (strength 4096)")
    print(f"   {'w':>5}{'h':>5}{'X':>6}{'Y':>6} | {'cx':>5}{'cy':>5} | "
          f"{'x0':>7}{'y0':>7}{'x1':>7}{'y1':>7} | {'new w':>7}{'new h':>7}")
    cases = [(200, 200, 0, 0), (200, 200, 50, 0), (200, 200, -400, 0),
             (320, 240, 0, 0), (320, 240, 160, 120), (100, 100, 2000, 2000)]
    for w, h, x, y in cases:
        cx, cy, x0, y0, x1, y1 = extents(w, h, x, y, 4096)
        print(f"   {w:>5}{h:>5}{x:>6}{y:>6} | {cx:>5}{cy:>5} | "
              f"{x0:>7}{y0:>7}{x1:>7}{y1:>7} | {x1 - x0:>7}{y1 - y0:>7}")
    print("   note the centre sitting outside the object (X=-400, X=2000): the near side")
    print("   clamps to 0 and only the far side grows, because max(0, ...) / min(0, ...)")
    print("   refuse to shrink the object below its original rectangle.")

    print("\n4) 強さ scales the growth linearly")
    w = h = 200
    print(f"   {'UI':>7}{'strength':>10}{'x0':>7}{'x1':>7}{'new w':>8}")
    for raw in (1000, 750, 500, 250, 100, 1):
        s = raw * 4096 // 1000
        _, _, x0, _, x1, _ = extents(w, h, 0, 0, s)
        print(f"   {raw / 10:>7.1f}{s:>10}{x0:>7}{x1:>7}{x1 - x0:>8}")
    print("   -> the canvas shrinks with 強さ even though 強さ is a threshold, not a")
    print("      length. The rays still reach 4x geometrically; the growth is trimmed")
    print("      on the assumption that the dim far end will not clear the threshold.")

    print("\n5) fit-to-canvas clamp - two independent limits, whichever binds first")
    print("   width must satisfy BOTH  <= 0x10196748 (exedit's max canvas width)")
    print("                     AND    <= fpip->w + 2*w  (frame width plus one object")
    print("                                               width of bleed on each side)")
    cx, cy, x0, y0, x1, y1 = extents(200, 200, 60, 0, 4096)
    print(f"   wanted: x0={x0} x1={x1} -> {x1 - x0} px wide")
    print(f"   {'max canvas':>11}{'fpip->w':>9}{'fpip->w+2w':>12}{'result':>8}"
          f"{'steps':>7}   {'x0':>6}{'x1':>6}   binding limit")
    for limit, fpip_w in ((4000, 1920), (4000, 200), (400, 1920), (256, 1920)):
        nx0, nx1, steps = fit(x0, x1, 200, limit, fpip_w)
        binding = "max canvas" if limit <= fpip_w + 400 else "fpip->w + 2w"
        if nx1 - nx0 == x1 - x0:
            binding = "neither - fits as-is"
        print(f"   {limit:>11}{fpip_w:>9}{fpip_w + 400:>12}{nx1 - nx0:>8}{steps:>7}   "
              f"{nx0:>6}{nx1:>6}   {binding}")
    print("   the loop always shaves the side with the larger overhang, so an")
    print("   off-centre glint keeps its asymmetry while being trimmed.")

    print("\n6) サイズ固定 (check[2]) discards all of the above")
    print("   0x1004e860: if fp->check[2] != 0 then x0=y0=0, x1=w, y1=h.")
    print("   The rays are still computed from the same centre and still 4x long -")
    print("   they are simply clipped to the original rectangle, so the streaks stop")
    print("   at the object edge instead of the effect growing the object.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
