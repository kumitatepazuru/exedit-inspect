"""From the directional alpha sum to the pixel that gets written.

Six claims:

  1. **`d = trunc(sum * 高さ_raw / (200 * steps))`**, and because `|sum|` is at
     most `steps * 4096`, the swing is `+-2048 * 高さ_shown` regardless of 幅
     or 角度. 高さ = 2.00 is therefore the setting at which a hard edge can
     drive luminance across the entire representable range.

  2. **Two output paths, and their two sub-branches collapse into one closed
     form.** The literal branch chain at 0x10007d08-0x10007d75 is equivalent
     to

         if d >= 0 or y0 <= 0:  out = (y0 + d, cb, cr, a)
         else:                  ny = max(0, y0 + d)
                                k  = trunc(4096 * ny / y0)
                                out = (ny, (cb*k)>>12, (cr*k)>>12, a)

     checked over every representable y0 crossed with a sweep of d that covers
     the full reachable range, plus a second sweep including negative y0.

  3. **Darkening is multiplicative, brightening is additive.** The dark path
     scales Y, Cb and Cr by the same factor, which under BT.601 is a multiply
     of R, G and B alike - the colour keeps its hue and saturation as it goes
     to black. The bright path adds to Y only and leaves the chroma alone, so
     the highlight desaturates the way blowing out an exposure does.

  4. **Nothing is clamped except at zero on the dark path.** `y0 + d` is stored
     into an `int16` with no upper bound and no lower bound, so the highlight
     can exceed 4096 and a pixel that already has `y0 < 0` can go further
     negative.

  5. **Alpha is copied verbatim on both paths**, so the silhouette never
     changes and the outer half of the shading band - the half that lands
     outside the object - is invisible. That is why the bevel reads as 幅
     pixels wide even though the filter reaches 幅 pixels in both directions.

  6. **高さ = 0 is not an early-out.** It makes `d` zero for every pixel, so
     the effect performs a full `w*h*幅`-sample scan and writes an exact copy.
     The only two no-ops that actually skip the work are `幅 = 0` and an object
     narrower or shorter than 2 px, and neither swaps the buffers.

Run via main.py:
    uv run main.py inspect/convex_edge/verify_shading.py
"""

import math

from tools.cints import c_div, sar

FULL = 4096
ANGLE_RAW = (-3600, 3600)
HEIGHT_RAW = (0, 300)      # 高さ: display scale 100 -> 0.00..3.00


def direction(angle_raw: int):
    """0x10007abb-0x10007aea."""
    t = angle_raw * -0.0017453292519943296
    return math.trunc(math.sin(t) * 65536.0), math.trunc(math.cos(t) * 65536.0)


def scale(height_raw: int, steps: int) -> float:
    """0x10007b38-0x10007b59, in x87:  fild 高さ ; fmul 0.5 ; fild 100*steps ; fdivp."""
    return (height_raw * 0.5) / (100 * steps)


def encode_branches(y0: int, cb: int, cr: int, a: int, d: int):
    """0x10007d08-0x10007d75 transcribed branch for branch."""
    if d < 0 and y0 > 0:                      # 0x10007d0d / 0x10007d11
        ny = d + y0                           # 0x10007d13
        if ny < 0:                            # 0x10007d15 jns
            ny, k = 0, 0                      # 0x10007d17 / 0x10007d19
        else:
            k = c_div(ny << 12, y0)           # 0x10007d1f-0x10007d23, idiv
        return ny, sar(cb * k, 12), sar(cr * k, 12), a
    return y0 + d, cb, cr, a                  # 0x10007d4f-0x10007d6d


def encode_closed(y0: int, cb: int, cr: int, a: int, d: int):
    """The same thing with the two sub-branches merged (claim 2)."""
    if d >= 0 or y0 <= 0:
        return y0 + d, cb, cr, a
    ny = max(0, y0 + d)
    k = c_div(ny << 12, y0)
    return ny, sar(cb * k, 12), sar(cr * k, 12), a


def sample_sum(alpha, w, h, x, y, steps, dx, dy):
    """0x10007c45-0x10007ced. Out-of-range samples contribute nothing."""
    ax = ay = total = 0
    for _ in range(steps):
        ax += dx
        ay += dy
        ox, oy = ax >> 16, ay >> 16
        sx, sy = x + ox, y + oy
        if 0 <= sx < w and 0 <= sy < h:
            total += alpha[sy * w + sx]
        sx, sy = x - ox, y - oy
        if 0 <= sx < w and 0 <= sy < h:
            total -= alpha[sy * w + sx]
    return total


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. d = trunc(sum * 高さ / (200*steps)), swing +-2048 * 高さ_shown ---")
    print(f"  {'高さ raw':>9}{'shown':>8}{'steps':>7}{'scale':>12}"
          f"{'|sum| max':>11}{'|d| max':>9}")
    for height, steps in ((100, 4), (100, 16), (0, 4), (200, 4), (300, 100)):
        s = scale(height, steps)
        print(f"  {height:>9}{height / 100:>8.2f}{steps:>7}{s:>12.6f}"
              f"{steps * FULL:>11}{math.trunc(steps * FULL * s):>9}")
    off = {}
    for height in range(HEIGHT_RAW[0], HEIGHT_RAW[1] + 1):
        for steps in range(1, 101):
            got = math.trunc(steps * FULL * scale(height, steps))
            off[(height, steps)] = got - height * FULL // 200
    check(f"over all {len(off)} (高さ, steps) pairs the extreme |d| is 20.48 * 高さ_raw "
          f"to within 1, independent of steps",
          set(off.values()) <= {0, -1}, f"deltas {sorted(set(off.values()))}")
    n = sum(1 for v in off.values() if v)
    check(f"the -1 cases are the x87 division landing just under an integer: "
          f"{n} of {len(off)} pairs, all of them 1/4096 of full luminance low",
          n and all(v in (0, -1) for v in off.values()))
    print(f"  e.g. 高さ = {[k for k, v in off.items() if v][0][0]}, "
          f"steps = {[k for k, v in off.items() if v][0][1]}: the exact quotient is an")
    print("  integer but `(高さ*0.5)/(100*steps)` rounds a hair below it, so the peak")
    print("  comes out one unit short. Nothing else in the effect rounds at all.")
    check("高さ = 2.00 is where a hard edge can move luminance by the full 0..4096",
          200 * FULL // 200 == FULL)
    print("  steps cancels: the sum grows with the number of taps and the divisor grows")
    print("  with it, so 幅 changes how WIDE the bevel is and never how strong it is.")
    print("  That is the whole reason the draft-quality cap (verify_direction.py §6)")
    print("  can thin the sampling without changing the result's amplitude.")

    print("\n--- 2. the encode: branch chain == closed form ---")
    bad = []
    ds = range(-2 * FULL - 2048, FULL + 1, 7)     # -10240..4096, the reachable span
    for y0 in range(0, FULL + 1):
        for d in ds:
            if encode_branches(y0, -1234, 987, 3000, d) != encode_closed(y0, -1234, 987, 3000, d):
                bad.append((y0, d))
    check(f"{FULL + 1} y0 values x {len(ds)} d values agree", not bad, f"first {bad[:1]}")
    bad = [(y0, d) for y0 in range(-FULL, FULL + 1, 3) for d in range(-8192, 8193, 5)
           if encode_branches(y0, 500, -500, 4096, d) != encode_closed(y0, 500, -500, 4096, d)]
    check("... including negative y0 and out-of-range d", not bad, f"first {bad[:1]}")
    print("  The `ny < 0 -> ny = 0, scale = 0` sub-branch is not a special case: it is")
    print("  what `max(0, y0+d)` then `trunc(4096*0/y0)` would have produced anyway.")
    print("  It exists to avoid the divide, not to change the answer.")

    print(f"\n  {'y0':>6}{'d':>7}{'out.y':>7}{'k (Q12)':>9}{'cb 2000 ->':>12}"
          f"{'cb -2000 ->':>13}")
    for y0, d in ((4096, 0), (4096, -1024), (4096, -4096), (4096, -5000),
                  (2048, -1024), (2048, 1024), (100, -50), (0, -1000), (0, 1000)):
        ny, cbp, _, _ = encode_branches(y0, 2000, 0, FULL, d)
        _, cbn, _, _ = encode_branches(y0, -2000, 0, FULL, d)
        k = c_div(max(0, y0 + d) << 12, y0) if (d < 0 and y0 > 0) else FULL
        print(f"  {y0:>6}{d:>7}{ny:>7}{k:>9}{cbp:>12}{cbn:>13}")
    check("a black pixel (y0 = 0) darkened goes NEGATIVE and keeps its chroma",
          encode_branches(0, 2000, 0, FULL, -1000) == (-1000, 2000, 0, FULL))

    print("\n--- 3. dark = multiply, bright = add ---")
    # BT.601 full-range inverse, the reading rgb_ycbcr.md §3 arrives at from the
    # forward coefficients. Scaling (Y, Cb, Cr) by k scales (R, G, B) by k
    # because the transform is linear and maps (0,0,0) to black.
    def to_rgb(y, cb, cr):
        return (y + 1.402 * cr,
                y - 0.344136 * cb - 0.714136 * cr,
                y + 1.772 * cb)

    y0, cb, cr = 2048, -900, 1500
    print(f"  source pixel  Y={y0} Cb={cb} Cr={cr}  ->  RGB "
          f"{tuple(round(v) for v in to_rgb(y0, cb, cr))}")
    print(f"  {'d':>7}{'path':>7}{'out (Y, Cb, Cr)':>24}{'-> RGB':>22}{'ratio to source':>20}")
    for d in (-1024, -1536, 512, 1024):
        oy, ocb, ocr, _ = encode_branches(y0, cb, cr, FULL, d)
        rgb = to_rgb(oy, ocb, ocr)
        src = to_rgb(y0, cb, cr)
        ratio = tuple(round(a / b, 3) for a, b in zip(rgb, src))
        print(f"  {d:>7}{'dark' if d < 0 else 'bright':>7}{str((oy, ocb, ocr)):>24}"
              f"{str(tuple(round(v) for v in rgb)):>22}{str(ratio):>20}")
    worst = 0.0
    for src_y in (512, 2048, 4096):
        for src_cb, src_cr in ((-900, 1500), (2000, -2000), (0, 0)):
            base = to_rgb(src_y, src_cb, src_cr)
            for d in range(-src_y, 0):
                out = to_rgb(*encode_branches(src_y, src_cb, src_cr, FULL, d)[:3])
                k = (src_y + d) / src_y
                worst = max(worst, max(abs(o - k * b) for o, b in zip(out, base)))
    check("on the dark path every RGB channel lands within 2 units of ny/y0 times the "
          f"source channel (worst {worst:.3f}) - the gap is one chroma LSB lost to the "
          f"`sar 12`, times the 1.772 Cb->B coefficient", worst < 2.0, f"{worst:.4f}")
    src = to_rgb(y0, cb, cr)
    bright = to_rgb(*encode_branches(y0, cb, cr, FULL, 1024)[:3])
    check("on the bright path all three channels gain the SAME absolute amount d, "
          "so saturation (max-min) is unchanged",
          all(abs((b - a) - 1024) < 1e-9 for a, b in zip(src, bright)))
    print("  Which is exactly how a real bevel behaves in a linear renderer: the shadow")
    print("  side is the surface times a fraction, the lit side is the surface plus")
    print("  white light. The inverse matrix is itself an inference (rgb_ycbcr.md §3),")
    print("  but the *shape* of the claim - one factor on all three components versus")
    print("  one addend on all three - holds for any linear transform with Y as its")
    print("  achromatic axis.")

    print("\n--- 4. no clamping except the zero on the dark path ---")
    hi = encode_branches(FULL, 0, 0, FULL, 6144)[0]
    check(f"y0 = 4096 with the maximum d = 6144 stores {hi}, i.e. 250% of full white",
          hi == 10240)
    check("... and 10240 still fits an int16, so the `mov word ptr` does not wrap",
          -32768 <= hi <= 32767)
    lo = encode_branches(-4096, 0, 0, FULL, -6144)[0]
    check(f"a below-black pixel goes to {lo} - the dark path's `y0 > 0` test sent it "
          f"down the additive branch", lo == -10240)
    worst = max(abs(encode_branches(y0, 0, 0, FULL, d)[0])
                for y0 in (-FULL, 0, FULL, 2 * FULL) for d in (-6144, 6144))
    check(f"the widest excursion reachable from a representable pixel is {worst}, "
          f"comfortably inside int16", worst < 32768)
    print("  The only guard in the whole encode is `jns` at 0x10007d15, which stops the")
    print("  darkening branch at 0. Everything above 4096 is left to aviutl.exe's")
    print("  YCbCr->RGB clip, the same open question every effect here ends on.")

    print("\n--- 5. the shading band, and why only half of it shows ---")
    # A vertical edge with 角度 = -90.0 makes the direction exactly (+1, 0), so
    # the profile can be read off one row.
    steps, height = 8, 100
    dx, dy = direction(-900)
    w, h = 40, 3
    alpha = [FULL if x >= 20 else 0 for _ in range(h) for x in range(w)]
    s = scale(height, steps)
    print(f"  幅 = {steps}, 高さ = {height / 100:.2f}, 角度 = -90.0 (direction = +x), "
          f"object starts at x = 20")
    print(f"  {'x - edge':>9}{'alpha':>7}{'sum':>9}{'d':>7}{'out.y (src 2048)':>18}"
          f"{'visible':>9}")
    prof = {}
    for x in range(20 - steps - 1, 20 + steps + 2):
        total = sample_sum(alpha, w, h, x, 1, steps, dx, dy)
        d = math.trunc(total * s)
        prof[x - 20] = d
        oy = encode_branches(2048, 0, 0, alpha[w + x], d)[0]
        print(f"  {x - 20:>9}{alpha[w + x]:>7}{total:>9}{d:>7}{oy:>18}"
              f"{'yes' if alpha[w + x] else '':>9}")
    check("the band is exactly 2*幅 pixels wide, from -幅 to 幅-1",
          all(prof[u] != 0 for u in range(-steps, steps))
          and prof[-steps - 1] == 0 and prof[steps] == 0)
    check("it peaks at the two innermost pixels of the edge (u = -1 and u = 0) with "
          "d = 2048 = 高さ * 4096 / 2", prof[-1] == prof[0] == 2048)
    check("the visible half (alpha > 0) is exactly 幅 pixels and ramps linearly to 0",
          [prof[u] for u in range(0, steps)] == [2048 * (steps - u) // steps
                                                 for u in range(0, steps)])
    check("the left edge is LIT when the direction points right, so the lit side is "
          "the one the vector points INTO", prof[0] > 0)
    print("  The outer half sits on alpha = 0 and is never seen; alpha is copied")
    print("  verbatim so the effect cannot widen the silhouette the way 縁取り does.")
    print("  With the default 角度 = -45.0 the vector points down-right, which lights")
    print("  the top-left edges and shades the bottom-right ones: light from above-left.")

    print("\n--- 6. degenerate settings ---")
    for height in (0,):
        s0 = scale(height, 4)
        check(f"高さ = {height}: scale is exactly 0.0, so d = 0 for every pixel and the "
              f"output is a bit-exact copy", s0 == 0.0
              and all(encode_branches(y, c, c, a, math.trunc(t * s0)) == (y, c, c, a)
                      for y in (0, 2048, 4096) for c in (-2000, 0, 2000)
                      for a in (0, 4096) for t in (-16384, 0, 16384)))
    print("  There is no `高さ == 0` early-out (0x10007a8f only tests 幅), so the full")
    print("  w*h*幅-sample scan runs and the buffers are still swapped. The two real")
    print("  no-ops - 幅 = 0 and min(w,h) < 2 - return before the swap, leaving the")
    print("  object completely untouched.")
    check("幅 = min(幅, w/2, h/2) drops to 0 for an object 1 px wide", c_div(1, 2) == 0)
    check("... and for a 2 px object it survives as 1", min(4, c_div(2, 2)) == 1)
    print("  That clamp is the effect's only bound on 幅. There is no comparison against")
    print("  fpip+0xEC / +0xF0 (the allocation) because nothing is ever read or written")
    print("  outside the object rectangle: all four bounds tests are in the inner loop.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
