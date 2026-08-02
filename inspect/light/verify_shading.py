"""The gradient pass: tints the object's OWN pixels in place, using a
box-blurred proxy for "how deep into the solid shape this point is".

Two workers do the box blur (vertical then horizontal, standard separable
box average, kernel width `2r+1`, no growth - see disasm_params.py), and the
horizontal one also performs the tint:

    逆光 OFF (default), sub_1005c080 + sub_1005c250:
        avg  = box_average(alpha, r)                    # plain alpha, 0..4096
        m    = trunc((avg + 4096) * B_scaled / 4096)     # B_scaled = trunc(B*2/11)
    逆光 ON, sub_1005c520 + sub_1005c700:
        avg  = box_average(4096 - alpha, r)              # INVERTED alpha
        m    = trunc(avg * B / 4096)                      # B unscaled, no +4096 bias

    m == 0        -> no change (both channels below)
    m >= 4096     -> fpip.ac[y][x].{Y,Cb,Cr} += light.{Y,Cb,Cr}   (raw, unscaled)
    otherwise     -> fpip.ac[y][x].{Y,Cb,Cr} += light.{Y,Cb,Cr} * m / 4096   (sar, floor)

This is an ADD onto the existing pixel, not a composite - the alpha channel
(+6) is never read or written by this pass, only Y/Cb/Cr.

This script checks:

  1. The "+4096" bias only appears on the OFF path, and the box-average input
     is only inverted on the ON path - the two facts that make the two modes
     opposite in where they are brightest (interior-bright vs edge-bright),
     even though the pixel-store code afterwards is otherwise identical
     (verified by literally diffing the tail bytes of the two decompiled
     workers in decompile_light.py's output; here it is checked as behaviour).
  2. OFF's multiplier never reaches 0 while B_scaled>0 (it ranges
     [B_scaled, 2*B_scaled]) - matching disasm_params.py's note that the `je`
     zero-check is dead in practice.
  3. ON's multiplier is exactly proportional to (4096-avg), so it is highest
     at the object's own edge (avg alpha low there) and lowest deep inside a
     large solid area (avg alpha near 4096) - the reverse of OFF.
  4. 強さ overdrive (raw 强さ > 1000, i.e. > 100%) never makes either pass
     add MORE than the raw light colour once - crossing the m>=4096 branch
     just makes the plateau (full light colour) start sooner, it does not
     multiply the light colour further.
  5. A concrete 1-D "shape" (a box of solid alpha with soft edges) run through
     both modes, showing the interior-bright vs rim-bright shapes directly.
  6. The closed windowed-sum form used above really does match a literal
     replay of sub_1005c080's silent-preload/head/middle/tail phases - in
     particular that the tail only runs `r` evict-only iterations, not
     `kernelWidth-1` like the halo pass's tail (verify_halo.py), which is the
     entire reason this pass does not grow the canvas.

Run via main.py:
    uv run main.py inspect/light/verify_shading.py
"""

import random

from tools.cints import c_div

FULL = 4096  # PIXEL_YCA full opacity / Q12 "1.0"


def box_average(values: list, r: int) -> list:
    """Plain separable box average with the 'always divide by full kernel
    width' edge behaviour documented in box_blur.md §3 (the growing variant -
    this effect has no サイズ固定 at all, and the gradient pass does not even
    grow the canvas, it just fades near the object's own edge)."""
    n = len(values)
    k = 2 * r + 1
    out = []
    for i in range(n):
        lo, hi = max(0, i - r), min(n - 1, i + r)
        s = sum(values[lo:hi + 1])
        out.append(c_div(s, k))
    return out


def box_average_literal(values: list, r: int) -> list:
    """box_average(), but written as sub_1005c080's actual three phases
    (disasm_params.py / decompile_light.py), so the closed windowed-sum form
    above can be checked against something closer to the raw instructions:

      a silent r-sample PRE-LOAD (accumulate only, no emit - this is what a
      growing pass like the halo's does NOT have, see verify_halo.py),
      then a head of (r+1) accumulate+emit iterations,
      a middle of (n-k) accumulate+evict+emit iterations,
      and a tail of r evict-only+emit iterations (NOT k-1, unlike the halo
      pass's tail - this r-vs-(k-1) difference is the entire reason this pass
      does not grow the canvas while the halo pass does).
    """
    n = len(values)
    k = 2 * r + 1
    node = 0
    add_i = 0
    for _ in range(min(r, n)):              # silent pre-load, no emit
        node += values[add_i]
        add_i += 1
    out = []
    for _ in range(r + 1):                  # head: r+1 emits
        if add_i < n:
            node += values[add_i]
            add_i += 1
        out.append(c_div(node, k))
    evict_i = 0
    for _ in range(max(0, n - k)):           # middle: n-k emits
        node += values[add_i] - values[evict_i]
        add_i += 1
        evict_i += 1
        out.append(c_div(node, k))
    for _ in range(min(r, n)):               # tail: r emits, evict only
        node -= values[evict_i]
        evict_i += 1
        out.append(c_div(node, k))
    return out


def multiplier(avg: int, coef: int, reverse_light: bool) -> int:
    """m for one pixel, given the box-averaged (possibly inverted) alpha and
    the dispatch-specific coefficient. `reverse_light` selects the ON-path
    shape (no bias) vs the OFF-path shape (+4096 bias)."""
    if reverse_light:
        return c_div(avg * coef, FULL)
    return c_div((avg + FULL) * coef, FULL)


def tinted_channel(base: int, light: int, m: int) -> int:
    """out = base + light                  if m >= FULL
       out = base + (light * m) >> 12      otherwise (sar, so floor)
       out = base                          if m == 0"""
    if m <= 0:
        return base
    if m >= FULL:
        return base + light
    return base + ((light * m) >> 12)


def gradient_add(alpha: int, r: int, coef_raw: int, backlight: bool, window_avg=None) -> int:
    """Single-pixel convenience wrapper used by the scalar checks below;
    `window_avg` lets a caller supply an already-box-averaged value."""
    avg = window_avg if window_avg is not None else alpha
    if backlight:
        return multiplier(FULL - avg, coef_raw, reverse_light=True)
    b_scaled = c_div(coef_raw * 2, 11)
    return multiplier(avg, b_scaled, reverse_light=False)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. OFF's multiplier never touches 0 while B_scaled > 0 ---")
    b_scaled = c_div(1000 * 2, 11)  # B = 1000 (arbitrary mid-range), scaled
    ms = [multiplier(avg, b_scaled, reverse_light=False) for avg in range(0, FULL + 1)]
    check("OFF multiplier stays within [B_scaled, 2*B_scaled] over the whole alpha range",
          min(ms) >= b_scaled and max(ms) <= 2 * b_scaled,
          f"min={min(ms)} max={max(ms)} B_scaled={b_scaled}")
    check("OFF multiplier is monotonically non-decreasing in alpha (brighter deeper in)",
          all(ms[i] <= ms[i + 1] for i in range(FULL)))

    print("\n--- 2. ON's multiplier is exactly proportional to (4096 - avg) ---")
    b = 1000
    ms_on = [multiplier(FULL - avg, b, reverse_light=True) for avg in range(0, FULL + 1)]
    check("ON multiplier is 0 at avg=4096 (deep interior) ...", ms_on[FULL] == 0, f"got {ms_on[FULL]}")
    check("... and at its maximum at avg=0 (fully transparent neighbourhood)",
          ms_on[0] == max(ms_on), f"ms_on[0]={ms_on[0]} max={max(ms_on)}")
    check("ON multiplier is monotonically non-increasing in alpha (opposite of OFF)",
          all(ms_on[i] >= ms_on[i + 1] for i in range(FULL)))

    print("\n--- 3. overdrive (強さ > 100%) plateaus at the raw light colour, never past it ---")
    light_y = 3000
    at_threshold = tinted_channel(0, light_y, FULL)
    deep_overdrive = tinted_channel(0, light_y, 20000)  # only reachable with 強さ well past 100%
    check("m at the m>=4096 threshold and m from deep overdrive (m=20000) add the same amount",
          at_threshold == deep_overdrive == light_y,
          f"threshold={at_threshold} overdrive={deep_overdrive} light_y={light_y}")
    print(f"  tinted_channel(base=0, light={light_y}, m=4096)  = {at_threshold}")
    print(f"  tinted_channel(base=0, light={light_y}, m=20000) = {deep_overdrive}"
          "   <- same as m=4096: the plateau, not a bigger number")

    print("\n--- 4. a 1-D shape: a 12-pixel-wide solid block (soft 3px ramp) through both modes ---")
    shape = [0] * 6 + [1365, 2730, 4096] + [4096] * 12 + [4096, 2730, 1365] + [0] * 6
    w = len(shape)
    assert len(shape) == w
    r = 3
    avg = box_average(shape, r)
    light_y = 4096
    print(f"  {'x':>3}{'alpha':>7}{'box avg':>9}{'OFF mult':>10}{'OFF add':>9}{'ON mult':>9}{'ON add':>8}")
    off_adds, on_adds = [], []
    for x in range(w):
        m_off = gradient_add(None, r, 1000, backlight=False, window_avg=avg[x])
        m_on = gradient_add(None, r, 1000, backlight=True, window_avg=avg[x])
        add_off = tinted_channel(0, light_y, m_off)
        add_on = tinted_channel(0, light_y, m_on)
        off_adds.append(add_off)
        on_adds.append(add_on)
        print(f"  {x:>3}{shape[x]:>7}{avg[x]:>9}{m_off:>10}{add_off:>9}{m_on:>9}{add_on:>8}")
    center = w // 2
    edge = shape.index(4096)  # first fully-opaque column, i.e. right at the silhouette's edge
    check("OFF (default) is brightest at the block's CENTER, not its edge",
          off_adds[center] > off_adds[edge], f"center(x={center})={off_adds[center]} edge(x={edge})={off_adds[edge]}")
    check("ON (逆光) is brightest near the block's EDGE, not its center",
          on_adds[edge] > on_adds[center], f"edge(x={edge})={on_adds[edge]} center(x={center})={on_adds[center]}")
    print("  OFF ('front light'): the tint grows toward the middle of a solid area - the object's")
    print("  own bulk lights up more than its thin edges. ON ('逆光'/backlight): the tint peaks")
    print("  right at the silhouette's edge and fades to nothing in a large solid interior - a rim")
    print("  light. Both read the SAME alpha channel; only the inversion and the +4096 bias differ.")

    print("\n--- 6. box_average (closed windowed-sum) vs box_average_literal (the actual")
    print("  silent-preload / head / middle / tail phases from sub_1005c080) ---")
    rng = random.Random(2)
    bad = None
    for _ in range(500):
        n = rng.randint(1, 60)
        r = rng.randint(0, 10)
        if n < 2 * r + 1:
            continue  # same n>=k restriction verify_halo.py §3 applies, for the same reason
        row = [rng.randint(0, FULL) for _ in range(n)]
        a, b = box_average(row, r), box_average_literal(row, r)
        if a != b:
            bad = (n, r, row, a, b)
            break
    check("closed form and literal 3-phase replay agree whenever n >= kernel width",
          bad is None, "" if bad is None else str(bad))
    print("  this is what tells apart the README's claim that the gradient pass's tail runs only")
    print("  r evict-only iterations (not kernelWidth-1 like the halo pass's) - see verify_halo.py")
    print("  for the halo side of the same comparison.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
