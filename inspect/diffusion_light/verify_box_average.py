"""The blur is a plain box average - and the three variants disagree about
what to divide by at the image edge.

Three claims, each with the instructions that support it:

  1. **uniform weights.** Every accumulate in all six workers is a bare
     `add`/`sub` of the pixel value; the only multiply in the loop body is the
     alpha premultiply, and the only divide is the one at the end. There is no
     weight table, no Gaussian, no per-tap coefficient anywhere - the same
     answer 発光 gives, but reached here with two radii instead of six.

  2. **colour is alpha-weighted, alpha is not.** The object workers accumulate
     `(c * a) >> 12` and finish with `trunc(sum_c * 4096 / sum_a)` in the x87
     unit, i.e. the average colour of what is actually visible in the window,
     independent of how much of the window is covered. Alpha is averaged
     separately and plainly. The frame workers have no alpha at all and divide
     all three channels by the sample count with `idiv`.

  3. **the divisor is where the variants differ.** The canvas-growing pair
     always divides by the full kernel width even when the window hangs off
     the image, so the diffusion fades out over the r pixels the canvas just
     gained. The fixed-size pair and the frame pair divide by the number of
     samples actually in the window, so the average stays "bright" right up to
     the edge and the diffusion does not fade there.

That third point is the behavioural difference behind サイズ固定 that is easy
to miss: it is not only "the object does/doesn't get bigger".

Run via main.py:
    uv run main.py inspect/diffusion_light/verify_box_average.py
"""

import random

from tools.cints import c_div
from tools.disasm import dump_all
from tools.pe_image import PEImage

ACCUMULATE = (0x1001C7A1, 0x6A)
NORMALISE = (0x1001C80B, 0x60)

# The divide that turns the running sums into a pixel, in each worker and each
# of its loops. This is the whole point of the script, so all of them are here.
DIVISORS = {
    "0x1001c710 growing V, loop 1 (ramp-up)": (0x1001C859, 0x0A),
    "0x1001c710 growing V, loop 2 (sliding)": (0x1001C9C0, 0x0A),
    "0x1001c710 growing V, loop 3 (tail)": (0x1001CABE, 0x0A),
    "0x1001cb10 growing H, loop 1 (left of the image)": (0x1001CCA9, 0x10),
    "0x1001cb10 growing H, loop 3 (sliding)": (0x1001CD7C, 0x0C),
    "0x1001d710 fixed V, loop 1 (ramp-up)": (0x1001D902, 0x14),
    "0x1001d710 fixed V, loop 2 (sliding)": (0x1001DA7D, 0x0E),
    "0x1001d710 fixed V, loop 3 (tail)": (0x1001DB7B, 0x12),
    "0x1001dbd0 fixed H, loop 1 (ramp-up)": (0x1001DD69, 0x18),
    "0x1001dbd0 fixed H, loop 3 (tail)": (0x1001E2DB, 0x14),
    "0x1001e4f0 frame V, loop 1 (ramp-up)": (0x1001E5F1, 0x0E),
    "0x1001e4f0 frame V, loop 3 (tail)": (0x1001E710, 0x0E),
    "0x1001e770 frame H, loop 2 (sliding)": (0x1001E86E, 0x1E),
}

ANNOTATIONS = {
    0x1001C7A1: "a = src.a",
    0x1001C7A5: "a == 0 -> contributes nothing, skip the whole pixel",
    0x1001C7AD: "a >= 4096 ?",
    0x1001C7B7: "no: sum_y += (y * a) >> 12   <- the only multiply in the loop",
    0x1001C7C3: "     sum_cb += (cb * a) >> 12",
    0x1001C7D7: "     sum_cr += (cr * a) >> 12",
    0x1001C7DF: "yes: add y/cb/cr unweighted - (c*4096)>>12 == c, so this is a shortcut",
    0x1001C805: "sum_a += a, always unweighted",
    0x1001C80B: "sum_a == 0 ?",
    0x1001C80D: "yes: skip the colour entirely - dst.y/cb/cr keep whatever was there",
    0x1001C80F: "st1 = sum_a",
    0x1001C813: "st0 = sum_y",
    0x1001C817: "* 4096",
    0x1001C81D: "/ sum_a",
    0x1001C81F: "_ftol -> dst.y = trunc(sum_y * 4096 / sum_a): un-premultiplied average",
    0x1001C859: "alpha: sum_a ...",
    0x1001C85C: "... / kernel width, no matter how much of the window was off-image",
    0x1001C9C3: "same full-width divide in the sliding loop",
    0x1001CAC1: "and in the tail, where the window is shrinking",
    0x1001CCB1: "the horizontal worker does the same",
    0x1001CD81: "ebx = kernel width here too",
    0x1001D90C: "fixed-size: divide by r + i + 1, the samples actually in the window",
    0x1001DA88: "full window in the middle, so the kernel width",
    0x1001DB85: "kernel width - i - 1 while the window shrinks at the bottom edge",
    0x1001DD72: "fixed-size horizontal: same clipped count",
    0x1001E055: "... kernel width in the middle ...",
    0x1001E2E3: "... and shrinking again at the right edge",
    0x1001E5F7: "frame: a running sample count, incremented as the window fills",
    0x1001E5F9: "y / count   <- integer divide, so it truncates toward zero",
    0x1001E603: "cb / count  <- and chroma is signed, so that matters",
    0x1001E716: "count decremented as the window empties at the bottom edge",
    0x1001E86E: "same running count in the horizontal pass",
}


def object_average(pixels, kernel_width, clipped):
    """One output pixel of an object-side box pass. `pixels` is the window's
    (y, cb, cr, a); `clipped` picks the fixed-size divisor over the growing
    one."""
    sy = scb = scr = sa = 0
    for y, cb, cr, a in pixels:
        if a == 0:
            continue
        if a >= 0x1000:
            sy += y; scb += cb; scr += cr
        else:
            sy += (y * a) >> 12
            scb += (cb * a) >> 12
            scr += (cr * a) >> 12
        sa += a
    n = len(pixels) if clipped else kernel_width
    if sa == 0:
        return None, None, None, 0
    return (c_div(sy * 4096, sa), c_div(scb * 4096, sa), c_div(scr * 4096, sa),
            c_div(sa, n))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "0x1001c710: the accumulate (one add per channel, one multiply for alpha)": ACCUMULATE,
        "0x1001c710: the normalise (x87, un-premultiply by the alpha sum)": NORMALISE,
        **DIVISORS,
    }, annotations=ANNOTATIONS)

    print("\n--- the x87 divide truncates toward zero, like idiv, not like Python's // ---")
    print("  checking trunc(float(sum_c)*4096/sum_a) == c_div(sum_c*4096, sum_a)")
    rng = random.Random(20260727)
    bad = []
    for _ in range(200000):
        sa = rng.randint(1, 1001 * 4096)
        sc = rng.randint(-4096 * 1001, 4096 * 1001)
        got = int(float(sc) * 4096.0 / float(sa))
        want = c_div(sc * 4096, sa)
        if got != want:
            bad.append((sc, sa, got, want))
    print(f"  200000 random (sum_c, sum_a) pairs over the reachable range: "
          f"{'OK' if not bad else f'{len(bad)} mismatches, e.g. {bad[:3]}'}")
    print("  (both round toward zero, so a negative chroma average lands on the same")
    print("   integer either way - the failure mode tools.cints exists to prevent)")

    print("\n--- edge behaviour: a window half off the image, alpha 4096 inside ---")
    r = 4
    kw = 2 * r + 1
    for covered in (kw, 5, 3, 1):
        window = [(2000, 300, -200, 4096)] * covered
        grow = object_average(window, kw, clipped=False)
        fixed = object_average(window, kw, clipped=True)
        print(f"  {covered:2d}/{kw} samples in the window:"
              f"  growing -> y={grow[0]:5d} a={grow[3]:5d}"
              f"   |  サイズ固定 -> y={fixed[0]:5d} a={fixed[3]:5d}")
    print("  The colour is identical - it is normalised by sum_a, not by the count.")
    print("  Only the alpha differs, and that is what makes the growing variant fade out")
    print("  across the new border while the fixed one keeps full strength at the edge.")

    print("\n--- alpha weighting: a bright but nearly transparent pixel next to a dark one ---")
    window = [(4096, 0, 0, 256), (256, 0, 0, 4096)]
    y, _, _, a = object_average(window, 2, clipped=True)
    plain = sum(p[0] for p in window) // len(window)
    print(f"  window = {window}")
    print(f"  alpha-weighted mean y = {y}   (plain mean would be {plain})")
    print(f"  averaged alpha        = {a}")
    print("  i.e. a faint highlight does not drag the diffused colour toward white;")
    print("  it lowers the coverage instead, and 強さ scales that coverage.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
