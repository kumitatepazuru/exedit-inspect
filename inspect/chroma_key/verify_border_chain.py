"""境界補正 - the three-pass matte chain, and the contrast stretch at the end.

With 境界補正 = r > 0 the effect stops being a per-pixel decision and becomes a
small image-processing pipeline over a 16-bit *matte*:

    pass 1  0x10013340 / 0x10013500   map B[y][x] = min(d, 4096)
                                      (色彩補正 also: map C[y][x] = hue_excess)
    pass 2  0x100136e0                map A = vertical box average of map B
    pass 3  0x10013880 / 0x10013de0   v = (horizontal box average of map A) ...
                                      v = (v * map B[y][x]) >> 12
                                      t = (v - A)*r + B
                                      alpha *= t/4096, then the spill un-mix

with the two stretch constants computed once per worker:

    A = 4096 - 4096/r          B = 4096 - (4096/r)*r   (= 4096 mod r)

Both box passes are the plain separable box average of
`inspect/common/box_blur.md`, in the variant whose **divisor is always the
kernel width** - so the matte is pulled toward 0 (= "this is key colour") at
the image border, never toward 1.

Claims checked here:

  1. **the phase structure.** Each pass walks the classic three-phase sliding
     window; this script replays the loop bounds as written and compares the
     result against the closed form `sum(src[i-r : i+r+1]) / (2r+1)` with
     out-of-range samples read as zero.
  2. **the stretch is exact at the top.** `t(4096) == 4096` for every r from 1
     to 5, which is what makes 境界補正 leave the interior of an opaque object
     untouched while eroding its edge.
  3. **r = 1 is the identity stretch** - the default value only blurs.
  4. **small images overrun.** Phases 2 and 4 write `r+1` and `r` rows
     unconditionally, so an image shorter than `2r+1` gets `2r+1` rows written.
     The same holds along x in pass 3. Bounded and harmless at r <= 5, but it
     is a real out-of-range write and worth naming.

Run via main.py:
    uv run main.py inspect/chroma_key/verify_border_chain.py
"""

import random

from tools.cints import c_div, sar
from tools.disasm import dump_all
from tools.pe_image import PEImage

PASS1_WRITE = (0x1001349C, 0x1A)
PASS1_MAPC = (0x1001365C, 0x2E)
PASS2 = (0x10013730, 0x140)
PASS3_CONST = (0x100138F3, 0x3A)
PASS3_APPLY = (0x100139B4, 0x34)

ANNOTATIONS = {
    # pass 1
    0x1001349C: "d >= 4096?",
    0x100134A4: "no : map B = d",
    0x100134AD: "yes: map B = 4096. The matte is clamped, unlike the alpha path",
    0x100134B1: "  where d >= 4096 simply means 'do not touch the pixel'",
    # pass 1, 色彩補正 variant
    0x1001365C: "map C = the hue term ALONE, written before the saturation term",
    0x10013660: "  is folded in - this is the f that pass 3 will un-mix with",
    0x10013667: "sat_range",
    0x1001366D: "d += 8*(ds - sat_range), map C does not see this",
    0x10013670: "map B = min(d, 4096), same as the other variant",
    # pass 2
    0x10013730: "r",
    0x10013736: "kernel width 2r+1",
    0x1001373C: "map B: the source",
    0x10013745: "map A: the destination (they are 2*stride*h bytes apart)",
    0x10013742: "src column x; the work is split over x, one column range per thread",
    0x1001375C: "phase 1: prime the sum with r rows, writing nothing",
    0x10013767: "step = stride*2 bytes = one row of a 16-bit map",
    0x1001377E: "phase 2 runs (2r+1) - r = r+1 times ...",
    0x1001378B: "  ... adding the leading sample only: the window is [0, i+r]",
    0x10013795: "  and the divisor is the FULL kernel width -> zero padding",
    0x100137C6: "phase 3 runs h - (2r+1) times: the steady state",
    0x100137DD: "  leading sample in, trailing sample out",
    0x1001381C: "phase 4 runs r times: trailing samples only, window [i-r, h-1]",
    0x1001382E: "  still divided by the full kernel width",
    # pass 3
    0x100138F3: "r",
    0x100138FF: "4096 / r",
    0x1001390C: "A = 4096 - 4096/r",
    0x10013919: "(4096/r) * r ...",
    0x10013923: "B = 4096 - that = 4096 mod r",
    0x100139B4: "the horizontal box average, same three phases as pass 2",
    0x100139C0: "/ kernel width",
    0x100139C6: "map B again: the UNBLURRED matte at this pixel",
    0x100139C9: "v = (blurred * unblurred) >> 12 - a product, not a blend",
    0x100139CF: "v == 0 -> alpha = 0 outright",
    0x100139DD: "v - A ...",
    0x100139DF: "... * r ...",
    0x100139E2: "... + B: the stretch. Slope r, and t(4096) == 4096 exactly",
    0x100139E6: "t <= 0 -> alpha = 0",
}


def box_pass(src: list, r: int, stats: dict | None = None) -> list:
    """The vertical pass of 0x100136e0, replayed as written.

    Indices are tracked the way the pointers are: `lead` is the sample being
    added, `trail` the one being removed, and each phase runs the number of
    times its own loop bound says - which is what makes the h < 2r+1 overrun
    visible instead of being smoothed over by a clamp Python would add for
    free. Out-of-range samples are counted and read as zero; the real code
    reads whatever happens to be in the buffer there.
    """
    h, kw = len(src), 2 * r + 1
    stats = stats if stats is not None else {}
    stats.setdefault("over_read", 0)

    def at(i):
        if 0 <= i < h:
            return src[i]
        stats["over_read"] += 1
        return 0

    out, s, lead, trail = [], 0, 0, 0
    for _ in range(r):                       # phase 1: prime, write nothing
        s += at(lead)
        lead += 1
    for _ in range(kw - r):                  # phase 2: r+1 times
        s += at(lead)
        lead += 1
        out.append(c_div(s, kw))
    for _ in range(max(0, h - kw)):          # phase 3: the steady state
        s += at(lead) - at(trail)
        lead, trail = lead + 1, trail + 1
        out.append(c_div(s, kw))
    for _ in range(r):                       # phase 4
        s -= at(trail)
        trail += 1
        out.append(c_div(s, kw))
    stats["over_write"] = max(0, len(out) - h)
    return out


def box_reference(src: list, r: int) -> list:
    """What the three phases are supposed to add up to."""
    h, kw = len(src), 2 * r + 1
    return [c_div(sum(src[max(0, i - r):i + r + 1]), kw) for i in range(h)]


def stretch(v: int, r: int) -> int:
    a = 4096 - c_div(4096, r)
    b = 4096 - c_div(4096, r) * r
    return (v - a) * r + b


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "pass 1: writing the matte  0x1001349c": PASS1_WRITE,
        "pass 1: the extra hue map  0x1001365c": PASS1_MAPC,
        "pass 2: vertical box average  0x100136e0": PASS2,
        "pass 3: the stretch constants  0x100138f3": PASS3_CONST,
        "pass 3: applying it  0x100139b4": PASS3_APPLY,
    }, annotations=ANNOTATIONS)

    print("\n--- 1. do the three phases add up to a zero-padded box average? ---")
    rng = random.Random(20240728)
    bad = []
    for r in range(0, 6):
        for h in range(2 * r + 1, 2 * r + 24):
            src = [rng.randrange(0, 4097) for _ in range(h)]
            if box_pass(src, r) != box_reference(src, r):
                bad.append((r, h))
    print("  r in 0..5, h from 2r+1 to 2r+23: "
          + (f"MISMATCH at (r,h) = {bad[:4]}" if bad else
             "OK, identical to sum(src[i-r:i+r+1]) / (2r+1) with zeros outside"))
    print("  The divisor never shrinks at the edge, so the top and bottom r rows of")
    print("  the matte are averaged against zeros - i.e. dragged toward 'key colour'.")
    print("  境界補正 therefore eats into an object that touches the frame border.")

    print("\n--- 4. what happens when the image is shorter than the kernel? ---")
    print(f"  {'r':>3}{'kernel':>8}{'h':>5}{'rows written':>14}{'rows past end':>15}"
          f"{'samples read past end':>23}")
    for r in (1, 3, 5):
        for h in (1, 2 * r, 2 * r + 1):
            stats = {}
            n = len(box_pass([0] * h, r, stats))
            print(f"  {r:>3}{2 * r + 1:>8}{h:>5}{n:>14}{stats['over_write']:>15}"
                  f"{stats['over_read']:>23}")
    print("  Phases 2 and 4 have no `min(h, ...)` anywhere: they run r+1 and r times")
    print("  whatever h is, and neither the leading nor the trailing pointer is")
    print("  bounded. Pass 2 writes into map A, so the spill lands in map B, which")
    print("  starts 2*stride*h bytes later - at most 2*stride*(2r+1) = 22 bytes per")
    print("  column past the end at r = 5. Pass 3 does the same along x, in the pixel")
    print("  buffer itself. Both need an image below 2r+1 pixels to fire.")

    print("\n--- 2/3. the contrast stretch ---")
    print(f"  {'r':>3}{'A':>7}{'B':>4}   t(v) for v =  0   1024   2048   3072   4096")
    for r in range(1, 6):
        a = 4096 - c_div(4096, r)
        b = 4096 - c_div(4096, r) * r
        row = "  ".join(f"{stretch(v, r):>5}" for v in (0, 1024, 2048, 3072, 4096))
        print(f"  {r:>3}{a:>7}{b:>4}                {row}")
    print("  t(4096) == 4096 for every r: a fully opaque interior stays fully opaque.")
    print("  r = 1 gives A = 0, B = 0 and slope 1 - the identity, so the default")
    print("  境界補正 = 1 is a 3x3 blur of the matte and nothing else.")
    print("  For larger r everything below A is clipped to alpha 0: at r = 5 a pixel")
    print("  needs blurred*unblurred/4096 > 3277 (80%) just to survive.")

    print("\n--- 2b. the whole chain on a step edge (r = 3) ---")
    r = 3
    matte = [0] * 6 + [4096] * 10            # a hard key/foreground boundary
    blurred = box_pass(matte, r)
    print(f"  {'y':>4}{'matte':>8}{'blurred':>9}{'v':>7}{'t':>7}{'alpha (of 4096)':>17}")
    for y, (m, bl) in enumerate(zip(matte, blurred)):
        v = sar(bl * m, 12)
        t = 0 if v == 0 else max(0, stretch(v, r))
        print(f"  {y:>4}{m:>8}{bl:>9}{v:>7}{t:>7}{sar(4096 * t, 12):>17}")
    print("  The product with the unblurred matte is what keeps the key side at 0;")
    print("  the blur alone would have bled the foreground outward. What the chain")
    print("  actually does is pull the transition *into* the foreground by about r")
    print("  pixels - an erosion with a soft shoulder, not a feather.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
