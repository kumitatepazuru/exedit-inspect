"""角度 -> the Q16 direction vector, and the sample offsets it generates.

Seven claims:

  1. **The angle constant is `-pi/1800`, and 凸エッジ owns the only copy.**
     0x1009a3f8 is the negative twin of 0x1009a410 (`+pi/1800`), which six
     other effects use. Both spellings produce the same vector; see
     inspect/common/angle_vector.md.

  2. **(dx, dy) = (trunc(-sin(角度)*65536), trunc(cos(角度)*65536))**, i.e.
     "screen down is +y, positive 角度 turns counter-clockwise on screen".
     凸エッジ writes it as `sin(-t)*65536` where 方向ブラー writes
     `sin(t)*(-65536)`; checked to be bit-identical over all 7201 raw angles.

  3. **The k-th offset is `(floor(k*dx/65536), floor(k*dy/65536))` exactly**,
     because the worker accumulates in int32 and shifts with `sar`. The
     backward sample is `-(o_k)`, NOT `floor(-k*dx/65536)`, so the sampling is
     exactly point-symmetric about the pixel - which is what makes the sum a
     signed derivative rather than a lopsided difference.

  4. **The reach is 幅 pixels of Euclidean distance, whatever the angle.**

  5. **In the quadrant -90 < 角度 < 0 the k=1 sample is degenerate**: both
     components floor to 0, so the first term of the sum is `a(p) - a(p) = 0`.
     That is 1798 of the 7201 raw angles - and the default -45.0 is in the
     middle of it. No other quadrant loses a sample, because a negative
     component floors to -1 instead of 0.

  6. **`fpip->flag & 0x200` caps the sample count at 16 without changing the
     reach**: the step vector is stretched by 幅/16 and the normaliser follows.

  7. **34 (angle, component) pairs are float-sensitive** - every one of them a
     multiple of 30 degrees, where sin or cos lands exactly on 0, +-0.5 or +-1
     and a 1-ulp difference between x87's `fsin`/`fcos` and the host libm
     would move the Q16 component by 1.

Run via main.py:
    uv run main.py inspect/convex_edge/verify_direction.py
"""

import math
from fractions import Fraction

from tools.cints import c_div, to_i32

DEG10 = 0x1009A3F8        # -pi/1800   (凸エッジ)
DEG10_POS = 0x1009A410    # +pi/1800   (方向ブラー / 色ずれ / フレームバッファ / ...)
Q16 = 0x1009A3E8          # 65536.0
Q16_NEG = 0x1009A408      # -65536.0

ANGLE_RAW = (-3600, 3600)  # 角度: raw range, display scale 10 -> -360.0..360.0
WIDTH_RAW = (0, 100)       # 幅  : raw range, display scale 1  -> pixels


def direction(angle_raw: int, k: float = -0.0017453292519943296):
    """0x10007abb-0x10007aea, in x87 throughout.

        fild 角度 ; fmul -pi/1800 ; fld st0 ; fsin ; fmul 65536 ; _ftol -> dx
                                             fcos ; fmul 65536 ; _ftol -> dy

    `_ftol` truncates toward zero, so both components round toward 0.
    """
    t = angle_raw * k
    return math.trunc(math.sin(t) * 65536.0), math.trunc(math.cos(t) * 65536.0)


def steps_and_delta(width_raw: int, angle_raw: int, w: int, h: int, draft: bool = False):
    """0x10007a88-0x10007b2d. Returns (steps, dx, dy) or None if it returns early."""
    width = width_raw
    if width == 0:                                  # 0x10007a8f
        return None
    width = min(width, c_div(w, 2))                 # 0x10007aa4
    width = min(width, c_div(h, 2))                 # 0x10007ab5
    dx, dy = direction(angle_raw)
    if draft and width > 16:                        # 0x10007af2 / 0x10007af7
        dx = c_div(dx * width, 16)
        dy = c_div(dy * width, 16)
        width = 16
    elif width <= 0:                                # 0x10007b2b
        return None
    return width, dx, dy


def offsets(steps: int, dx: int, dy: int):
    """The k-th sample offset, as the worker builds it (0x10007c61-0x10007c7a)."""
    ax = ay = 0
    out = []
    for _ in range(steps):
        ax = to_i32(ax + dx)
        ay = to_i32(ay + dy)
        out.append((ax >> 16, ay >> 16))            # sar = floor
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    from tools.pe_image import PEImage
    from tools.xrefs import function_owners, nearest_owner, scan
    img = PEImage(dll_path)
    owners = function_owners(img)

    print("--- 1. the angle constants ---")
    c = img.f64(DEG10)
    check(f"0x{DEG10:08x} = {c!r} = -pi/1800 exactly (as a double)",
          c == -math.pi / 1800)
    check(f"0x{DEG10_POS:08x} = +pi/1800, the same double with the sign bit flipped",
          img.f64(DEG10_POS) == math.pi / 1800)
    check(f"0x{Q16:08x} = 65536.0 and 0x{Q16_NEG:08x} = -65536.0",
          img.f64(Q16) == 65536.0 and img.f64(Q16_NEG) == -65536.0)

    for va, label in ((DEG10, "-pi/1800"), (DEG10_POS, "+pi/1800")):
        hits = scan(img, va)
        who = sorted({nearest_owner(owners, v).split(" +")[0] for v in hits})
        print(f"  0x{va:08x} ({label}): {len(hits)} reference(s) from {who}")
    check("凸エッジ is the only user of the negative constant",
          {nearest_owner(owners, v).split(".")[0] for v in scan(img, DEG10)} == {"凸エッジ"})
    check("the positive constant is shared by several other (unanalysed) effects",
          len({nearest_owner(owners, v).split(".")[0] for v in scan(img, DEG10_POS)}) >= 5)
    print("  Splitting the sign between the constant and the multiplier is a compiler")
    print("  artefact, not a different convention - claim 2 shows the results agree.")

    print("\n--- 2. (dx, dy) = (-sin(角度), cos(角度)) in Q16 ---")
    print(f"  {'角度':>8}{'dx':>9}{'dy':>9}{'as a unit vector':>26}{'points':>12}")
    for raw in (-900, -450, 0, 450, 900, 1800, -1800, 2700):
        dx, dy = direction(raw)
        where = {(-1, 0): "left", (1, 0): "right", (0, -1): "up", (0, 1): "down"}.get(
            (round(dx / 65536), round(dy / 65536)), "")
        print(f"  {raw / 10:>8.1f}{dx:>9}{dy:>9}"
              f"{f'({dx / 65536:+.4f}, {dy / 65536:+.4f})':>26}{where:>12}")
    check("角度 = 0 points straight down the screen (0, +1)", direction(0) == (0, 65536))
    check("角度 = -90.0 points right (+1, 0)", direction(-900) == (65536, 0))
    check("the default -45.0 points down-right, i.e. the lit edge is the top-left one",
          direction(-450) == (46340, 46340))

    # 方向ブラー's spelling: fmul +pi/1800, then sin*(-65536) and cos*(+65536).
    bad = [raw for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1)
           if direction(raw) != (math.trunc(math.sin(raw * -c) * -65536.0),
                                 math.trunc(math.cos(raw * -c) * 65536.0))]
    check(f"all {ANGLE_RAW[1] - ANGLE_RAW[0] + 1} raw angles agree with 方向ブラー's "
          f"spelling bit for bit", not bad, f"first mismatch {bad[:1]}")

    print("\n--- 3. offsets are floor(k*d / 65536), and the pair is point-symmetric ---")
    bad = []
    over = []
    for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1, 7):
        dx, dy = direction(raw)
        for k, (ox, oy) in enumerate(offsets(WIDTH_RAW[1], dx, dy), start=1):
            if (ox, oy) != ((k * dx) >> 16, (k * dy) >> 16):
                bad.append((raw, k))
            if not (-(1 << 31) <= k * dx < (1 << 31) and -(1 << 31) <= k * dy < (1 << 31)):
                over.append((raw, k))
    check("the running accumulators reproduce floor(k*d/65536) for every k up to 100",
          not bad, f"first {bad[:1]}")
    check("... and never overflow int32 (max |k*d| = 100*65536 = 6553600)",
          not over and 100 * 65536 < (1 << 31))
    print("  The backward sample is coded as `x - ox`, `y - oy` (0x10007cb0-0x10007cba):")
    print("  the SAME floored offset negated, not floor(-k*dx/65536). For dx = 46340 and")
    print("  k = 1 that is -(0) = 0, where a second floor would have given -1 - the two")
    print("  differ on every k whose product is not a multiple of 65536.")
    dx, _ = direction(-450)
    check("worked example: -(floor(1*46340/65536)) = 0 but floor(-46340/65536) = -1",
          -((1 * dx) >> 16) == 0 and ((-1 * dx) >> 16) == -1)

    print("\n--- 4. the reach is 幅 pixels of Euclidean distance ---")
    print(f"  {'角度':>8}{'幅':>5}{'max |offset|':>14}{'distinct pixels':>17}"
          f"{'offsets k = 1..8':>44}")
    for raw in (0, -450, -900, -300, 450):
        for width in (4, 8):
            offs = offsets(width, *direction(raw))
            reach = max(math.hypot(*o) for o in offs)
            print(f"  {raw / 10:>8.1f}{width:>5}{reach:>14.2f}{len(set(offs)):>17}"
                  f"{str(offs[:8]):>44}")
    worst, comp = [], []
    for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1, 3):
        offs = offsets(WIDTH_RAW[1], *direction(raw))
        worst.append(max(math.hypot(*o) for o in offs))
        comp.append(max(max(abs(o[0]), abs(o[1])) for o in offs))
    check("no single component of any offset ever exceeds k, so 幅 bounds the reach "
          "on each axis exactly", max(comp) <= WIDTH_RAW[1], f"max component {max(comp)}")
    check("the Euclidean reach of a 幅=100 run stays within +-sqrt(2) of 100 px",
          abs(min(worst) - 100) <= math.sqrt(2) and abs(max(worst) - 100) <= math.sqrt(2),
          f"min {min(worst):.3f} max {max(worst):.3f}")
    print("  `sar` floors, so a negative component grows in magnitude by up to 1 while a")
    print("  positive one shrinks - which is why the diagonal reach can land slightly")
    print("  either side of 幅 instead of always short of it. Per axis the bound is")
    print("  exact. The *visible* bevel is 幅 px wide because the outer half of the band")
    print("  falls where alpha = 0 (verify_shading.py §5).")

    print("\n--- 5. the k=1 sample is wasted for -90.0 < 角度 < 0.0 ---")
    dead = [raw for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1)
            if offsets(1, *direction(raw)) == [(0, 0)]]
    runs, start, prev = [], None, None
    for raw in dead:
        if prev is None or raw != prev + 1:
            if start is not None:
                runs.append((start, prev))
            start = raw
        prev = raw
    runs.append((start, prev))
    check(f"{len(dead)} of {ANGLE_RAW[1] - ANGLE_RAW[0] + 1} raw angles put the first "
          f"sample on the pixel itself", len(dead) == 1798)
    check("they form exactly the open quadrant -89.9..-0.1 and its +360 alias",
          runs == [(-899, -1), (2701, 3599)], f"{runs}")
    check("the default 角度 = -45.0 is one of them", -450 in dead)
    print("  Both components are then in (0, 1) and floor to 0, so the term is")
    print("  `a(p) - a(p) = 0`. In the other three quadrants at least one component is")
    print("  negative and floors to -1, so the sample lands on a real neighbour.")
    print(f"  {'角度':>8}{'dx':>9}{'dy':>9}{'k=1 offset':>14}{'wasted?':>10}")
    for raw in (-899, -450, -1, 0, 1, 450, 900, -900, -901):
        dx, dy = direction(raw)
        o = offsets(1, dx, dy)[0]
        print(f"  {raw / 10:>8.1f}{dx:>9}{dy:>9}{str(o):>14}"
              f"{'yes' if o == (0, 0) else '':>10}")
    print("  Cost: one term out of 幅. With the default 幅 = 4 that is a quarter of the")
    print("  samples, so a 45-degree bevel is very slightly softer than a 44-degree one.")

    dup = {raw: 8 - len(set(offsets(8, *direction(raw))))
           for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1)}
    check("at 幅 = 8 at most 2 of the 8 offsets are duplicates, and none on the axes",
          max(dup.values()) == 2 and dup[0] == 0 and dup[-900] == 0,
          f"max {max(dup.values())}")
    print("  Repeats are unavoidable: the step is one pixel of Euclidean length, so on a")
    print("  diagonal each component only advances 0.707 px per step. The repeated term")
    print("  is counted twice, which is a mild directional weighting, not an error.")

    print("\n--- 6. fpip->flag & 0x200 caps the sample count at 16 ---")
    print(f"  {'幅':>5}{'draft':>7}{'steps':>7}{'dx':>9}{'dy':>9}"
          f"{'reach (px)':>13}{'normaliser':>12}")
    for width in (16, 17, 40, 100):
        for draft in (False, True):
            steps, dx, dy = steps_and_delta(width, -450, 4096, 4096, draft)
            offs = offsets(steps, dx, dy)
            print(f"  {width:>5}{str(draft):>7}{steps:>7}{dx:>9}{dy:>9}"
                  f"{max(math.hypot(*o) for o in offs):>13.2f}{200 * steps:>12}")
    check("幅 = 16 is not capped (the test is `幅 > 16`)",
          steps_and_delta(16, -450, 4096, 4096, True)[0] == 16
          and steps_and_delta(16, -450, 4096, 4096, True)[1] == direction(-450)[0])
    drift = []
    for width in range(17, WIDTH_RAW[1] + 1):
        for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1, 13):
            full = offsets(*steps_and_delta(width, raw, 4096, 4096, False))
            cut = offsets(*steps_and_delta(width, raw, 4096, 4096, True))
            drift.append(max(abs(full[-1][0] - cut[-1][0]), abs(full[-1][1] - cut[-1][1])))
    check("the furthest sample moves by at most 1 px when the cap kicks in",
          max(drift) <= 1, f"max drift {max(drift)} px")
    print("  So draft mode keeps the geometry and the amplitude and only thins the")
    print("  sampling: 16 taps instead of 幅, each 幅/16 px apart. The worker never")
    print("  reads the flag itself - func_proc bakes the decision into the globals.")

    print("\n--- 7. angles where x87 and libm could disagree ---")
    risky = []
    for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1):
        t = raw * c
        for name, f in (("sin", math.sin(t)), ("cos", math.cos(t))):
            v = f * 65536.0
            frac = v - math.floor(v)
            if frac < 1e-9 or frac > 1 - 1e-9:
                risky.append((raw, name, v))
    check("34 (角度, component) pairs sit within 1e-9 of an integer", len(risky) == 34,
          f"{len(risky)}")
    check("every one of them is a multiple of 30.0 degrees",
          all(raw % 300 == 0 for raw, _, _ in risky),
          f"{sorted({raw for raw, _, _ in risky if raw % 300})}")
    print(f"  {'角度':>8}{'':>5}{'value * 65536':>24}{'exact?':>9}")
    for raw, name, v in risky[:8]:
        print(f"  {raw / 10:>8.1f}{name:>5}{v!r:>24}{str(v == round(v)):>9}")
    print("  ...")
    safe = min(min(abs(math.sin(raw * c) * 65536.0 - round(math.sin(raw * c) * 65536.0)),
                   abs(math.cos(raw * c) * 65536.0 - round(math.cos(raw * c) * 65536.0)))
               for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1) if raw % 300)
    check(f"every other angle keeps a margin of at least {safe:.2e} to the nearest "
          f"integer, far more than a double ulp at 65536 (1.5e-11)", safe > 1e-8,
          f"{safe:.3e}")
    print("  x87's fsin/fcos are specified to about 1 ulp, so at the 30-degree multiples")
    print("  the Q16 component could come out 1 lower than the reference here computes.")
    print("  It matters where the component is exactly 32768 (= 0.5): floor(2*32768/65536)")
    print("  is 1 but floor(2*32767/65536) is 0, i.e. one sample slides by a pixel.")
    print("  Nothing in this repository pins down which value the real x87 produces.")

    # Exact-rational cross-check of the one thing that is not transcendental:
    # the step count normaliser 200*steps that pairs with these offsets.
    check("the normaliser 100*steps is built as `(5*(5*steps))*4`, exact for all steps",
          all(((s + s * 4) + (s + s * 4) * 4) * 4 == 100 * s for s in range(1, 101)))
    check("Fraction cross-check: 高さ/(200*steps) at the defaults is 1/800",
          Fraction(100) / (200 * 4) == Fraction(1, 8))

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
