"""What the per-pixel loop actually walks: the direction, the length, and how
many samples it takes to get there.

Both workers open the same way. For an output pixel (x, y):

    dist8  = (int)(sqrt(dx*dx + dy*dy) * 8.0)     dx,dy point at the centre
    length = trunc(dist8 * 750 / 1000)
    if dist8 > R:  length = R*length/dist8 ;  N = R
    else:          m = 8/4/2/1 by size    ;  N = dist8*m ;  length *= m
    if N < 2 or length < 2:  -> the degenerate centre path
    step = (dx << 16) / N , (dy << 16) / N ;  take `length` samples from (x,y)

Three things are worth pinning down, because none of them is visible from the
formula as written:

  * `length` samples of a step of `dist/N` always cover 0.75*dist, in *both*
    branches. dist8 measures in eighths of a pixel and R counts samples, so
    the comparison `dist8 > R` mixes units - but the span it produces does
    not change, only the sample spacing does. The ray is a fixed 75% of the
    way to the centre no matter what.
  * R is therefore purely a cost cap, and it caps *quality*: past dist == R
    the spacing exceeds one pixel and the streak starts skipping source rows.
  * R itself is `trunc(maxd/4) + trunc(maxd/2)`, two separate truncating
    divides, which is not the same as trunc(0.75*maxd) - it is one lower
    whenever maxd % 4 == 3.

Run via main.py:
    uv run main.py inspect/glint/verify_ray_geometry.py
"""

import math

from tools.cints import MAGIC_1000, c_div, msvc_div


def ftol(v: float) -> int:
    """sub_10091ad8: MSVC _ftol - sets RC=truncate, fistp, restores. Toward zero."""
    return int(v)


def sample_cap(maxd: int) -> int:
    """0x1004e68d..0x1004e6b7: R = trunc(maxd*250/1000) + trunc(maxd/2)."""
    return msvc_div(maxd * 250, MAGIC_1000, 6) + c_div(maxd, 2)


def max_extent(w: int, h: int, cx: int, cy: int, draft: bool = False) -> int:
    """0x1004e5c2..0x1004e688: the largest centre-to-corner-ish distance, capped
    by the image diagonal, and by 50 when fpip->flag & 0x200 is set."""
    maxd = max(abs(cx), abs(cy), abs(cx - w), abs(cy - h))
    diag = ftol(math.sqrt(w * w + h * h))
    maxd = min(maxd, diag)
    if draft and maxd > 50:
        maxd = 50
    return maxd


def ray(dx: int, dy: int, R: int):
    """The block at 0x1004ea86..0x1004eb2a. Returns (N, length, branch)."""
    dist8 = ftol(math.sqrt(dx * dx + dy * dy) * 8.0)
    length = msvc_div(dist8 * 750, MAGIC_1000, 6)
    if dist8 > R:
        length = c_div(R * length, dist8) if dist8 else 0
        return R, length, "capped"
    m = 8 if dist8 > 8 else 4 if dist8 > 4 else 2 if dist8 > 2 else 1
    return dist8 * m, length * m, f"x{m}"


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("1) R = trunc(maxd/4) + trunc(maxd/2), which is NOT trunc(0.75*maxd)")
    diff = [m for m in range(0, 4001) if sample_cap(m) != (3 * m) // 4]
    print(f"   maxd 0..4000: {len(diff)} values differ from trunc(0.75*maxd)")
    print(f"   they are exactly the maxd % 4 == 3 ones: "
          f"{all(m % 4 == 3 for m in diff)}  (first few: {diff[:6]})")
    for m in (7, 11, 100, 101):
        print(f"     maxd={m:<5} R={sample_cap(m):<5} trunc(0.75*maxd)={(3 * m) // 4}")

    print("\n2) the ray always spans 75% of the distance, in both branches")
    print(f"   {'dx':>6}{'dy':>6}{'dist':>9}{'branch':>9}{'N':>7}{'length':>8}"
          f"{'step px':>10}{'span px':>10}{'span/dist':>11}")
    R = sample_cap(100)
    worst = 0.0
    for dx, dy in ((1, 0), (2, 0), (3, 0), (5, 0), (12, 0), (40, 0), (100, 0),
                   (300, 0), (60, 80), (-200, 150)):
        dist = math.hypot(dx, dy)
        N, length, branch = ray(dx, dy, R)
        if N < 2 or length < 2:
            print(f"   {dx:>6}{dy:>6}{dist:>9.2f}{'degenerate':>9}"
                  f"{N:>7}{length:>8}{'-':>10}{'-':>10}{'-':>11}")
            continue
        step = dist / N
        span = step * length
        worst = max(worst, abs(span / dist - 0.75))
        print(f"   {dx:>6}{dy:>6}{dist:>9.2f}{branch:>9}{N:>7}{length:>8}"
              f"{step:>10.4f}{span:>10.2f}{span / dist:>11.4f}")
    print(f"   worst deviation from 0.75 in the rows above: {worst:.4f} "
          "(integer truncation only)")

    print("\n3) R is a cost cap that becomes a quality cap")
    print(f"   with R={R} (a 200x200 object, centre in the middle):")
    print(f"   {'dist px':>9}{'branch':>11}{'samples':>9}{'spacing px':>12}  quality")
    for dx in (0, 1, 4, 12, 50, 75, 100, 200, 400):
        dist = float(dx)
        N, length, branch = ray(dx, 0, R)
        if N < 2 or length < 2:
            print(f"   {dist:>9.1f}{'degenerate':>11}{'-':>9}{'-':>12}  centre pixel path")
            continue
        spacing = dist / N
        q = ("supersampled" if spacing < 0.5 else
             "~1 sample/px" if spacing <= 1.5 else f"skips {spacing:.1f} px per sample")
        print(f"   {dist:>9.1f}{branch:>11}{length:>9}{spacing:>12.3f}  {q}")
    print("   -> beyond dist == R the streak is undersampled: thin bright features")
    print("      further out than R alias into dashes rather than a continuous ray.")

    print("\n4) which pixels feed which - the 4x reach, by brute force")
    w = h = 41
    cx, cy = 20, 20
    R2 = sample_cap(max_extent(w, h, cx, cy))
    reach = {}
    for D in range(1, 200):
        N, length, _ = ray(D, 0, R2)
        if N < 2 or length < 2:
            continue
        stepx = c_div(D << 16, N)
        px = (D + cx) << 16 | 0x8000  # walking left from x = cx + D toward cx
        hit = set()
        for _ in range(length):
            hit.add((px >> 16) - cx)
            px -= stepx
        lo, hi = min(hit), max(hit)
        reach[D] = (lo, hi)
    inner = [(D, lo) for D, (lo, _) in reach.items() if lo > 0]
    fracs = [lo / D for D, lo in inner]
    print("   walking each destination pixel's own ray and recording the nearest")
    print("   source distance it still touches, as a fraction of its own distance:")
    print(f"     min {min(fracs):.4f}   max {max(fracs):.4f}   over D=1..199")
    print(f"     destinations reaching inside 0.25*D (which 4x would not cover): "
          f"{sum(1 for f in fracs if f < 0.25)}")
    print("   0.25 is the ideal (a ray spanning 0.75*D from D ends at 0.25*D); the")
    print("   capped branch overshoots it slightly because R truncates the sample")
    print("   count, and the +0.5 pixel centring rounds the last sample outward.")
    print("   -> a source pixel at d reaches destinations out to at most 4*d, which is")
    print("      exactly the growth factor verify_canvas_growth.py finds in func_proc:")
    print("      the canvas is grown to hold the whole streak and not a pixel more.")

    print("\n5) the degenerate branch")
    degen = [d8 for d8 in range(0, 40)
             if (lambda t: t[0] < 2 or t[1] < 2)(
                 (d8 * (8 if d8 > 8 else 4 if d8 > 4 else 2 if d8 > 2 else 1),
                  msvc_div(d8 * 750, MAGIC_1000, 6) * (8 if d8 > 8 else 4 if d8 > 4 else 2 if d8 > 2 else 1)))]
    print(f"   dist8 values that fall through to the centre path: {degen}")
    print(f"   dist8 = trunc(8*dist), so that is dist <= {max(degen) / 8} px:")
    print("   at most the single pixel the centre lands on, plus its immediate")
    print("   neighbours when the centre sits on a pixel corner. See")
    print("   verify_center_pixel.py for what that path then does.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
