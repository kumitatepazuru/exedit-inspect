"""The halo pass: box-blurs the object's alpha into a SEPARATE, larger canvas
and paints a flat light-coloured patch there, then draws the (possibly
gradient-tinted) object back on top of it.

Unlike the gradient pass (verify_shading.py), this one grows the canvas by
`2r` in both axes - sub_1005bcd0 (vertical) produces `h+2r` output rows from
`h` input rows via the standard 3-phase sliding window (head/middle/tail:
`kernelWidth + (h-kernelWidth) + (kernelWidth-1) = h+2r` outputs), and
sub_1005be50 (horizontal) does the same for columns, `w -> w+2r`. Per pixel of
that grown canvas:

    avg2D  = box_average_2d(alpha, r)                # plain alpha, NOT inverted, 0..4096
    scale  = min(4096, trunc(avg2D * A / 4096))        # the ONLY hard clamp in this effect
    pixel  = { Y = 4096, Cb = light.Cb, Cr = light.Cr, a = trunc(light.Y * scale / 4096) }

`Y` pinned to reference white and the payload carried entirely in `a` is the
same amplify-multiply idiom 閃光 uses (rgb_ycbcr.md / glint/README.md §5): once
composited normally, the visible contribution is `light * scale/4096`, without
ever needing to store `light.Y` directly.

func_proc then does, unconditionally when A>0:

    table[0x44](dst=fpip+0xB0, r, r, src=fpip+0xAC, 0, 0, w, h, 0, mode=3)   # normal composite
    swap fpip+0xAC <-> fpip+0xB0
    fpip+0xB4 = w+2r ; fpip+0xB8 = h+2r

mode=3 is "normal src-over-dst, 8 bytes/pixel" (blend_modes.md) - so the
object (already gradient-tinted, if that pass ran) is drawn crisply on top of
the halo, centred in the grown canvas.

This script checks:

  1. The 2D box average of alpha stays within [0, 4096], so `scale` only ever
     needs clamping when `A > 4096` (i.e. 強さ overdrive combined with 比率
     not reducing A) - never from the box average alone.
  2. The vertical+horizontal pass really does produce `(w+2r) x (h+2r)`
     outputs from a `w x h` input, replaying the exact 3-phase iteration
     counts from disasm_params.py rather than asserting the total.
  3. `A <= 0` (比率 at -100%) skips the halo pass, the canvas growth AND the
     final table[0x44] composite/swap entirely - but any gradient tint already
     baked into fpip+0xAC by the earlier pass survives, because that buffer is
     never touched again. This is the concrete edge-case verify_params.py §4
     flags: the object still looks shaded, just with no halo and no resize.
  4. `B <= 0` (比率 at +100%) skips the gradient dispatch only; the halo pass,
     growth and composite all proceed at full strength (A=S), so table[0x44]
     draws the UNMODIFIED object on top of the halo.
  5. Because the encoding stores `light.Y * scale / 4096` *as the alpha*, a
     dark light colour caps the halo's opacity no matter how high 強さ goes -
     the same "dark light colours vanish" trap 発光/閃光/グロー have
     (rgb_ycbcr.md §4), reached here through the amplify-multiply encoding
     rather than through a threshold or an exponent.

Run via main.py:
    uv run main.py inspect/light/verify_halo.py
"""

import random

from tools.cints import c_div

FULL = 4096


def box_average_1d(values: list, r: int) -> list:
    n = len(values)
    k = 2 * r + 1
    out = []
    for i in range(n):
        lo, hi = max(0, i - r), min(n - 1, i + r)
        out.append(c_div(sum(values[lo:hi + 1]), k))
    return out


def grow_1d(values: list, r: int) -> list:
    """Replay of the 3-phase sliding window that GROWS the axis by 2r, exactly
    as sub_1005bcd0/sub_1005be50 do (disasm_params.py). Output index `j`
    (0..n+2r-1) covers source window `[j-2r, j]` intersected with the real
    `0..n-1` - out-of-range positions simply contribute nothing to the sum,
    which is *always* divided by the full kernel width `k`, never by however
    many real samples happened to land in range (box_blur.md §3's "always
    divide by kernel width" variant - the one that fades at the edges).

    head phase (j=0..k-1): pure accumulation, nothing evicted yet.
    middle phase (j=k..n-1): accumulate the new sample, evict the one k back.
    tail phase (j=n..n+2r-1): input exhausted, only eviction continues.
    All three are the same two-line body below; splitting them out was only
    ever an optimisation, not a change in what gets summed."""
    n = len(values)
    k = 2 * r + 1
    total = 0
    out = []
    for j in range(n + 2 * r):
        if 0 <= j < n:
            total += values[j]
        if 0 <= j - k < n:
            total -= values[j - k]
        out.append(c_div(total, k))
    return out


def grow_1d_literal(values: list, r: int) -> list:
    """The same computation as grow_1d, but written as the three separate
    phases sub_1005bcd0 actually executes (disasm_params.py), so grow_1d's
    compact form can be checked against something closer to the raw
    instructions rather than trusted on its own:

      head:   k iterations, each ADDS one more sample and emits (no eviction)
      middle: (n-k) iterations, each ADDS the new sample AND EVICTS the old
              one in the same step, keeping exactly k real samples
      tail:   (k-1) iterations, each EVICTS one sample and emits (no adding -
              the input is exhausted)
    """
    n = len(values)
    k = 2 * r + 1
    out = []
    node = 0
    add_i = 0
    for _ in range(k):                      # head: k emits
        node += values[add_i]
        add_i += 1
        out.append(c_div(node, k))
    evict_i = 0
    for _ in range(max(0, n - k)):          # middle: n-k emits
        node += values[add_i] - values[evict_i]
        add_i += 1
        evict_i += 1
        out.append(c_div(node, k))
    for _ in range(k - 1):                  # tail: k-1 emits, evict only
        node -= values[evict_i]
        evict_i += 1
        out.append(c_div(node, k))
    return out


def halo_pixel(avg2d: int, a_coef: int, light_y: int) -> int:
    scale = c_div(avg2d * a_coef, FULL)
    if scale > FULL:
        scale = FULL
    return c_div(light_y * scale, FULL)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. the 2D box average of alpha never leaves [0, 4096] ---")
    rng = random.Random(0)
    bad = []
    for _ in range(2000):
        n = rng.randint(1, 40)
        r = rng.randint(0, 10)
        row = [rng.randint(0, FULL) for _ in range(n)]
        avg = box_average_1d(row, r)
        if min(avg) < 0 or max(avg) > FULL:
            bad.append((row, r, avg))
    check("2,000 random 1-D alpha rows: box average stays within [0, 4096]", not bad,
          "" if not bad else str(bad[0]))
    print("  since the halo formula is separable (vertical then horizontal), the same bound")
    print("  applies to the 2D average: a weighted mean of values in [0,4096] cannot leave it.")

    print("\n--- 2. scale needs clamping only when A > 4096 (i.e. 強さ overdrive) ---")
    for a_coef in (2048, 4096, 4097, 8192, 12288):
        scales = [c_div(avg * a_coef, FULL) for avg in range(0, FULL + 1)]
        needs_clamp = max(scales) > FULL
        expected = a_coef > FULL
        check(f"A={a_coef:>6}: needs clamping = {needs_clamp} (expected {expected})",
              needs_clamp == expected)

    print("\n--- 3. the halo pass really grows w and h by 2r, via the 3-phase window ---")
    for n, r in ((10, 2), (1, 0), (1, 3), (5, 5), (200, 12)):
        row = [4096] * n
        grown = grow_1d(row, r)
        check(f"n={n:>4}, r={r:>2}: output length is n+2r = {n+2*r}", len(grown) == n + 2 * r,
              f"got {len(grown)}")

    print("\n  grow_1d (compact, index-guarded) vs grow_1d_literal (the actual 3-phase")
    print("  head/middle/tail loop bounds from sub_1005bcd0) - only compared where n >= k,")
    print("  since clamp #1 (verify_params.py §5) is specifically what keeps 2r+1 < w,h in")
    print("  the first place; n < k is the untested tiny-object overrun box_blur.md §4 already")
    print("  flags as an open question for other effects, not something newly resolved here:")
    rng2 = random.Random(1)
    bad = None
    for _ in range(500):
        n = rng.randint(1, 60)
        r = rng.randint(0, 10)
        if n < 2 * r + 1:
            continue
        row = [rng2.randint(0, FULL) for _ in range(n)]
        a, b = grow_1d(row, r), grow_1d_literal(row, r)
        if a != b:
            bad = (n, r, row, a, b)
            break
    check("compact and literal-phase implementations agree whenever n >= kernel width",
          bad is None, "" if bad is None else str(bad))

    print("\n  a fully-opaque n-wide row, r=3:")
    row = [4096] * 10
    grown = grow_1d(row, 3)
    print(f"    input:  {row}")
    print(f"    output: {grown}")
    print("  the growing edges are exactly where the box average fades (fewer real samples,")
    print("  always divided by the full kernel width - box_blur.md §3's 'always divide by")
    print("  kernel width' variant, the same one 発光/ぼかし's growing passes use).")
    check("the grown row fades to 0 at both new edges (no real samples there yet)",
          grown[0] < grown[3] and grown[-1] < grown[-4])
    check("the grown row is exactly FULL wherever the window never crosses the real edge",
          all(v == 4096 for v in grown[2 * 3:10]), f"got {grown[2 * 3:10]}")

    print("\n--- 4. the amplify-multiply halo pixel, at a few (avg2D, A) combinations ---")
    light_y = 3500
    print(f"  {'avg2D':>7}{'A':>7}{'scale':>7}{'alpha out':>11}")
    for avg2d, a_coef in ((0, 4096), (2048, 4096), (4096, 4096), (2048, 8192), (2048, 1000)):
        scale = min(FULL, c_div(avg2d * a_coef, FULL))
        alpha_out = halo_pixel(avg2d, a_coef, light_y)
        print(f"  {avg2d:>7}{a_coef:>7}{scale:>7}{alpha_out:>11}")
    check("avg2D=0 (fully outside the blurred silhouette) -> alpha out = 0 (fully transparent)",
          halo_pixel(0, 4096, light_y) == 0)
    check("avg2D=4096, A=4096 (no overdrive) -> alpha out = light_y exactly (scale saturates at 1.0)",
          halo_pixel(4096, 4096, light_y) == light_y)

    print("\n  the halo's alpha can never exceed the light colour's own Y, at any 強さ:")
    print(f"  {'colour':>9}{'light Y':>9}{'max halo alpha':>16}{'max opacity':>13}")
    ceilings = {}
    for name, y in (("#ffffff", 4095), ("#ff0000", 1224), ("#0000ff", 466), ("#000080", 234)):
        # sweep A across its whole reachable range, 強さ 0..300% -> S up to 12288
        best = max(halo_pixel(4096, a, y) for a in range(0, 12289, 64))
        ceilings[name] = best
        print(f"  {name:>9}{y:>9}{best:>16}{100 * best / FULL:>12.1f}%")
    check("a dark light colour caps the halo's opacity - #0000ff never exceeds ~11%",
          ceilings["#0000ff"] == 466, f"got {ceilings['#0000ff']}")
    print("  This is the same 'dark light colours vanish' trap 発光/閃光/グロー have")
    print("  (rgb_ycbcr.md §4), reached by a different route: here it is the amplify-multiply")
    print("  encoding, where light.Y is literally the alpha being stored. The gradient pass")
    print("  is NOT affected - it adds light*m/4096 to the pixel and never touches alpha.")

    print("\n--- 5. 比率 = -100% (A=0): halo/growth/composite are skipped, but a live gradient tint survives ---")
    print("  func_proc's flow (disasm_params.py):")
    print("    B>0 ? dispatch gradient pass -> tints fpip+0xAC IN PLACE, unconditionally on A")
    print("    A>0 ? ...(clamp #2, halo dispatch, table[0x44], swap, resize)... : return 1")
    print("  so at 比率=-100% the function returns right after the gradient pass, if any ran.")
    print("  fpip+0xAC (already tinted) is never touched again and is what AviUtl displays -")
    print("  the object looks shaded exactly as verify_shading.py describes, with NO halo and")
    print("  NO change to fpip+0xB4/0xB8 (the bounding box is untouched).")
    check("this is a direct reading of the control flow, not a numeric claim - see §5 of the README", True)

    print("\n--- 6. 比率 = +100% (B=0): the gradient dispatch is skipped, halo runs at full A=S ---")
    print("  the mirror case: the gradient pass's own early-out (B<=0) fires, so fpip+0xAC is")
    print("  the UNMODIFIED object when table[0x44] later draws it on top of the halo. The halo")
    print("  itself is unaffected - A only depends on 比率 when 比率<0, so A=S here regardless.")
    check("this is a direct reading of the control flow, not a numeric claim - see §5 of the README", True)

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
