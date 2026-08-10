"""The combine worker 0x10089b60 - what シャープ actually is.

Everything before this worker is a plain blur. This is where the effect
happens, and it is an unsharp mask:

    S = trunc(強さ * 4096 / 1000)
    c' = c_orig + S * (c_orig - c_blur) / 4096

...but only when both alphas are 4096. exedit writes that case out separately
and takes a different, alpha-weighted route otherwise:

    p = (blur.a * orig.a) >> 12

    p == 4096 : c' = orig.c + (S * (orig.c - blur.c)) >> 12
    p >  0    : c' = orig.c + (S * trunc((orig.c*orig.a - blur.c*blur.a)/p)) >> 12
    p <= 0    : c' = orig.c                                     (blur discarded)

    out.a = orig.a, unconditionally

Five claims are checked here.

(1) `p == 4096` happens exactly when `orig.a == blur.a == 4096`, so the fast
    path really is "both opaque" and nothing else reaches it.

(2) On that path the two formulas are the same expression: at
    `orig.a = blur.a = 4096` the divide is exact and the general form collapses
    onto the fast one. Checked over a grid of colours and every interesting S.

(3) The general path is **not** a straight unsharp mask on straight colours.
    `trunc((a0*c0 - ab*cb)/((a0*ab)>>12))` is `4096*(c0/ab - cb/a0)`, so where
    the object is半透明 the difference is amplified by roughly `4096/a`. A 50%
    transparent area is sharpened twice as hard as an opaque one at the same
    `強さ`, and it is not a rounding artefact - it is the shape of the formula.

(4) `imul eax, S` is a plain 32-bit multiply applied *after* that divide, with
    no clamp on either side. The quotient reaches 16.7M when `p == 1`, so the
    product overflows int32 well inside the parameter range. Where that is
    reachable is bounded below.

(5) `p <= 0` writes the ORIGINAL pixel back. Combined with (4)'s absence of any
    upper clamp on the luma, this settles what happens at the two extremes:
    fully transparent areas come out untouched, and highlights are free to
    overshoot past 4096.

Run via main.py:
    uv run main.py inspect/sharp/verify_unsharp.py
"""

from tools.cints import c_div, sar

FULL = 4096
INT32_MIN, INT32_MAX = -(1 << 31), (1 << 31) - 1


def fast(c0, cb, s):
    """0x10089c41-0x10089c74."""
    return c0 + sar((c0 - cb) * s, 12)


def general(c0, cb, a0, ab, s):
    """0x10089cb2-0x10089d18. Divide first, scale second - see disasm_params.py."""
    p = (ab * a0) >> 12
    q = c_div(a0 * c0 - ab * cb, p)
    return c0 + sar(q * s, 12)


def combine(px_orig, px_blur, s):
    """One pixel of the worker, both paths plus the luma cleanup."""
    y0, cb0, cr0, a0 = px_orig
    yb, cbb, crb, ab = px_blur
    p = (ab * a0) >> 12
    if p == 0x1000:
        y, cb, cr = (fast(y0, yb, s), fast(cb0, cbb, s), fast(cr0, crb, s))
    elif p > 0:
        y = general(y0, yb, a0, ab, s)
        cb = general(cb0, cbb, a0, ab, s)
        cr = general(cr0, crb, a0, ab, s)
    else:
        return (y0, cb0, cr0, a0)          # untouched
    if y < 0:                              # 0x10089c76 / 0x10089d1a
        if y > -1024:
            cb = sar(cb * (y + 1024), 10)
            cr = sar(cr * (y + 1024), 10)
        else:
            cb = cr = 0
        y = 0
    return (y, cb, cr, a0)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- (1) which alpha pairs reach the fast path ---")
    # (a0*ab)>>12 == 4096  <=>  a0*ab in [4096*4096, 4097*4096), so the whole
    # square can be swept exactly by turning that into a range of ab per a0.
    hits = []
    lo, hi = 0x1000 << 12, (0x1001 << 12) - 1
    for a0 in range(1, FULL + 1):
        for ab in range(max(0, -(-lo // a0)), min(FULL, hi // a0) + 1):
            hits.append((a0, ab))
    print(f"  (orig.a, blur.a) pairs in [0,4096]^2 with (a0*ab)>>12 == 4096: {hits}")
    print("  -> only the fully opaque pair. Anything even one step translucent on")
    print("     either side takes the general path.")

    print("\n--- (2) the two paths agree where they meet ---")
    bad = checked = 0
    for s in (0, 409, 2048, 4096, 8192, 32768):
        for c0 in range(-8192, 8193, 37):
            for cb in range(-8192, 8193, 41):
                checked += 1
                if fast(c0, cb, s) != general(c0, cb, FULL, FULL, s):
                    bad += 1
    print(f"  {checked} (強さ, orig.c, blur.c) triples, {bad} mismatch(es)")
    print("  the divide is exact at a0 = ab = 4096, so the collapse is algebraic,")
    print("  not approximate.")

    print("\n--- (3) what the divisor does to translucent pixels ---")
    print("  a flat area at alpha `a`, orig.y = 4096, blur.y = 2048, 強さ = 100.0")
    print()
    print("      alpha   p       quotient   out.y at 強さ=100.0   amplification")
    for a in (4096, 3072, 2048, 1024, 512, 256, 64):
        p = (a * a) >> 12
        if p <= 0:
            print(f"      {a:5d}   {p:<7d} -          (blur discarded)")
            continue
        q = c_div(a * 4096 - a * 2048, p)
        out = combine((4096, 0, 0, a), (2048, 0, 0, a), FULL)[0]
        print(f"      {a:5d}   {p:<7d} {q:<10d} {out:<20d} x{q / 2048:.2f}")
    print("""
  The plain unsharp difference here is 2048 at every alpha. The worker instead
  scales it by ~4096/a, so the same 強さ bites harder the more transparent the
  object is - halos on a 25% -opacity object are four times what they are on an
  opaque one. That is the single biggest way シャープ differs from a textbook
  unsharp mask.""")

    print("\n--- (4) the 32-bit multiply after the divide ---")
    worst = (0, None)
    for ab in range(1, FULL + 1):
        a0_min = -(-FULL // ab)                       # smallest a0 with p >= 1
        for a0 in {min(a0_min, FULL), FULL}:
            if (a0 * ab) >> 12 == 0:
                continue
            p = (a0 * ab) >> 12
            for c0 in (-FULL, FULL):
                for cb in (-FULL, FULL):
                    q = c_div(a0 * c0 - ab * cb, p)
                    if abs(q) > worst[0]:
                        worst = (abs(q), (a0, ab, c0, cb, p, q))
    mag, (a0, ab, c0, cb, p, q) = worst
    print(f"  largest |quotient| over the representable domain: {mag}")
    print(f"    at orig.a={a0} blur.a={ab} orig.c={c0} blur.c={cb} -> p={p}, q={q}")
    print("    (that is `p == 1`: the divide by (a0*ab)>>12 barely divides at all)")
    print()
    print("      UI 強さ     S    |q| that overflows int32   headroom")
    for ui in (10.0, 50.0, 100.0, 400.0, 800.0):
        s = c_div(int(ui * 10) * FULL, 1000)
        if s == 0:
            continue
        thresh = (1 << 31) // s
        print(f"      {ui:7.1f} {s:6d}   >= {thresh:<20d} {'reachable' if thresh < mag else 'not reachable'}")
    print("""
  So `imul eax, ebp` wraps for a quotient the code can produce. What bounds it
  in practice is the blur itself: blur.a is an average of a window that always
  contains the pixel's own alpha, so blur.a >= orig.a / kernel_width per pass.
  Getting blur.a down near 1 while orig.a stays at 4096 takes a large 範囲 and
  an object only a few pixels across. **Not demonstrated on real output** - the
  claim here is only that no clamp stands between the divide and the multiply.""")

    print("\n--- (5) the two ends of the alpha range ---")
    print("  p == 0 (blur discarded) whenever orig.a * blur.a < 4096, not just when")
    print(f"  one of them is 0: the largest equal pair that still rounds to 0 is "
          f"{max(a for a in range(4097) if a * a < 4096)}"
          f" ({max(a for a in range(4097) if a * a < 4096) / 4096:.2%} opacity on both sides).")
    demo = [
        ("fully transparent", (2048, 100, -100, 0), (1000, 0, 0, 0)),
        ("both near-invisible", (2048, 100, -100, 63), (1000, 0, 0, 63)),
        ("blur went to zero", (2048, 100, -100, 4096), (1000, 0, 0, 0)),
        ("both opaque",       (3000, 100, -100, 4096), (2000, 50, -50, 4096)),
        ("highlight",         (4096, 0, 0, 4096), (1024, 0, 0, 4096)),
        ("mild undershoot",   (200, 2000, -2000, 4096), (700, 0, 0, 4096)),
        ("deep undershoot",   (0, 2000, -2000, 4096), (3000, 0, 0, 4096)),
    ]
    s = c_div(1000 * FULL, 1000)          # 強さ = 100.0
    print("  強さ = 100.0 (S = 4096)")
    print("      case                 orig                 blur                 out")
    for label, o, b in demo:
        print(f"      {label:<20s} {str(o):<20s} {str(b):<20s} {combine(o, b, s)}")
    print("""
  * `p <= 0` writes the original back verbatim - so transparent and
    near-transparent regions are never touched, and the four blur passes leave
    no residue there.
  * `out.a` is always `orig.a`: シャープ cannot change an object's silhouette.
  * the luma has no upper clamp. 4096 -> 7168 above is a real overshoot that
    only aviutl.exe's final YCbCr->RGB clips (rgb_ycbcr.md §3).
  * on the low side it does not simply clamp: between -1024 and 0 the chroma is
    faded out proportionally, below -1024 the pixel goes flat black. That is a
    shared idiom - verify_luma_undershoot.py.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
