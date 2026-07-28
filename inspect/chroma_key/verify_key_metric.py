"""The key metric: how far a pixel is from the key colour.

Every one of the four keying workers opens with the same twenty instructions,
and they are the whole of what クロマキー means by "this pixel is the key
colour". The metric is not a distance in the Cb-Cr plane - it is a pair of
independent 1-D distances, one angular and one radial, added with a fixed
weight:

    hue     = ftol(atan2(cr, cb) * 65536/(2*pi))     a 16-bit binary turn
    sat     = max(|cb|, |cr|)                        Chebyshev, not Euclidean
    dh      = |(int16)(hue - key_hue)|               wraps the short way round
    ds      = |sat - key_sat|
    d       = max(0, dh - hue_range) + 8 * max(0, ds - sat_range)

with `hue_range = 色相範囲 << 7` and `sat_range = (彩度範囲 * key_sat) >> 8`.

Four claims, checked separately:

  1. **the constant.** `0x1009a430` holds 10430.378350470453, which is
     `65536/(2*pi)` to the last bit of a double - so the angle really is a
     binary turn and the `(int16)` truncation below is a modular subtraction,
     not a bug.
  2. **`(int16)(hue - key_hue)` is the circular hue distance.** Checked
     against `min(|delta|, 65536-|delta|)` over the full range of hue values
     the ftol can produce, including the two endpoints where atan2 hits +-pi.
  3. **sat is the Chebyshev norm.** Which matters because it makes the
     "saturation" of a pure-Cb colour and of a 45-degree colour of the same
     Euclidean radius differ by sqrt(2) - the key band is a square annulus,
     not a circular one.
  4. **the 8x weight.** The saturation term is worth eight times the hue term
     per unit, so `d` reaches 4096 after 4096 units of hue (= 1/16 of a turn)
     but after only 512 units of saturation.

Run via main.py:
    uv run main.py inspect/chroma_key/verify_key_metric.py
"""

import math

from tools.cints import sar
from tools.disasm import dump_range
from tools.pe_image import PEImage

K_VA = 0x1009A430               # the double every worker multiplies the angle by
PIXEL_METRIC = (0x10012FE6, 0x76)

ANNOTATIONS = {
    0x10012FE6: "cr of the current pixel (px+4)",
    0x10012FEA: "cb of the current pixel (px+2)",
    0x10012FFE: "fpatan -> atan2(cr, cb)",
    0x10013000: "x 65536/(2*pi)",
    0x10013006: "_ftol: hue is an integer number of 65536ths of a turn",
    0x1001300F: "abs(cr) ...",
    0x10013019: "... abs(cb) ...",
    0x1001301D: "... sat = max(|cb|, |cr|)",
    0x10013025: "hue - key_hue, as a full 32-bit int ...",
    0x10013029: "... then truncated to 16 bits: THIS is the wrap-around",
    0x1001302D: "dh = |wrapped difference|",
    0x1001303B: "sat - key_sat ...",
    0x10013040: "... ds = |that|",
    0x10013044: "d = 0",
    0x10013046: "dh > hue_range ?",
    0x1001304A: "  d = dh - hue_range   (nothing at all when inside the hue band)",
    0x10013052: "ds > sat_range ?",
    0x10013058: "  d += (ds - sat_range) * 8   <- the saturation term weighs 8x",
    0x1001305B: "d >= 4096 -> leave the pixel completely alone",
    0x10013063: "alpha (px+6) ...",
    0x1001306A: "... *= d/4096. d == 0 means fully transparent",
    0x1001306D: "the only thing this worker ever writes",
}


def ftol(x: float) -> int:
    """CRT _ftol at 0x10091ad8: truncate toward zero."""
    return math.trunc(x)


def i16(x: int) -> int:
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def hue_of(cb: int, cr: int, k: float) -> int:
    return ftol(math.atan2(cr, cb) * k)


def sat_of(cb: int, cr: int) -> int:
    return max(abs(cb), abs(cr))


def distance(cb, cr, key_cb, key_cr, hue_raw, sat_raw, k):
    """The metric, replayed literally. Returns (d, hue_excess); hue_excess is
    the value the 色彩補正 pass-1 worker stores into scratch map C."""
    key_hue, key_sat = hue_of(key_cb, key_cr, k), sat_of(key_cb, key_cr)
    hue_range, sat_range = hue_raw << 7, sar(sat_raw * key_sat, 8)
    dh = abs(i16(hue_of(cb, cr, k) - key_hue))
    ds = abs(sat_of(cb, cr) - key_sat)
    hue_excess = max(0, dh - hue_range)
    return hue_excess + 8 * max(0, ds - sat_range), hue_excess


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    k = img.f64(K_VA)

    dump_range(img, *PIXEL_METRIC, label="the per-pixel metric (worker 0x10012f10)",
               annotations=ANNOTATIONS)

    print("\n--- 1. the multiplier at 0x1009a430 ---")
    exact = 65536 / (2 * math.pi)
    print(f"  in the binary : {k!r}")
    print(f"  65536/(2*pi)  : {exact!r}")
    print(f"  -> {'OK: bit-identical' if k == exact else 'MISMATCH'}")
    print(f"  reachable hue values: atan2 in [-pi, pi] -> ftol gives "
          f"[{ftol(-math.pi * k)}, {ftol(math.pi * k)}]")
    print("  i.e. exactly the range of an int16 plus its own negation - which is why")
    print("  truncating the *difference* to 16 bits is the right modular reduction.")

    print("\n--- 2. is (int16)(hue - key_hue) the circular distance? ---")
    lo, hi = ftol(-math.pi * k), ftol(math.pi * k)
    span = list(range(lo, hi + 1, 331)) + [lo, lo + 1, -1, 0, 1, hi - 1, hi]
    bad = []
    for a in span:
        for b in span:
            delta = abs(a - b) % 65536
            if abs(i16(a - b)) != min(delta, 65536 - delta):
                bad.append((a, b))
    print(f"  {len(span) ** 2} pairs over the full reachable range: "
          + (f"MISMATCH at {bad[:4]}" if bad else "OK, always the short way round"))
    print("  Worth stating because 色相範囲 = 256 gives hue_range = 32768 = half a")
    print("  turn, i.e. the maximum the wrapped distance can ever reach: at 256 the")
    print("  hue test can no longer reject anything and only saturation is left.")

    print("\n--- 3. sat = max(|cb|, |cr|): what the key band looks like ---")
    print(f"  {'colour (cb,cr)':>16}{'Chebyshev':>11}{'Euclidean':>11}   ratio")
    for cb, cr in ((512, 0), (0, 512), (512, 512), (362, 362), (-512, 200)):
        cheb, eucl = sat_of(cb, cr), math.hypot(cb, cr)
        print(f"  {f'({cb},{cr})':>16}{cheb:>11}{eucl:>11.1f}   {cheb / eucl:.3f}")
    print("  The locus of constant sat is a square, so a key colour on a diagonal")
    print("  (cb ~ cr) covers a 41% wider range of true chroma magnitudes than one")
    print("  on an axis. There is no code anywhere that corrects for this.")

    print("\n--- 4. the two tolerance bands, in their own units ---")
    print(f"  {'色相範囲':>10}{'hue_range':>12}   as a fraction of a full turn")
    for raw in (0, 8, 24, 64, 128, 256):
        hr = raw << 7
        note = "everything passes the hue test" if hr >= 32768 else f"+-{hr / 65536:.4f} turn"
        print(f"  {raw:>10}{hr:>12}   {note}   {'(default)' if raw == 24 else ''}")
    print(f"\n  {'彩度範囲':>10}{'key_sat':>10}{'sat_range':>12}   accepted sat band")
    for raw in (0, 32, 96, 192, 256):
        for key_sat in (256,):
            sr = sar(raw * key_sat, 8)
            print(f"  {raw:>10}{key_sat:>10}{sr:>12}   [{key_sat - sr}, {key_sat + sr}]"
                  f"   {'(default)' if raw == 96 else ''}")
    print("  sat_range is a *fraction of the key's own saturation* (彩度範囲/256 of")
    print("  it), so the same slider is a wider absolute band for a vivid key than")
    print("  for a washed-out one. And it is a band, not a ceiling: a colour more")
    print("  saturated than the key by more than sat_range is rejected too.")

    print("\n--- 4b. how far outside the band before a pixel is fully kept? ---")
    print("  d >= 4096 leaves the pixel untouched; d == 0 erases it.")
    print(f"  {'excess':>8}{'via hue':>12}{'via sat':>12}")
    for d in (0, 1024, 2048, 4096):
        print(f"  {d:>8}{d:>12}{d // 8:>12}")
    print("  4096 units of hue is 1/16 of a turn; 512 units of saturation is 512")
    print("  out of a Cb/Cr range of +-2048. The saturation axis is much the sharper")
    print("  of the two, and it is the one that carries the soft edge in practice.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
