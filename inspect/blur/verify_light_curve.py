"""Work out what 光の強さ actually changes, by running the exact curve
arithmetic from disasm_light_strength.py in Python.

The parameter does not scale anything. It wraps the four blur passes in a
forward/inverse pair of exponential/logarithmic maps, so the luma average
stops being an arithmetic mean:

    out = 16 * log_base( mean_i( base^(y_i / 16) ) ),   base = 1 + s*0.001

That is a power mean. At s -> 0 it degenerates into the plain average; as s
grows it leans harder and harder toward the brightest sample in the window,
so highlights survive the blur instead of being averaged away - "光の強さ".

Three things are worth checking rather than assuming, and this script checks
all three:

  * The curve itself is (almost) lossless. If forward+inverse round-tripped
    badly, the visible change would be curve error rather than the mean, and
    the reading above would be wrong.

  * The result never leaves [0, 4096]. This is where ぼかし differs from 発光,
    which drives the same helpers: 発光 SUMS six blur passes in curved space,
    so its inverse can overshoot full luma and clip per channel. ぼかし
    AVERAGES, and an average of curved values lies between the smallest and
    largest of them, so the unclamped 16-bit write-back at 0x10070517 can
    never actually overflow.

  * The chroma pays for it. cb/cr are requantised to a signed byte via
    (c + 8) >> 4 and restored with << 4, so they come back on a 16-unit grid.

Run via main.py:
    uv run main.py inspect/blur/verify_light_curve.py
"""

import math
import struct


def f32(x):
    """Round to float32 - the forward curve stores its result as a float."""
    return struct.unpack("<f", struct.pack("<f", x))[0]


def base_of(strength):
    """0x10070220: clamp to [1,100], then 1.0 + s * 0.001."""
    return 1.0 + min(max(strength, 1), 100) * 0.001


def forward(y, base):
    """0x1007038b-0x100703ae: pow(base, clamp(y,0,4096)/16) - 1, as float32."""
    return f32(math.pow(base, min(max(y, 0), 4096) * 0.0625) - 1.0)


def inverse(v, base):
    """0x100704ec-0x10070517: round(ln(v+1) * 16/ln(base)), no clamp."""
    return int(math.log(v + 1.0) * (16.0 / math.log(base)) + 0.5)


def quantise_chroma(c):
    """0x10070327-0x10070386 then 0x10070511: (c+8)>>4 clamped, later <<4."""
    return min(max((c + 8) >> 4, -128), 127) << 4


def blurred_luma(window, strength):
    """One window of an averaging pass, with or without the curve."""
    if strength <= 0:
        return sum(window) // len(window)
    base = base_of(strength)
    mean = sum(forward(y, base) for y in window) / len(window)
    return inverse(f32(mean), base)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- base = 1.0 + clamp(光の強さ,1,100) * 0.001 ---")
    print("    光の強さ |   base   | base^256 (the largest curved luma, y=4096)")
    for s in (0, 1, 5, 10, 20, 30, 45, 60):
        b = base_of(s)
        note = "   <- 0 never reaches the curve; func_proc skips it" if s == 0 else ""
        print(f"    {s:8d} | {b:.6f} | {b ** 256:18.6f}{note}")

    print("\n--- forward+inverse round trip over the whole luma range ---")
    print("    光の強さ | max |error| | mean |error| | worst y")
    for s in (1, 5, 10, 20, 30, 45, 60):
        b = base_of(s)
        worst, worst_y, total = 0, None, 0
        for y in range(0, 4097):
            e = abs(inverse(forward(y, b), b) - y)
            total += e
            if e > worst:
                worst, worst_y = e, y
        print(f"    {s:8d} | {worst:11d} | {total / 4097:11.4f} | "
              f"{'-' if worst_y is None else worst_y}")

    print("\n--- the curve turns the average into a power mean ---")
    window = [0, 0, 0, 0, 4096]      # one bright pixel in a 5-tap window
    print(f"    window (luma) = {window}, arithmetic mean = {sum(window) // len(window)}")
    print("    光の強さ | blurred luma | as a fraction of the brightest sample")
    for s in (0, 1, 5, 10, 20, 30, 45, 60):
        out = blurred_luma(window, s)
        print(f"    {s:8d} | {out:12d} | {out / max(window):.3f}")

    print("\n    same window with the bright sample at half luma:")
    window2 = [0, 0, 0, 0, 2048]
    for s in (0, 10, 30, 60):
        out = blurred_luma(window2, s)
        print(f"    光の強さ={s:3d} -> {out:5d}  (arithmetic mean would be "
              f"{sum(window2) // len(window2)})")

    print("\n--- the result can never leave [0, 4096], so the unclamped "
          "write-back is safe ---")
    worst_hi, worst_lo, cases = -1, 1 << 30, 0
    for s in (1, 10, 30, 60, 100):
        b = base_of(s)
        for lo in (0, 1, 100, 2048, 4095):
            for hi in (0, 1, 100, 2048, 4096):
                for n in (2, 3, 5, 9, 21, 101):
                    win = [lo] * (n - 1) + [hi]
                    out = blurred_luma(win, s)
                    cases += 1
                    worst_hi, worst_lo = max(worst_hi, out), min(worst_lo, out)
    print(f"    {cases} windows tested; results span [{worst_lo}, {worst_hi}] "
          f"-> {'within [0,4096]' if 0 <= worst_lo and worst_hi <= 4096 else 'OUT OF RANGE'}")
    print("    (contrast 発光, which sums six passes in curved space and does "
          "overshoot 4096)")

    print("\n--- chroma is requantised to a 16-unit grid for the whole blur ---")
    # data/filter.h documents cb/cr as -2048..2048, and says values may sit
    # outside that. Separate the two effects: rounding inside the byte's reach,
    # and hard clamping beyond it.
    in_reach = range(-2032, 2033)
    errs = [abs(quantise_chroma(c) - c) for c in in_reach]
    print(f"    within the byte's reach ([-2032, 2032]): max error {max(errs)}, "
          f"mean error {sum(errs) / len(errs):.2f}")
    print(f"    distinct output levels over the documented -2048..2048 range: "
          f"{len({quantise_chroma(c) for c in range(-2048, 2049)})} of 4097")
    print("    examples: " + ", ".join(f"{c}->{quantise_chroma(c)}"
                                       for c in (-8, -7, 0, 7, 8, 24, 2032)))
    print(f"    beyond it the [-128,127] byte clamp bites, asymmetrically: "
          f"2048->{quantise_chroma(2048)} but -2048->{quantise_chroma(-2048)} "
          f"(a signed byte reaches -128 but only +127).")

    print("""
Verdict:
  光の強さ = 0   the four passes run on plain 16-bit pixels, arithmetic mean.
  光の強さ > 0   the same four passes run on {float luma, byte chroma}, and
                 the luma average becomes a base-(1+s/1000) power mean, so a
                 bright pixel dominates its neighbourhood instead of being
                 diluted. The cost is two extra full-image passes plus a
                 4-bit-coarser chroma - and, unlike 発光's use of the same
                 helpers, no possibility of overshooting full luma.
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
