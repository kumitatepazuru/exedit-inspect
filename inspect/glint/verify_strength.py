"""Check what 強さ actually becomes, over every value the trackbar can hold.

func_proc turns track[0] into two numbers and nothing else:

    strength = trunc(raw * 4096 / 1000)          via the magic-number divide
    T        = 4096 - strength, floored at 0     the threshold the workers use

The first is worth checking exhaustively because the disassembly does not say
"divide by 1000" anywhere - it says `imul` by 0x10624dd3 and `sar edx, 6`, and
whether that rounds or truncates decides the value at every one of the 1001
settings. The second is worth stating because it inverts the meaning of the
parameter: 強さ never multiplies anything. It is subtracted, as a floor that
the averaged ray luminance has to clear, and the *canvas growth* is the only
place strength appears as a multiplier (verify_canvas_growth.py).

Consequences that fall out of the numbers below:

  * 強さ = 100.0 (raw 1000, the default and the maximum) gives T = 0: every ray
    with any light along it at all produces output. There is no way to ask for
    a brighter glint, only for a dimmer one.
  * 強さ = 0 returns from func_proc immediately - the effect is skipped, not
    rendered as a no-op, so the canvas is not grown either.
  * the raw range stops at 1000, so unlike 発光 (whose 強さ goes to 2000 and
    carries the excess as an additive overflow) 閃光 has no above-100% regime.

Run via main.py:
    uv run main.py inspect/glint/verify_strength.py
"""

from tools.cints import MAGIC_1000, c_div, divisor_of, msvc_div
from tools.pe_image import PEImage
from tools.xrefs import scan

RAW_MIN, RAW_MAX = 0, 1000


def strength_from_raw(raw: int) -> int:
    """The instruction sequence at 0x1004e579..0x1004e599, literally."""
    return msvc_div(raw << 12, MAGIC_1000, 6)


def threshold_from_strength(strength: int) -> int:
    t = 0x1000 - strength
    return 0 if t < 0 else t


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("1) is `imul 0x10624dd3; sar edx, 6` really a truncating divide by 1000?")
    d = divisor_of(MAGIC_1000, 6)
    print(f"   divisor recovered from the magic: {d}")
    mismatches = [x for x in range(-2_000_000, 2_000_001, 7) if msvc_div(x, MAGIC_1000, 6) != c_div(x, 1000)]
    print(f"   disagreements with C's trunc-toward-zero /1000 over -2M..2M step 7: {len(mismatches)}")

    print("\n2) every 強さ setting")
    bad = []
    for raw in range(RAW_MIN, RAW_MAX + 1):
        got = strength_from_raw(raw)
        want = raw * 4096 // 1000  # raw >= 0, so floor and trunc agree
        if got != want:
            bad.append((raw, got, want))
    print(f"   raw {RAW_MIN}..{RAW_MAX}: {RAW_MAX - RAW_MIN + 1} values, "
          f"{len(bad)} disagree with raw*4096//1000")
    if bad:
        print(f"   !! {bad[:8]}")

    print("\n3) the table the README quotes")
    print(f"   {'UI':>7} {'raw':>6} {'strength':>9} {'threshold T':>12}  effect of T")
    for raw in (0, 1, 100, 250, 500, 750, 900, 1000):
        s = strength_from_raw(raw)
        t = threshold_from_strength(s)
        if raw == 0:
            note = "func_proc returns immediately - effect skipped entirely"
        elif t == 0:
            note = "any light at all along the ray survives"
        else:
            note = f"ray average must exceed {t}/4096 = {t / 4096:.3f} of full luminance"
        print(f"   {raw / 10:>7.1f} {raw:>6} {s:>9} {t:>12}  {note}")

    print("\n4) strength is never a multiplier on the pixel value")
    img = PEImage(dll_path)
    reads = [va for va in scan(img, 0x101A6B94) if 0x1004E560 <= va < 0x1004F260]
    workers = [va for va in reads if va >= 0x1004E9C0]
    print(f"   references to 0x101a6b94 (strength) in 閃光's code: {len(reads)}, "
          f"of which inside the two workers (>= 0x1004e9c0): {len(workers)}")
    print("   -> the per-pixel code never sees strength; it only ever reads 0x101a6b7c (T).")
    print("   func_proc uses strength exactly once, at 0x1004e791, to scale the canvas")
    print("   growth (`imul <extent>, strength; sar <extent>, 0xc`) - verify_canvas_growth.py.")
    print(f"   T is at its largest, {threshold_from_strength(strength_from_raw(1))}, at raw=1, "
          "just short of full luminance 4096;")
    print("   almost nothing can clear it, so low 強さ makes the glint vanish rather than")
    print("   dim smoothly - the parameter erodes the streak from its dim end inward.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
