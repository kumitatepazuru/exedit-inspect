"""The two trackbars, from the raw value the UI stores to the Q12 the workers use.

エッジ抽出 is the first effect in this project whose two trackbars use *two
different* constant divisors, so the usual "everything is raw*4096/1000" shortcut
([`param_scaling.md`](../common/param_scaling.md)) is wrong here:

    強さ     0x10624dd3, sar 6   -> trunc(raw * 4096 / 1000)     display scale 10
    しきい値  0x68db8bad, sar 12  -> trunc(raw * 4096 / 10000)    display scale 100

Both divisors say the same thing once the display scale is folded in - "the UI's
100 % is Q12 1.0" - which is why the scales differ by the same factor of 10 as
the divisors. 強さ shows one decimal (100.0), しきい値 shows two (100.00).

Section 1 proves the divisors rather than asserting them: `tools.cints.divisor_of`
takes the (magic, shift) pair straight out of the instruction stream and reports
which constant divisor it implements, checked against C's `/` over a wide range.
Section 2 then replays the exact MSVC instruction sequence over *every* raw value
the trackbar can hold and compares it against `trunc(raw*4096/d)`.

Section 3 is the part that matters for using the effect: 強さ reaches x10, and a
Prewitt magnitude saturates the Q12 output long before that.

Run via main.py:
    uv run main.py inspect/edge_extraction/verify_param_scaling.py
"""

import math

from tools.cints import c_div, divisor_of, msvc_div
from tools.disasm import dump_all
from tools.pe_image import PEImage

# (name, magic, shift, raw_lo, raw_hi, display scale)
TRACKS = [
    ("強さ", 0x10624DD3, 6, 0, 10000, 10),
    ("しきい値", 0x68DB8BAD, 12, -10000, 10000, 100),
]

CONVERSIONS = (0x10022D66, 0x42)

ANNOTATIONS = {
    0x10022D6C: "track[0] = 強さ, raw",
    0x10022D6E: "magic #1",
    0x10022D73: "raw << 12",
    0x10022D76: "edx:eax = magic * (raw<<12); edx = the high dword",
    0x10022D78: "sar 6  -> effectively >> 38  -> /1000",
    0x10022D82: "+1 when the quotient came out negative: truncation, not floor",
    0x10022D87: "g_10134e74",
    0x10022D7D: "magic #2 - a different constant, loaded before the first one is even used",
    0x10022D90: "track[1] = しきい値, raw (can be negative)",
    0x10022D93: "raw << 12",
    0x10022D98: "sar 12 -> >> 44 -> /10000",
    0x10022DA2: "g_10134e6c",
}


def _peak_magnitude():
    """Largest trunc(sqrt(Gx^2+Gy^2)) the Prewitt pair can reach on a Q12 channel.

    Both gradients are linear in the eight taps, so the maximum sits at a corner
    of the box [0, 4096]^8 - all 256 of which are cheap to try.
    """
    best = (0, None)
    for bits in range(256):
        t = [(bits >> i) & 1 for i in range(8)]
        tl, tt, tr, ll, rr, bl, bb, br = t
        gx = (tr + rr + br - tl - ll - bl) * 4096
        gy = (bl + bb + br - tl - tt - tr) * 4096
        m = math.isqrt(gx * gx + gy * gy)
        if m > best[0]:
            best = (m, f"{tl}{tt}{tr}/{ll}.{rr}/{bl}{bb}{br}")
    return best


def _occurrences(img: PEImage, magic: int) -> int:
    """How many times this 4-byte constant appears anywhere in the mapped image."""
    needle = magic.to_bytes(4, "little")
    n, pos = 0, 0
    while True:
        i = img.data.find(needle, pos)
        if i == -1:
            return n
        n, pos = n + 1, i + 1


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- 1. which divisor does each (magic, shift) pair implement? ---")
    print(f"  {'track':<10}{'magic':>12}{'shift':>7}{'divisor':>10}")
    for name, magic, shift, *_ in TRACKS:
        print(f"  {name:<10}0x{magic:08x}{shift:>9}{str(divisor_of(magic, shift)):>10}")
    print("  (divisor_of derives the candidate from the magic and then checks it")
    print("   against C's / over 8000 sample points - it is not reading a table.)")

    print("\n--- 2. the instruction sequence, replayed over every reachable raw value ---")
    print(f"  {'track':<10}{'raws tested':>12}{'mismatches':>12}  formula")
    for name, magic, shift, lo, hi, _ in TRACKS:
        d = divisor_of(magic, shift)
        bad = sum(msvc_div(raw << 12, magic, shift) != c_div(raw * 4096, d)
                  for raw in range(lo, hi + 1))
        print(f"  {name:<10}{hi - lo + 1:>12}{bad:>12}  trunc(raw * 4096 / {d})")
    print("  -> both are plain truncating divisions; no rounding, no clamping.")
    print("  しきい値 keeps its sign: raw -10000 gives T = -4096, which *adds* 4096")
    print("  to every edge magnitude instead of subtracting.")
    print()
    print("  how common each magic is in the whole image (plain byte scan):")
    for name, magic, *_ in TRACKS:
        n = _occurrences(img, magic)
        print(f"    0x{magic:08x}  {n:>3} occurrence(s)   ({name})")
    print("  /1000 is exedit's house divisor; /10000 shows up four times in the whole")
    print("  binary and only once in an effect analysed here.")

    print("\n--- 3. what the numbers mean in the UI ---")
    print(f"  {'track':<10}{'scale':>6}{'UI range':>18}{'raw range':>16}{'Q12 range':>16}")
    for name, magic, shift, lo, hi, scale in TRACKS:
        d = divisor_of(magic, shift)
        ui = f"{lo / scale:.{len(str(scale)) - 1}f}..{hi / scale:.{len(str(scale)) - 1}f}"
        q12 = f"{c_div(lo * 4096, d)}..{c_div(hi * 4096, d)}"
        print(f"  {name:<10}{scale:>6}{ui:>18}{f'{lo}..{hi}':>16}{q12:>16}")
    print()
    print(f"  {'強さ UI':>10}{'raw':>8}{'Q12':>8}   gain applied to (magnitude - T)")
    for ui in (0, 25, 50, 100, 200, 400, 1000):
        raw = ui * 10
        print(f"  {ui:>9}.0{raw:>8}{c_div(raw * 4096, 1000):>8}   x{c_div(raw * 4096, 1000) / 4096:.3f}")
    print()
    peak, pattern = _peak_magnitude()
    axis = 3 * 4096
    print(f"  The largest magnitude a Q12 channel can produce is {peak} "
          f"(= sqrt(10) * 4096),")
    print(f"  from the neighbourhood {pattern} (0 = 0, 1 = 4096, centre skipped);")
    print(f"  a plain axis-aligned full-contrast step gives {axis}. Both are far above")
    print("  the 4096 the output clamps at, so:")
    print(f"  {'edge':<34}{'magnitude':>13}{'saturates from 強さ':>22}")
    for label, m in (("full-contrast step, axis aligned", axis),
                     ("the strongest possible neighbourhood", peak),
                     ("a 1/4-contrast step", axis // 4)):
        need = -(-4096 * 4096 // m)                 # smallest Q12 gain that clamps
        raw = -(-need * 1000 // 4096)
        print(f"  {label:<34}{m:>13}{raw / 10:>19.1f}")
    print("  i.e. at the default 100.0 every ordinary edge is already clamped, and 強さ")
    print("  only shapes the picture *below* about 30. Above it, only faint edges move.")

    print()
    dump_all(img, {"the two conversions in func_proc": CONVERSIONS}, annotations=ANNOTATIONS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
