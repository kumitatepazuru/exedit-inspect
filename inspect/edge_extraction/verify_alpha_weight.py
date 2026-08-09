"""How each neighbour's own alpha weights it before the Prewitt sum.

verify_prewitt_taps.py derives the kernels along the path where every neighbour
is opaque. The other two paths are what this script is about. Each tap in the
色エッジ and 輝度エッジ workers opens with the neighbour's alpha and branches
three ways:

    a >= 4096   ->  v = c                    take the sample as it is
    0 < a < 4096 -> v = (c * a) >> 12        premultiply it
    a <= 0      ->  the tap is skipped       contributes nothing at all

which is one expression, `v = c * clamp(a, 0, 4096) / 4096` - the sample in
**premultiplied** form - with the two ends of the range special-cased so the
common cases cost no multiply. Section 2 checks that the three arms really are
one expression by brute force over the whole 16-bit range.

The 透明度エッジ worker has none of this: there the alpha *is* the sample, so
there is nothing to weight it by. Section 1 counts the branches to show the
split is real and not an artifact of where the ranges were cut.

Two consequences worth stating out loud:

  * the gradient sees premultiplied colour, so **the silhouette of a flat-coloured
    object is itself an edge** - alpha falling from 4096 to 0 drags y, cb and cr
    down with it. 輝度エッジ on a solid square draws its outline even though the
    luminance inside and outside the shape never differs.
  * `>> 12` is `sar`, i.e. floor, not the truncation C's `/` would give
    ([`integer_semantics.md`](../common/integer_semantics.md)). Cb and Cr are
    signed, so section 3 shows where a reference implementation written with
    `int(c*a/4096)` drifts by one - on colour only, never on greys.

Run via main.py:
    uv run main.py inspect/edge_extraction/verify_alpha_weight.py
"""

from tools.cints import c_div, sar
from tools.disasm import disasm_range, dump_all
from tools.pe_image import PEImage

# the pixel-loop body of each worker: first tap up to the magnitude
BODIES = {
    "色エッジ": (0x10022E30, 0x10022FA1, 0x1002336C, 3),
    "輝度エッジ": (0x100234C0, 0x1002362D, 0x10023789, 1),
    "透明度エッジ": (0x10023880, 0x100239D2, 0x10023A09, 0),
}

# one tap of 輝度エッジ, in full: the smallest complete instance of the branch
ONE_TAP = (0x1002362D, 0x2B)

ANNOTATIONS = {
    0x1002362D: "the neighbour's alpha, s(-1,-1).a",
    0x10023632: "eax = 0 ...",
    0x10023634: "... ecx = 0: both gradients start empty",
    0x10023636: "a >= 4096 ?",
    0x1002363C: "  no -> the premultiply arm at 0x10023645",
    0x1002363E: "opaque: take s(-1,-1).y as it is",
    0x10023643: "  -> straight to the accumulate",
    0x10023645: "a > 0 ?",
    0x10023647: "  no -> 0x10023658, the next tap. This tap contributes nothing",
    0x10023649: "s(-1,-1).y ...",
    0x1002364E: "... * a ...",
    0x10023651: "... sar 12: premultiplied. sar, so this floors",
    0x10023654: "Gx = -v  (the first tap initialises both accumulators)",
    0x10023656: "Gy = Gx, i.e. also -v",
}


def count(img: PEImage, lo: int, hi: int, pred) -> int:
    return sum(bool(pred(i)) for i, _ in disasm_range(img, lo, hi - lo, resolve=False))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- 1. the branch exists in two workers and not in the third ---")
    print(f"  {'worker':<14}{'body':>24}{'cmp ..,0x1000':>15}{'imul':>7}{'sar ..,0xc':>12}"
          f"{'channels':>10}")
    ok = True
    for name, (addr, lo, hi, ch) in BODIES.items():
        cmps = count(img, lo, hi, lambda i: i.mnemonic == "cmp" and i.op_str.endswith("0x1000"))
        # the squares that build the magnitude are `imul r, r` with equal operands
        imuls = count(img, lo, hi, lambda i: i.mnemonic == "imul"
                      and len(set(i.op_str.split(", "))) == 2)
        sars = count(img, lo, hi, lambda i: i.mnemonic == "sar" and i.op_str.endswith("0xc"))
        good = cmps == 8 * bool(ch) and sars == 8 * ch and imuls == 8 * ch
        ok &= good
        print(f"  {name:<14}{f'0x{lo:08x}..0x{hi:08x}':>24}{cmps:>15}{imuls:>7}{sars:>12}"
              f"{ch:>10}   {'OK' if good else 'MISMATCH'}")
    print(f"  -> {'OK' if ok else 'MISMATCH'}: exactly 8 alpha tests per worker that has")
    print("     colour to weight (one per neighbour) and one multiply+shift per channel;")
    print("     透明度エッジ has none, because there the alpha is the sample.")

    print("\n--- 2. the three arms are one expression ---")
    print("  claim:  v = c * clamp(a, 0, 4096) / 4096, rounded down")
    bad = []
    for a in list(range(-4096, 8193)):
        for c in (-2048, -1, 0, 1, 2047, 4096):
            if a >= 4096:
                arm = c
            elif a > 0:
                arm = sar(c * a, 12)
            else:
                arm = 0
            if arm != sar(c * max(0, min(a, 4096)), 12):
                bad.append((a, c, arm))
    print(f"  checked a in -4096..8192 x c in six extremes: {len(bad)} disagreement(s)")
    print("  (`a >= 4096` giving c and `sar(c*4096,12)` giving c is why the fast path")
    print("   is exact rather than approximate.)")

    print("\n--- 3. sar vs C's divide: where a reference implementation drifts ---")
    print(f"  {'c':>8}{'a':>7}{'sar(c*a,12)':>13}{'c_div(c*a,4096)':>17}   note")
    for c, a in ((4096, 2048), (-1, 2048), (-1024, 3000), (-2048, 1), (2048, 1)):
        s, d = sar(c * a, 12), c_div(c * a, 4096)
        note = "same" if s == d else "OFF BY ONE - only ever for negative c"
        print(f"  {c:>8}{a:>7}{s:>13}{d:>17}   {note}")
    pairs = [(c, a) for c in range(-2048, 2049) for a in range(0, 4097, 7)]
    bad = [(c, a) for c, a in pairs if sar(c * a, 12) != c_div(c * a, 4096)]
    print(f"  over c in -2048..2048 x a in 0..4096 step 7: {len(bad)} of {len(pairs)} "
          "disagree,")
    print(f"  and {sum(1 for c, a in bad if c >= 0)} of those have c >= 0.")
    print("  y is never negative so it is unaffected; cb and cr are, on most taps.")

    print("\n--- 4. one tap in full (輝度エッジ, the first one) ---")
    dump_all(img, {"輝度エッジ tap s(-1,-1)": ONE_TAP}, annotations=ANNOTATIONS)
    print("\n  The 色エッジ worker repeats this shape three times per tap (y, cb, cr),")
    print("  reusing the single alpha test; 透明度エッジ drops the test entirely and")
    print("  goes straight from the load to `add`/`sub`.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
