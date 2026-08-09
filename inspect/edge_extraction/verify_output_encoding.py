"""From the two gradients to the pixel that gets written.

The tail of every worker is the same five steps, and this script pins each one
to the instruction that performs it:

    mag  = trunc(sqrt(Gx*Gx + Gy*Gy))       fild / fsqrt / _ftol
    e    = (mag - T) * strength >> 12       one sub, one imul, one sar
    e    = clamp(e, 0, 4096)                jns / cmp 0x1000
    out.y, out.cb, out.cr = the colour      three word stores, unconditional
    out.a = (src.a * e) >> 12               the centre pixel's own alpha

Three things about that are worth being explicit about.

**The output carries no image colour at all.** y, cb and cr come from
`色の設定` verbatim, for every pixel including the ones with no edge. What the
effect computes is an alpha channel; the colour is a constant. That is why
`色の設定` has no 「指定なし」 option the way 発光 and グロー do
(verify_ex_data.py) - there is nothing to fall back to.

**The centre pixel enters exactly once, as `src.a`.** So an edge inside a fully
transparent region is discarded, and the result never extends past the original
silhouette even though the neighbourhood does.

**色エッジ takes three separate square roots and adds them**, rather than one
root over all six gradients. `sqrt(a)+sqrt(b)+sqrt(c) >= sqrt(a+b+c)`, so it
saturates sooner than a joint magnitude would; and because it is a sum, a grey
image (cb = cr = 0) makes 色エッジ and 輝度エッジ produce *identical* output.
Section 3 shows both.

Run via main.py:
    uv run main.py inspect/edge_extraction/verify_output_encoding.py
"""

import math

from tools.cints import sar
from tools.disasm import disasm_range, dump_all
from tools.pe_image import PEImage

FTOL = 0x10091AD8

TAILS = {
    "色エッジ 0x10022e30": (0x1002336C, 0x10023447 - 0x1002336C),
    "輝度エッジ 0x100234c0": (0x10023789, 0x10023807 - 0x10023789),
    "透明度エッジ 0x10023880": (0x10023A09, 0x10023A87 - 0x10023A09),
}

ANNOTATIONS = {
    # ---- 色エッジ: three magnitudes, one shared threshold ----------------
    0x1002336C: "Gx.cr",
    0x10023372: "Gx.cr squared",
    0x10023377: "Gy.cr squared (eax still holds Gy.cr)",
    0x1002337A: "Gx.cr^2 + Gy.cr^2",
    0x10023380: "-> x87 ...",
    0x10023384: "... sqrt ...",
    0x10023386: "... _ftol: truncate toward zero. Non-negative here, so floor",
    0x1002338B: "**the whole threshold, subtracted from the cr magnitude alone**",
    0x10023395: "Gx.cb",
    0x100233AF: "cb magnitude",
    0x100233B4: "(cr_mag - T) ...",
    0x100233BA: "... + cb_mag",
    0x100233BC: "Gx.y",
    0x100233D4: "y magnitude",
    0x100233D9: "sum = y_mag + cb_mag + cr_mag - T",
    0x100233DB: "x 強さ (Q12) ...",
    0x100233E2: "... >> 12",
    0x100233E5: "negative -> 0",
    0x100233F1: "above 4096 -> 4096",
    0x10023409: "colour Y ...",
    0x10023417: "... written unconditionally, edge or no edge",
    0x1002341A: "colour Cb",
    0x10023425: "colour Cr",
    0x10023430: "the *centre* pixel's alpha - the only time it is read",
    0x1002343A: "src.a ...",
    0x1002343D: "... x e ...",
    0x10023440: "... >> 12 ...",
    0x10023443: "... -> out.a. Everything else about the pixel is discarded",
    # ---- 輝度エッジ: one magnitude ---------------------------------------
    0x10023789: "Gx.y squared",
    0x10023790: "Gy.y squared",
    0x10023799: "one magnitude, not three",
    0x100237A4: "- T",
    0x100237AA: "x 強さ",
    0x100237B1: ">> 12",
    0x100237B4: "clamp low",
    0x100237BA: "clamp high",
    0x100237C6: "colour Y / Cb / Cr into the output",
    0x100237F3: "src.a x e >> 12 -> out.a",
    # ---- 透明度エッジ: identical tail ------------------------------------
    0x10023A09: "Gx.a squared",
    0x10023A10: "Gy.a squared",
    0x10023A19: "same magnitude, on alpha",
    0x10023A24: "- T",
    0x10023A2A: "x 強さ",
    0x10023A34: "clamp low",
    0x10023A3A: "clamp high",
    0x10023A46: "colour Y / Cb / Cr into the output",
    0x10023A73: "src.a x e >> 12 -> out.a. The alpha edge is still masked by src.a",
}


def edge_alpha(mags, T: int, strength: int, src_a: int) -> int:
    """The tail, as a Python function. `mags` is one or three magnitudes."""
    e = sar((sum(mags) - T) * strength, 12)
    e = 0 if e < 0 else 4096 if e > 4096 else e
    return sar(src_a * e, 12)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- 1. how many square roots does each worker take? ---")
    print(f"  {'worker':<24}{'fsqrt':>7}{'calls to _ftol':>16}{'stores of the colour':>22}")
    for label, (lo, size) in TAILS.items():
        ins = [i for i, _ in disasm_range(img, lo, size, resolve=False)]
        sqrts = sum(i.mnemonic == "fsqrt" for i in ins)
        ftols = sum(i.mnemonic == "call" and i.op_str == hex(FTOL) for i in ins)
        colour = sum(i.mnemonic == "mov" and "word ptr [0x10134e7" in i.op_str for i in ins)
        print(f"  {label:<24}{sqrts:>7}{ftols:>16}{colour:>22}")
    print("  -> 色エッジ takes three (one per channel) and adds the results;")
    print("     the other two take one. All three write all three colour words.")

    print("\n--- 2. the threshold and the gain are applied once, to the sum ---")
    print("  In 色エッジ the `sub` lands on the cr magnitude (0x1002338b) before the")
    print("  other two are added, which reads oddly but is arithmetically the same as")
    print("  subtracting it from the total: there is no clamp in between.")
    print(f"  {'y_mag':>8}{'cb_mag':>8}{'cr_mag':>8}{'T':>7}{'強さ':>8}{'e':>8}{'out.a (src.a=4096)':>20}")
    for mags, T, s in ((( 900,  0,  0),     0, 4096),
                       (( 900, 40, 60),     0, 4096),
                       (( 900, 40, 60),  1024, 4096),
                       (( 900, 40, 60), -1024, 4096),
                       (( 900, 40, 60),     0, 1024),
                       ((5000,  0,  0),     0, 4096)):
        e = sar((sum(mags) - T) * s, 12)
        e = 0 if e < 0 else 4096 if e > 4096 else e
        print(f"  {mags[0]:>8}{mags[1]:>8}{mags[2]:>8}{T:>7}{s:>8}{e:>8}"
              f"{edge_alpha(mags, T, s, 4096):>20}")

    print("\n--- 3. two consequences of the three-root sum ---")
    print("  a) on a grey image cb = cr = 0, so 色エッジ == 輝度エッジ exactly:")
    for y in (300, 1200, 4096):
        gx, gy = 3 * y, 0
        m = int(math.isqrt(gx * gx + gy * gy))
        print(f"     a step of {y:>4} in y: colour worker "
              f"{edge_alpha((m, 0, 0), 0, 4096, 4096):>5}   luminance worker "
              f"{edge_alpha((m,), 0, 4096, 4096):>5}")
    print("  b) with chroma present the sum is larger than a joint magnitude would be:")
    ys, cbs, crs = 3 * 1000, 3 * 400, 3 * 300
    m = [math.isqrt(v * v) for v in (ys, cbs, crs)]
    print(f"     y {ys}, cb {cbs}, cr {crs} ->  sum of roots {sum(m)}   "
          f"joint root {math.isqrt(ys * ys + cbs * cbs + crs * crs)}")

    print("\n--- 4. the tails, annotated ---")
    dump_all(img, TAILS, annotations=ANNOTATIONS)
    print("\n  `_ftol` (0x10091ad8) truncates toward zero; the argument is a square")
    print("  root and so never negative, which makes it a floor here")
    print("  ([integer_semantics.md](../common/integer_semantics.md)).")
    print("  The largest magnitude one channel can produce is sqrt(10)*4096 = 12952")
    print("  (verify_param_scaling.py brute-forces the eight taps), so Gx^2+Gy^2 peaks")
    print("  at 1.7e8 and 色エッジ's three-magnitude sum at 38856. Even multiplied by")
    print("  強さ = 40960 that is 1.6e9, still inside int32 - nothing here overflows.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
