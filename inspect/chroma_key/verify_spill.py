"""色彩補正 / 透過補正 - the spill un-mix, and what it assumes.

Once the alpha has been decided, the 色彩補正 workers do one more thing: they
push the pixel's chroma *away* from the key colour.

    f   = max(hue_excess, ((key_sat - sat) << 12) / key_sat)
    if 1 < f < 4096:
        cb' = clamp(key_cb + ((cb - key_cb) << 12) / f, -2048, 2048)
        cr' = clamp(key_cr + ((cr - key_cr) << 12) / f, -2048, 2048)
    if 透過補正 and f < 4096:
        a'  = (f * a) >> 12

That is the standard un-premultiply of a two-colour mix. If an edge pixel is
`c` parts foreground and `1-c` parts key colour, then

    px = c*fg + (1-c)*key      =>      fg = key + (px - key)/c

and `f/4096` is exedit's estimate of `c`. The saturation half of the estimate
is *exact* when the foreground is achromatic, which is the case this script
demonstrates - and its failure mode when the foreground is not is the reason
色彩補正 is a checkbox rather than something the filter always does.

透過補正 then multiplies the alpha by the same `c`, which is the other half of
the same identity: the pixel keeps only the coverage that was foreground. It
has no effect of its own - it is read by the two 色彩補正 workers and by
nothing else (verify_dispatch.py).

Claims checked here:

  1. the formula and its clamps, read off the instruction stream;
  2. `key_sat` is clamped to >= 1 *for the division only* - `sat_range` is
     computed from the unclamped value, so an achromatic key colour
     (`cb == cr == 0`) gives `sat_range = 0` and a divisor of 1;
  3. the un-mix inverts a grey-foreground mix exactly (up to integer
     truncation) and overshoots on a coloured foreground;
  4. the clamp to +-2048 is reachable, and it is what stops a nearly-pure-key
     pixel from exploding when `f` is small.

Run via main.py:
    uv run main.py inspect/chroma_key/verify_spill.py
"""

from tools.cints import c_div, sar
from tools.disasm import dump_range
from tools.pe_image import PEImage

SPILL = (0x1001324C, 0xB0)

ANNOTATIONS = {
    0x1001324C: "ebp = key_sat (clamped to >= 1 at 0x10013157)",
    0x1001324E: "key_sat - sat",
    0x10013250: "<< 12",
    0x10013254: "/ key_sat -> the saturation estimate of the foreground coverage",
    0x10013256: "esi = max(hue_excess, that)  <- hue_excess was saved before the",
    0x10013258: "  saturation term was folded into d, so f is NOT d",
    0x1001325C: "f >= 4096: the pixel is not contaminated, leave the chroma alone",
    0x10013264: "f <= 1: the pixel is essentially pure key colour - dividing by it",
    0x10013267: "  would blow up, so leave the chroma alone here too",
    0x10013269: "ebp = ex_data",
    0x1001326D: "cb of the pixel",
    0x10013271: "key_cb (ex_data+2)",
    0x10013275: "cb - key_cb ...",
    0x1001327B: "... << 12 / f: the difference is *amplified*, since f < 4096",
    0x10013283: "... and added back onto the key",
    0x10013285: "key_cr (ex_data+4), same again for cr",
    0x10013293: "clamp cb' to +2048 ...",
    0x100132A2: "... and to -2048",
    0x100132AF: "clamp cr' the same way",
    0x100132CD: "write cb' (px+2)",
    0x100132D1: "write cr' (px+4)",
    0x100132D4: "check[1] = 透過補正",
    0x100132DC: "f >= 4096 -> nothing to correct",
    0x100132E4: "alpha *= f/4096: the coverage the un-mix just assumed",
    0x100132F8: "write the alpha (px+6)",
}


def coverage(sat: int, key_sat: int, hue_excess: int) -> int:
    """f, exactly as the workers compute it."""
    k = max(key_sat, 1)
    return max(hue_excess, c_div((k - sat) << 12, k))


def unmix(c: int, key_c: int, f: int) -> int:
    """One chroma channel of the correction, clamps included."""
    out = key_c + c_div((c - key_c) << 12, f)
    return max(-2048, min(2048, out))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    dump_range(img, *SPILL, label="色彩補正 + 透過補正 (worker 0x100130b0)",
               annotations=ANNOTATIONS)

    print("\n--- 2. the two different key_sat values ---")
    print("  0x10013142  imul eax, edx      sat_range uses the RAW max(|cb|,|cr|)")
    print("  0x10013157  mov [esp+0x38], 1  ... and only then is it clamped to >= 1")
    print("  The clamp exists for the divide below and for nothing else; the band")
    print("  keeps the raw value. Only an achromatic key colour tells them apart,")
    print("  and it is worth spelling out what that does, because the eyedropper is")
    print("  perfectly happy to pick a black or white pixel:")
    print(f"    {'pixel':>16}{'sat':>6}{'d':>8}{'f':>8}   result")
    for cb, cr, what in ((0, 0, "grey"), (40, 0, "nearly grey"), (700, -300, "saturated")):
        sat = max(abs(cb), abs(cr))
        d = 8 * sat                     # sat_range = 0, and the hue term is 0 at cb>=0
        f = coverage(sat, 0, 0)
        print(f"    {f'({cb},{cr})':>16}{sat:>6}{d:>8}{f:>8}   "
              f"{'erased' if d == 0 else 'kept' if d >= 4096 else 'attenuated'}, "
              f"{'no' if not 1 < f < 4096 else 'some'} chroma correction   {what}")
    print("  key_sat = 0 forces sat_range = 0 whatever 彩度範囲 says, so the metric")
    print("  collapses to d = 8*sat: an achromatic key colour keys *greyness*, not a")
    print("  hue. That is a coherent effect, but it is not what the UI suggests.")

    print("\n--- 3. does the un-mix invert a mix? ---")
    key_cb, key_cr = -512, -256          # a plausible green
    key_sat = max(abs(key_cb), abs(key_cr))
    print(f"  key = (cb {key_cb}, cr {key_cr}), key_sat = {key_sat}")
    for fg_cb, fg_cr, label in ((0, 0, "grey foreground"), (300, 400, "a red-ish one")):
        print(f"\n  {label}: fg = (cb {fg_cb}, cr {fg_cr})")
        print(f"    {'c':>6}{'mixed (cb,cr)':>18}{'f':>7}{'f/4096':>9}"
              f"{'corrected':>18}   error")
        for pct in (10, 25, 50, 75, 90):
            c = pct / 100
            cb = round(c * fg_cb + (1 - c) * key_cb)
            cr = round(c * fg_cr + (1 - c) * key_cr)
            f = coverage(max(abs(cb), abs(cr)), key_sat, 0)
            out = (unmix(cb, key_cb, f), unmix(cr, key_cr, f)) if 1 < f < 4096 else (cb, cr)
            err = (out[0] - fg_cb, out[1] - fg_cr)
            print(f"    {c:>6.2f}{f'({cb},{cr})':>18}{f:>7}{f / 4096:>9.3f}"
                  f"{f'({out[0]},{out[1]})':>18}   {err}")
    print("\n  Exact for the grey foreground: with fg chroma 0 the mixed saturation is")
    print("  (1-c)*key_sat, so f/4096 recovers c on the nose and the division undoes")
    print("  the mix. For a coloured foreground the mixed saturation is not (1-c)*")
    print("  key_sat any more, f is wrong, and the correction over- or under-shoots.")
    print("  This is the model 色彩補正 embodies: 'whatever is not key colour was")
    print("  grey'. It is right for hair and smoke against a green screen and wrong")
    print("  for a red jacket, which is why it is optional.")

    print("\n--- 4. is the +-2048 clamp reachable? ---")
    print(f"  {'f':>7}{'raw cb\'':>14}{'written':>10}{'clamped?':>10}")
    for f in (4095, 2048, 512, 64, 8, 2):
        raw = key_cb + c_div((0 - key_cb) << 12, f)
        print(f"  {f:>7}{raw:>14}{max(-2048, min(2048, raw)):>10}"
              f"{'yes' if abs(raw) > 2048 else 'no':>10}")
    print("  A grey pixel sitting on a strong key needs f >= 1024 to stay in range;")
    print("  below that the clamp fires and the corrected chroma saturates at the")
    print("  edge of the Cb/Cr range instead of running away. The gate `f > 1` is the")
    print("  only thing between this and a divide by zero.")

    print("\n--- 透過補正, on its own terms ---")
    print(f"  {'f':>7}{'alpha in':>10}{'alpha out':>11}")
    for f in (4096, 3072, 2048, 1024, 0):
        a = 4096
        print(f"  {f:>7}{a:>10}{(a if f >= 4096 else sar(f * a, 12)):>11}")
    print("  Note this multiplies the alpha the keying step already produced, so a")
    print("  pixel can be attenuated twice: once by d (the key distance) and once by")
    print("  f (the coverage estimate). They are different numbers - d folds in the")
    print("  saturation term at 8x weight, f does not.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
