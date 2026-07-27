"""The composite: how the blurred image is put back on top of the original.

This is where 拡散光 differs from 発光. 発光 extracts the bright parts first
and then adds the blurred extract. 拡散光 blurs the image *as it is* and then
merges the blur back with a rule that only ever brightens:

    d = gy - max(0, premultiplied source luma)
    if d <= 0:  the pixel is left exactly as it was

so the diffused layer is visible only where the blur came out brighter than
what was already there. That is what makes bright areas bleed into their
surroundings without the whole frame turning into a smear, with no threshold
parameter anywhere in the filter.

Where it does win, the chroma is a luma-weighted blend rather than a straight
replacement:

    base   = gy - d                      (what the source itself contributed)
    cb_mix = (premul(src.cb) * base + d * gcb) / gy

i.e. the pixel keeps its own hue in proportion to how much of the final luma
it was already providing, and takes the blurred hue for the rest.

Only then does 強さ come in, and the two halves spell it differently:

  * object effect - a textbook source-over of a (gy, cb_mix, cr_mix) pixel at
    opacity `ga` onto the original, with three shortcuts spliced in for
    ga >= 4096, src.a >= 4096 and src.a <= 0. The resulting alpha is
    ga + src.a - src.a*ga/4096, computed as
    `(0x1000800 - (4096-src.a)*(4096-ga)) >> 12`.
  * frame filter - no alpha to compose, so a plain lerp toward the merged
    pixel.

Nothing in either path clamps the output, and nothing has to: gy is an average
of values already in range, and the source-over alpha cannot exceed 4096.

Run via main.py:
    uv run main.py inspect/diffusion_light/verify_composite.py
"""

from tools.cints import c_div
from tools.disasm import dump_all
from tools.pe_image import PEImage

OBJECT_COMPOSITE = (0x1001CD7C, 0x20B)
FRAME_COMPOSITE = (0x1001E896, 0xA8)

ANNOTATIONS = {
    0x1001CD7D: "st0 = sum_a",
    0x1001CD81: "sum_a / kernel width",
    0x1001CD83: "st0 = sum_cr",
    0x1001CD8F: "* strength ...",
    0x1001CD96: "... >> 12",
    0x1001CD99: "ga = opacity of the diffused layer",
    0x1001CD9D: "_ftol -> gcr",
    0x1001CDB2: "-> gcb",
    0x1001CDC7: "-> gy",
    0x1001CDD2: "gy <= 0: nothing to add, leave the pixel alone",
    0x1001CDD8: "ebx = src.y",
    0x1001CDDB: "eax = src.a",
    0x1001CDE1: "src.y * src.a ...",
    0x1001CDE4: "... >> 12 = the source's premultiplied luma",
    0x1001CDE7: "negate",
    0x1001CDEB: "clamp to <= 0, i.e. -max(0, premul_y)",
    0x1001CDEF: "d = gy - max(0, premul_y)",
    0x1001CDF7: "d > 0 ?",
    0x1001CDF9: "no: copy the source pixel through - the filter never darkens anything",
    0x1001CE0E: "base = gy - d = max(0, premul_y)",
    0x1001CE10: "d * gcb",
    0x1001CE1D: "src.cb * src.a ...",
    0x1001CE20: "... >> 12",
    0x1001CE23: "* base",
    0x1001CE28: "+ d * gcb",
    0x1001CE2B: "/ gy -> cb_mix",
    0x1001CE50: "the same for cr -> cr_mix",
    0x1001CE56: "ga >= 4096 ?",
    0x1001CE66: "yes: out = (gy, cb_mix, cr_mix, 4096), no blend at all",
    0x1001CE85: "src.a >= 4096 ?",
    0x1001CE92: "yes: gy * ga ...",
    0x1001CE9A: "... + src.y * (4096 - ga) ...",
    0x1001CEA3: "... >> 12: a plain lerp, because there is no transparency to compose",
    0x1001CED0: "and the result stays fully opaque",
    0x1001CEDB: "src.a <= 0 ?",
    0x1001CEE3: "yes: pure diffusion at opacity ga",
    0x1001CEFC: "otherwise, the general case:",
    0x1001CF01: "ia = 4096 - ga",
    0x1001CF08: "4096 - src.a",
    0x1001CF0A: "4096*4096 + 2048 (the +2048 is the rounding bias)",
    0x1001CF0F: "(4096 - src.a) * ia",
    0x1001CF12: "subtract",
    0x1001CF1C: ">> 12 -> na, the source-over alpha",
    0x1001CF1F: "w_src  = ia * src.a / na",
    0x1001CF2D: "w_luminous = (ga << 12) / na",
    0x1001CF39: "src.y * w_src + gy * w_luminous ...",
    0x1001CF3F: "... >> 12",
    0x1001CF68: "out.a = na",
    0x1001CF79: "the untouched path: 8 bytes copied straight across",
    # --- frame filter
    0x1001E896: "esi = gy (a plain box average here, no alpha to un-premultiply)",
    0x1001E89A: "gy <= 0: leave the pixel",
    0x1001E8A0: "ebx = src.y",
    0x1001E8A3: "negate ...",
    0x1001E8A9: "... clamped to <= 0",
    0x1001E8AB: "d = gy - max(0, src.y)",
    0x1001E8AF: "d <= 0: leave the pixel - same 'never darkens' rule",
    0x1001E8BB: "base = gy - d",
    0x1001E8C1: "src.cb * base",
    0x1001E8CB: "d * gcb",
    0x1001E8D3: "/ gy -> cb_mix",
    0x1001E8E3: "/ gy -> cr_mix",
    0x1001E8E5: "強さ = 100.0 ?",
    0x1001E8ED: "yes: take the merged pixel outright",
    0x1001E8FA: "no: lerp from the source toward it by strength",
}


def merge(src, gy, gcb, gcr, premultiply: bool):
    """The shared part: the 'only brighten' test and the chroma blend.
    Returns None when the pixel is to be left alone."""
    s_y, s_cb, s_cr, s_a = src
    if gy <= 0:
        return None
    py = (s_y * s_a) >> 12 if premultiply else s_y
    d = gy - max(0, py)
    if d <= 0:
        return None
    base = gy - d
    pcb = (s_cb * s_a) >> 12 if premultiply else s_cb
    pcr = (s_cr * s_a) >> 12 if premultiply else s_cr
    return gy, c_div(pcb * base + d * gcb, gy), c_div(pcr * base + d * gcr, gy)


def composite_object(src, gy, gcb, gcr, ga):
    """Replay of 0x1001cdd8-0x1001cf83."""
    s_y, s_cb, s_cr, s_a = src
    merged = merge(src, gy, gcb, gcr, premultiply=True)
    if merged is None:
        return src
    gy, cb_mix, cr_mix = merged
    if ga >= 0x1000:
        return gy, cb_mix, cr_mix, 0x1000
    if s_a >= 0x1000:
        ia = 0x1000 - ga
        return ((s_y * ia + gy * ga) >> 12, (s_cb * ia + cb_mix * ga) >> 12,
                (s_cr * ia + cr_mix * ga) >> 12, 0x1000)
    if s_a <= 0:
        return gy, cb_mix, cr_mix, ga
    ia = 0x1000 - ga
    na = (0x1000800 - (0x1000 - s_a) * ia) >> 12
    w_src = c_div(ia * s_a, na)
    w_luminous = c_div(ga << 12, na)
    return ((s_y * w_src + gy * w_luminous) >> 12, (s_cb * w_src + cb_mix * w_luminous) >> 12,
            (s_cr * w_src + cr_mix * w_luminous) >> 12, na)


def composite_frame(src, gy, gcb, gcr, strength):
    """Replay of 0x1001e898-0x1001e935. `src` carries a dummy alpha."""
    merged = merge(src, gy, gcb, gcr, premultiply=False)
    if merged is None:
        return src[:3]
    if strength >= 0x1000:
        return merged
    return tuple(c + (((m - c) * strength) >> 12) for c, m in zip(src[:3], merged))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "0x1001cb10: object composite (identical copies live in the other four loops)":
            OBJECT_COMPOSITE,
        "0x1001e770: frame composite": FRAME_COMPOSITE,
    }, annotations=ANNOTATIONS)

    print("\n--- the source-over alpha really is ga + a - a*ga/4096 ---")
    worst = 0
    for a in range(1, 0x1000):
        for ga in range(1, 0x1000, 37):
            na = (0x1000800 - (0x1000 - a) * (0x1000 - ga)) >> 12
            worst = max(worst, abs(na - (ga + a - (a * ga) // 4096)))
    print(f"  max deviation from ga + a - floor(a*ga/4096) over a=1..4095: {worst}"
          f"  (the +2048 makes it round instead of truncate)")

    print("\n--- object effect: an opaque grey source under a brighter diffusion ---")
    print(f"  {'src':>22} {'gy':>6} {'ga':>6}  ->  out")
    src = (1200, 300, -200, 4096)
    for gy in (600, 1200, 1201, 2500, 4096):
        out = composite_object(src, gy, 0, 0, 2048)
        note = "  <- unchanged: the blur is not brighter" if out == src else ""
        print(f"  {str(src):>22} {gy:6d} {2048:6d}  ->  {out}{note}")

    print("\n--- object effect: the same diffusion over sources of varying alpha ---")
    print("  (gy=2500, gcb=400, gcr=-300, ga=2048)")
    for s_a in (0, 1024, 2048, 4095, 4096):
        out = composite_object((1200, 300, -200, s_a), 2500, 400, -300, 2048)
        print(f"  src.a={s_a:5d}  ->  y={out[0]:5d} cb={out[1]:5d} cr={out[2]:5d} a={out[3]:5d}")
    print("  src.a=0 gives the diffused colour at exactly ga, i.e. the halo outside the")
    print("  object; src.a=4096 keeps alpha at 4096 and just lerps the colour.")

    print("\n--- the chroma blend: a red source lit by a blue-ish diffusion ---")
    print("  (src.y varies, so `base` varies, so the hue mixes differently each time)")
    for s_y in (0, 500, 1500, 2400):
        out = composite_object((s_y, -300, 700, 4096), 2500, 600, -400, 4096)
        print(f"  src.y={s_y:5d} (cb=-300 cr=700)  ->  y={out[0]:5d} cb={out[1]:5d} "
              f"cr={out[2]:5d}   base/gy = {max(0, s_y) / 2500:.2f}")
    print("  at src.y=0 the output takes the diffused chroma outright; as the source")
    print("  gets closer to gy its own chroma dominates, and at src.y >= gy the pixel")
    print("  is not written at all.")

    print("\n--- frame filter: same rule, no alpha ---")
    for s_y in (0, 1000, 2000, 2500, 3000):
        out = composite_frame((s_y, -300, 700, 0), 2500, 600, -400, 2048)
        print(f"  src.y={s_y:5d}  強さ=50.0  ->  y={out[0]:5d} cb={out[1]:5d} cr={out[2]:5d}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
