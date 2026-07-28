"""The final composite, and what `光成分のみ` actually leaves behind.

The accumulation buffer is not an image yet when the shape workers are done:
it holds *premultiplied* glow in (y, cb, cr) and an alpha of 4096 everywhere,
put there by the `table[0x48]` clear at 0x1005516c. `sub_10058aa0` is what turns
it into a PIXEL_YCA image, and it does three different things depending on what
is underneath (0x10058b3e splits the rows, 0x10058bc1/0x10058cda the columns):

  glow only (the 2*rx by 2*ry margin, and any pixel whose source alpha is 0)

      if g.y <= 0:  (0, 0, 0, 0)
      else:         a = min(g.y, 4096)
                    (c_div(g.y << 12, a), c_div(g.cb << 12, a), c_div(g.cr << 12, a), a)

  opaque source (src.a >= 4096)

      dst.y += src.y ; dst.cb += src.cb ; dst.cr += src.cr ; dst.a = src.a

  semi-transparent source (0 < src.a < 4096)

      na = min(g.y + src.a, 4096)
      dst.c = c_div(src.c * src.a + (g.c << 12), na)     # y / cb / cr alike
      dst.a = na

The first branch is the amplify-unpremultiply 閃光 ends on
([`閃光` §5](../glint/README.md)) and the last two are 発光's composite with the
roles swapped - there the glow was the source, here it is the destination
([`発光` §6](../luminous/README.md)).

Section 3 is the finding that is easy to miss: `光成分のみ` skips this worker
entirely (0x1005548e), and nothing else ever writes the alpha channel, so the
result is the buffer as `table[0x48]` left it - **opaque** black with the glow
drawn on it, not a transparent glow layer.

The frame filter's composite (`sub_10058de0`) is four instructions long: a
16-bit `add` per channel with no clamp, reading the glow at `(rx, ry)` so the
margin is simply discarded.

Run via main.py:
    uv run main.py inspect/glow/verify_composite.py
"""

from tools.cints import c_div
from tools.disasm import disasm_range, dump_all
from tools.pe_image import PEImage

GLOW_ONLY = (0x10058D7A, 0x52)
OPAQUE = (0x10058BD4, 0x2B)
SEMI = (0x10058C51, 0x6B)
SKIP = (0x10055481, 0x22)
FRAME = (0x10058E52, 0x32)

ANNOTATIONS = {
    0x10058D7A: "esi = eax = glow.y",
    0x10058D83: "g.y <= 0 -> fully transparent, nothing of the glow survives",
    0x10058D8B: "a = min(g.y, 4096) ...",
    0x10058D92: "... and the colour is divided by it: un-premultiply",
    0x10058D98: "dst.a = a. the glow's own brightness IS the opacity",
    0x10058DBD: "the g.y <= 0 case writes (0,0,0,0)",
    0x10058BD4: "edi = src.a",
    0x10058BD8: "src.a >= 4096 ?",
    0x10058BE3: "yes: dst.y += src.y, no clamp, 16-bit wraparound",
    0x10058BF6: "dst.a = src.a. the object stays opaque and the glow is added on top",
    0x10058C4F: "(the src.a <= 0 case falls into the glow-only path above)",
    0x10058C51: "edx = glow.y",
    0x10058C56: "na = glow.y + src.a",
    0x10058C5B: "na <= 0 -> write zeros",
    0x10058C65: "na = min(na, 4096)",
    0x10058C6D: "src.y * src.a ...",
    0x10058C70: "... + (glow.y << 12) ...",
    0x10058C76: "... / na",
    0x10058CA2: "dst.a = na",
    0x10055486: "eax = fp->check",
    0x10055489: "ecx = check[2] = 光成分のみ",
    0x1005548E: "非0 -> skip sub_10058aa0 entirely",
    0x10058E52: "edx = fpip+0xB0, offset by (rx, ry): the margin is dropped",
    0x10058E64: "16-bit add, y ...",
    0x10058E6D: "... cb ...",
    0x10058E75: "... cr. no alpha, no clamp, no threshold",
}


def glow_only(g: tuple) -> tuple:
    """0x10058d7a and its two duplicates at 0x10058b61 / 0x10058ce0."""
    gy = g[0]
    if gy <= 0:
        return 0, 0, 0, 0
    a = min(gy, 4096)
    return c_div(gy << 12, a), c_div(g[1] << 12, a), c_div(g[2] << 12, a), a


def over_source(g: tuple, src: tuple) -> tuple:
    """0x10058bd4 / 0x10058c51: the object is under the glow."""
    sa = src[3]
    if sa >= 4096:
        return g[0] + src[0], g[1] + src[1], g[2] + src[2], sa
    if sa <= 0:
        return glow_only(g)
    na = g[0] + sa
    if na <= 0:
        return 0, 0, 0, 0
    na = min(na, 4096)
    return tuple(c_div(src[i] * sa + (g[i] << 12), na) for i in range(3)) + (na,)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "composite: glow only (no source pixel under it)": GLOW_ONLY,
        "composite: opaque source": OPAQUE,
        "composite: semi-transparent source": SEMI,
        "光成分のみ skips the whole worker": SKIP,
        "frame filter composite": FRAME,
    }, annotations=ANNOTATIONS)

    print("\n--- 1. glow-only pixels: brightness becomes opacity ---")
    print(f"  {'glow (y,cb,cr)':>22}{'out (y,cb,cr,a)':>30}   note")
    for g in ((0, 0, 0), (1024, -256, 512), (4096, -1024, 2048),
              (6000, -1500, 3000), (8192, -2048, 4096)):
        out = glow_only(g)
        note = ("transparent" if out[3] == 0 else
                "alpha saturated, luma stays super-white" if g[0] > 4096 else
                f"alpha = luma = {out[3]}")
        print(f"  {str(g):>22}{str(out):>30}   {note}")
    print("  below 4096 this is an exact un-premultiply: the colour is divided by")
    print("  the same number that becomes the alpha, so re-multiplying at draw time")
    print("  gives the value back. Above 4096 alpha clips and the excess stays in")
    print("  the luma - the 4096..8192 band the accumulate step allows is super-white.")

    print("\n--- 1b. the faint fringe: chroma is amplified by 4096/a ---")
    print("  the same divide that un-premultiplies also multiplies whatever rounding")
    print("  error the accumulate step's three independent `sar 4`s left behind. At")
    print("  the outer edge of a glow, where a is single digits, that factor is huge:")
    print(f"  {'glow (y,cb,cr)':>22}{'out':>30}{'chroma x':>10}")
    for g in ((1, 9, -2), (2, 15, -3), (8, 35, -6), (64, 281, -46), (1024, 4500, -740)):
        out = glow_only(g)
        print(f"  {str(g):>22}{str(out):>30}{4096 // max(1, min(g[0], 4096)):>9}x"
              + ("   <- int16 overflow" if not -32768 <= out[1] <= 32767 else ""))
    print("  int16 has room for about 4096 * 8 in chroma, so a strongly coloured glow")
    print("  can wrap in its faintest pixels. Whether that is visible depends on the")
    print("  YCbCr->RGB clip in aviutl.exe ([`rgb_ycbcr.md` §3](../common/rgb_ycbcr.md)).")

    print("\n--- 2. with an object underneath ---")
    src = (2000, 400, -300, 4096)
    print(f"  opaque source {src}:")
    for g in ((0, 0, 0), (1000, 100, -50), (8192, -2048, 4096)):
        print(f"    glow {str(g):>22} -> {over_source(g, src)}")
    print("  a pure add. dst.a comes from the source, so the glow cannot make an")
    print("  opaque pixel any more opaque - it only makes it brighter, and nothing")
    print("  clamps the 16-bit store.")
    print("\n  semi-transparent source, alpha 2048:")
    src = (2000, 400, -300, 2048)
    for g in ((0, 0, 0), (500, 50, -20), (2048, 200, -100), (4000, 0, 0)):
        print(f"    glow {str(g):>22} -> {over_source(g, src)}")
    print("  alpha is a plain SUM clipped at 4096, not the usual a+b-ab. The colour")
    print("  is the premultiplied average of the two, so a bright glow pulls a faint")
    print("  object's colour toward the glow's own.")

    print("\n--- 3. 光成分のみ: what the buffer looks like when nobody converts it ---")
    print("  who writes the alpha channel at all? scanning every worker for a store")
    print("  to offset 6 of a pixel:")
    img = PEImage(dll_path)
    for label, addr, size in (("extract, object, 指定なし", 0x10055540, 0x150),
                              ("extract, object, 指定あり", 0x10055690, 0x110),
                              ("extract, frame, 指定なし", 0x100557A0, 0x140),
                              ("extract, frame, 指定あり", 0x100558E0, 0x130),
                              ("通常: vertical", 0x10055A10, 0x260),
                              ("通常: horizontal", 0x10055ED0, 0x350),
                              ("ぼかし tail: horizontal", 0x10055C70, 0x260),
                              ("ライン(縦)", 0x10056220, 0x460),
                              ("ライン(横)", 0x100569E0, 0x420),
                              ("accumulate helper", 0x10056680, 0x73),
                              ("composite (object)", 0x10058AA0, 0x340)):
        n = sum(1 for insn, _ in disasm_range(img, addr, size, resolve=False)
                if insn.mnemonic == "mov" and "word ptr [" in insn.op_str
                and "+ 6]" in insn.op_str and insn.op_str.startswith("word ptr"))
        print(f"    {label:<26} {n} store(s) to +6")
    print("  only the four extraction workers (which write 4096 into the scratch)")
    print("  and the composite touch it. So with 光成分のみ on, the alpha is whatever")
    print("  table[0x48] left at 0x1005516c:")
    print(f"  {'pixel':>28}{'without 光成分のみ':>26}{'with it':>26}")
    for g in ((0, 0, 0), (1024, -256, 512), (8192, -2048, 4096)):
        print(f"  {str(g):>28}{str(glow_only(g)):>26}{str(g + (4096,)):>26}")
    print("  i.e. an OPAQUE canvas: the glow is still premultiplied, the background")
    print("  is opaque black, and the object itself is gone. Useful as an additive")
    print("  layer, a black box under normal alpha blending.")

    print("\n--- 4. the frame filter just adds ---")
    print(f"  {'frame px':>18}{'glow':>22}{'out':>22}")
    for f, g in (((1000, 0, 0), (500, 100, -50)),
                 ((4000, 0, 0), (8192, -2048, 4096))):
        print(f"  {str(f):>18}{str(g):>22}{str(tuple(a + b for a, b in zip(f, g))):>22}")
    print("  16-bit `add word ptr`, no clamp and no threshold: a frame-wide glow can")
    print("  push luma past full white and it is the display conversion in")
    print("  aviutl.exe that decides what that looks like.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
