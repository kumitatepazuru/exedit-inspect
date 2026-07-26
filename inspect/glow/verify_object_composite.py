"""Show that the object-effect composite is an alpha-aware blend, not the
per-channel addition the frame-filter composite uses.

The glow accumulator holds 6-byte PIXEL_YC values, but an object's image is
8-byte PIXEL_YCA. sub_10053890 bridges the two by treating the glow's *luma*
as the glow layer's alpha, and un-premultiplying the colour by the resulting
alpha:

    a = dst.a
    if a >= 4096:                      # opaque - and only here is it a plain add
        dst.y += g.y;  dst.cb += g.cb;  dst.cr += g.cr        (no clamping)
    elif a <= 0:                       # fully transparent
        na = g.y;  if na <= 0: leave the pixel alone
        na = min(na, 4096)
        dst.y  = (g.y  << 12) / na
        dst.cb = (g.cb << 12) / na
        dst.cr = (g.cr << 12) / na
        dst.a  = na
    else:                              # partially covered
        na = a + g.y;  if na <= 0: leave the pixel alone
        na = min(na, 4096)
        dst.y  = (dst.y  * a + (g.y  << 12)) / na
        dst.cb = (dst.cb * a + (g.cb << 12)) / na
        dst.cr = (dst.cr * a + (g.cr << 12)) / na
        dst.a  = na

So the glow behaves as a layer whose coverage is its own luma (saturating at
4096) and whose premultiplied colour is the accumulator value, composited
with *additive* alpha - not the usual a + b - a*b. Note also that the opaque
branch never clamps, so an object's interior can end up with y well past
4096; the clipping only happens when exedit finally converts YCA to RGB.

sub_10053800, the frame-filter composite, is printed alongside for contrast:
frames have no alpha, so it is a straight `add word` of all three channels.

Run via main.py:
    uv run main.py inspect/glow/verify_object_composite.py
"""

import capstone
import pefile

COMPOSITE_OBJECT = (0x10053890, 0x1A0)
COMPOSITE_FRAME = (0x10053800, 0x90)

ANNOTATIONS = {
    0x1005392A: "ebx = dst.a (PIXEL_YCA alpha at +6)",
    0x1005392E: "compare alpha against 4096 (fully opaque?)",
    0x10053936: "--- opaque branch: plain 16-bit add of y/cb/cr, no clamp ---",
    0x10053951: "test alpha <= 0",
    0x10053955: "--- transparent branch: new alpha = glow luma ---",
    0x10053962: "clamp new alpha to 4096",
    0x1005396F: "(glow.y << 12) / new_alpha  -> un-premultiplied luma",
    0x1005398F: "--- partial branch: new alpha = dst.a + glow luma ---",
    0x100539A6: "(dst.y * dst.a + (glow.y << 12)) / new_alpha",
    0x100539E1: "store new alpha into dst.a",
    0x100539F0: "advance dst by 8 bytes (PIXEL_YCA)",
    0x100539ED: "advance glow accumulator by 6 bytes (PIXEL_YC)",
    0x10053855: "frame path: dst = fpip->ycp_edit (+4)",
    0x10053858: "frame path: src = the glow accumulator *(fpip+0xB0)",
    0x10053866: "--- frame path: unconditional per-channel add, no alpha involved ---",
}


def _dump(md, image_base, data, start, size, label):
    print(f"\n--- {label} @ 0x{start:08x} ---")
    code = data[start - image_base:start - image_base + size]
    for insn in md.disasm(code, start):
        note = ANNOTATIONS.get(insn.address, "")
        marker = f"    <-- {note}" if note else ""
        print(f"0x{insn.address:08x}: {insn.mnemonic:7s} {insn.op_str}{marker}")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    _dump(md, image_base, data, *COMPOSITE_OBJECT,
          "sub_10053890 (object effect: alpha-aware composite onto *(fpip+0xAC))")
    _dump(md, image_base, data, *COMPOSITE_FRAME,
          "sub_10053800 (frame filter: plain add into fpip->ycp_edit)")

    print(
        "\n"
        "Verdict: only the opaque case is additive. Everywhere else the glow's luma\n"
        "becomes the layer's alpha and the colour is divided by the combined alpha,\n"
        "with the alphas *added* (then clamped to 4096) rather than combined with the\n"
        "usual a + b - a*b. A port that composites the glow additively will match on an\n"
        "opaque interior and drift everywhere the object is transparent or antialiased.\n"
        "\n"
        "Equivalence note: over a fully transparent destination the result is\n"
        "  colour = glow / min(glow.y, 4096),  alpha = min(glow.y, 4096)\n"
        "whose premultiplied product is just `glow` again - so the difference only\n"
        "shows up once something is composited behind or below it, or once the alpha\n"
        "saturates. Because that saturation point is glow.y = 4096 and glow.y already\n"
        "carries the light colour's Y factor (verify_extract_alpha.py), a dark light\n"
        "colour keeps the halo translucent far longer than a naive port would.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
