"""Show exactly what the four brightness-extraction workers compute, and in
particular that the object-effect ones weight luma by the source alpha
before comparing it against the threshold.

This matters for a port: an object's transparent (or partially covered)
pixels normally still carry a full-intensity RGB value in a straight-alpha
pipeline, so a port that thresholds on plain luma will extract glow from
areas AviUtl treats as empty, producing a haze around every object. AviUtl
multiplies first:

    y_eff = (src.y * src.a) >> 12          (object effect only)
    diff  = y_eff - threshold
    brightness = 0                                   if diff < 0
               = min((diff * gain >> 12) + overflow, 4096)  otherwise

Note the asymmetry: only luma is alpha-weighted. Chroma is taken raw from
the source pixel and merely scaled by `brightness`.

The frame-filter workers have no alpha to weight by (PIXEL_YC is 3 shorts),
so they threshold on src.y directly - which is why the two pairs must not
be treated as interchangeable.

The two workers within each pair differ only in where the output chroma
comes from (bit24 of ex_data): the source pixel's own cb/cr, or the picked
light color. In the picked-color case the light color's *Y* scales the
output luma too, i.e. a dark light color produces a proportionally dimmer
glow - see the `g_101b2004` multiply below.

Run via main.py:
    uv run main.py inspect/glow/verify_extract_alpha.py
"""

import capstone
import pefile

# object-effect pair: source is *(fpip+0xAC), 8 bytes/pixel, alpha at +6
EXTRACT_OBJECT_SRC_COLOR = (0x10053639, 0x70)   # bit24 SET: keep the source pixel's chroma
EXTRACT_OBJECT_PICKED = (0x10053761, 0x80)      # bit24 CLEAR: replace with the picked color
# frame-filter pair: source is fpip->ycp_edit, 6 bytes/pixel, no alpha at all
EXTRACT_FRAME_SRC_COLOR = (0x10053433, 0x60)

GLOBALS = {
    0x101B1FE4: "strength gain (clamped to 4096)",
    0x101B200C: "strength overflow (raw fixed-point above 4096)",
    0x101B2008: "threshold (raw*4096/1000)",
    0x101B2004: "picked light color Y",
    0x101B1FF4: "picked light color Cb",
    0x101B1FFC: "picked light color Cr",
}


def _dump(md, image_base, data, start, size, label):
    print(f"\n--- {label} @ 0x{start:08x} ---")
    code = data[start - image_base:start - image_base + size]
    for insn in md.disasm(code, start):
        marker = ""
        for addr, name in GLOBALS.items():
            if f"0x{addr:08x}" in insn.op_str:
                marker = f"    <-- {name}"
        if insn.mnemonic == "movsx" and "+ 6]" in insn.op_str:
            marker = "    <-- src.a (PIXEL_YCA alpha, offset +6)"
        elif insn.mnemonic == "imul" and not marker:
            marker = "    <-- fixed-point multiply (result is >> 12'd next)"
        elif insn.mnemonic == "cmp" and "0x1000" in insn.op_str:
            marker = "    <-- clamp brightness at 4096"
        elif insn.mnemonic == "add" and insn.op_str in ("edi, 8", "edx, 8"):
            marker = "    <-- advance source by 8 bytes = PIXEL_YCA stride"
        elif insn.mnemonic == "add" and insn.op_str in ("edi, 6", "ecx, 6"):
            marker = "    <-- advance by 6 bytes = PIXEL_YC stride"
        print(f"0x{insn.address:08x}: {insn.mnemonic:7s} {insn.op_str}{marker}")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    _dump(md, image_base, data, *EXTRACT_OBJECT_SRC_COLOR,
          "sub_100535a0 inner loop (object effect, bit24 SET: source chroma)")
    _dump(md, image_base, data, *EXTRACT_OBJECT_PICKED,
          "sub_100536d0 inner loop (object effect, bit24 CLEAR: picked light color)")
    _dump(md, image_base, data, *EXTRACT_FRAME_SRC_COLOR,
          "sub_100533c0 inner loop (frame filter, bit24 SET: source chroma)")

    print(
        "\n"
        "Verdict:\n"
        "\n"
        "  object effect (8-byte PIXEL_YCA source)\n"
        "      y_eff      = (src.y * src.a) >> 12        <-- alpha weighting, luma only\n"
        "      diff       = y_eff - threshold\n"
        "      brightness = 0 if diff < 0 else min((diff*gain >> 12) + overflow, 4096)\n"
        "      bit24 SET  : out.y = brightness\n"
        "                   out.cb = (src.cb * brightness) >> 12   (src chroma NOT alpha-weighted)\n"
        "                   out.cr = (src.cr * brightness) >> 12\n"
        "      bit24 CLEAR: out.y  = (colorY  * brightness) >> 12\n"
        "                   out.cb = (colorCb * brightness) >> 12\n"
        "                   out.cr = (colorCr * brightness) >> 12\n"
        "\n"
        "  frame filter (6-byte PIXEL_YC source)\n"
        "      identical, except there is no alpha, so y_eff = src.y.\n"
        "\n"
        "Two consequences that are easy to miss when porting:\n"
        "  1. The alpha multiply happens BEFORE the threshold comparison, so a\n"
        "     half-covered edge pixel glows like a half-brightness pixel, and a fully\n"
        "     transparent one never glows at all no matter what colour it stores.\n"
        "  2. With a picked light color, the color's own Y scales the glow's luma. A\n"
        "     pure red light (Y = 0.299 of full) yields a glow only ~30% as luminous as\n"
        "     the same settings with white - and since the glow's luma is what the\n"
        "     composite later uses as alpha (see verify_object_composite.py) and what\n"
        "     the diffusion-speed curve exponentiates (see verify_curve_clamp.py), this\n"
        "     scaling has to be applied here, at extraction time, not at the end.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
