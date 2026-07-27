"""Nail down the range handling of the 拡散速度 curve pair - what is clamped
on the way in, and what is deliberately left unclamped on the way out.

    forward (sub_100705c0, once before the 6 blur passes)
        y_in   = clamp(src.y, 0, 4096)          <-- clamped BEFORE the pow
        out.y  = (f32) pow(base, y_in/16) - 1
        out.cb = clamp((src.cb + 8) >> 4, -128, 127)   (signed byte)
        out.cr = clamp((src.cr + 8) >> 4, -128, 127)

    inverse (sub_10070780, once after the 6 blur passes)
        y_out  = round(16 * ln(sum + 1) / ln(base))    <-- NOT clamped
        stored with `mov word [esi], ax`, i.e. the low 16 bits of the int
        out.cb = cb_byte << 4;  out.cr = cr_byte << 4

The asymmetry is the point. The input clamp means the exponent can never
exceed 256 no matter what the extraction produced, but the output is written
straight back as a 16-bit PIXEL_YC luma with no ceiling, so the glow buffer
routinely ends up brighter than 4096 (full white) after a strong diffusion
speed. Downstream that over-range luma is what the object composite feeds
into its alpha, and what finally gets clipped per channel during YCbCr->RGB -
clipping R and G while a saturated Cb still pulls B down, which is how a red
glow lands on yellow rather than on red.

The 6-byte record the two workers share is {float y; int8 cb; int8 cr},
occupying the same 6 bytes per pixel as a PIXEL_YC - the forward pass
rewrites the buffer in place into that layout and the inverse pass turns it
back into a real PIXEL_YC.

Run via main.py:
    uv run main.py inspect/glow/verify_curve_clamp.py
"""

import math

from tools.disasm import dump_all
from tools.pe_image import PEImage

FORWARD_WORKER = (0x10070640, 0xA0)   # per-pixel body of sub_100705c0
INVERSE_WORKER = (0x100707EB, 0x40)   # per-pixel body of sub_10070780

ANNOTATIONS = {
    0x10070642: "eax = src.cb", 0x10070646: "ebx = src.cr", 0x1007064A: "ecx = src.y",
    0x1007064D: "cb + 8", 0x10070650: "cr + 8",
    0x10070653: ">> 4  (chroma scaled into signed-byte range)",
    0x10070659: "y > 4096 ?",
    0x10070669: "clamp y to 4096  <-- the pow exponent can never exceed 256",
    0x10070673: "y < 0 ?", 0x10070677: "clamp y to 0",
    0x1007067F: "cb > 127 ?", 0x1007068E: "cb < -128 ?",
    0x1007069B: "cr > 127 ?", 0x100706A7: "cr < -128 ?",
    0x100706B1: "push base (double, from sub_10070550)",
    0x100706B5: "load the clamped y as an integer",
    0x100706B9: "* 0.0625 = y/16 -> the exponent, 0..256",
    0x100706BF: "call pow(base, y/16)",
    0x100706C4: "- 1.0f",
    0x100706CE: "store cr byte at +5", 0x100706D1: "store cb byte at +4",
    0x100706D8: "store the f32 curved luma at +0 (record is {f32 y; i8 cb; i8 cr})",
    0x100707EB: "load the accumulated f32 sum",
    0x100707ED: "+ 1.0f",
    0x100707F3: "fldln2 / fyl2x -> ln(sum + 1)",
    0x100707F9: "* (16 / ln(base))",
    0x100707FB: "+ 0.5 then truncate = round to nearest",
    0x1007080B: "store y' with `mov word` - NO clamp, values above 4096 survive",
    0x10070813: "cb byte << 4", 0x10070816: "cr byte << 4",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "sub_100705c0 per-pixel body (forward curve)": FORWARD_WORKER,
        "sub_10070780 per-pixel body (inverse curve)": INVERSE_WORKER,
    }, annotations=ANNOTATIONS, mnemonic_width=7)

    print(
        "\nWhat the two clamps do to a real case (light color #f00, strength 60,\n"
        "threshold 20, diffusion speed 60 -> base = 1.06), in the middle of a flat\n"
        "white area where each blur pass reproduces the same value:"
    )
    base = 1.06
    brightness = ((4095 - 819) * 2457) >> 12          # extraction, see verify_strength_threshold.py
    for label, glow_y in (("light color applied (colorY=1224)", (1224 * brightness) >> 12),
                          ("light color NOT applied (a port bug)", brightness)):
        y_in = max(0, min(4096, glow_y))
        curved = base ** (y_in / 16.0) - 1.0
        total = curved * 6
        y_out = int(16 * math.log(total + 1.0) / math.log(base) + 0.5)
        print(f"  {label}:")
        print(f"    glow luma in = {glow_y:5d} -> curved = {curved:12.3f}"
              f" -> sum of 6 = {total:13.3f} -> y' = {y_out:6d}"
              f"  ({'over' if y_out > 4096 else 'under'} 4096)")

    print(
        "\n"
        "Verdict: the forward transform clamps its input to [0,4096] before the pow,\n"
        "and the inverse writes its result back unclamped as a 16-bit luma. Both\n"
        "matter for a port: the first bounds the exponent, the second is what lets the\n"
        "glow exceed full white and clip in RGB later. And because the exponent is\n"
        "taken from the *extracted glow luma*, which already includes the light\n"
        "colour's Y (verify_extract_alpha.py), applying that colour factor after the\n"
        "curve instead of before it changes the result by orders of magnitude - see\n"
        "the two rows above.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
