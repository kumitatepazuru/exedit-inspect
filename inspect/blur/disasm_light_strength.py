"""Raw capstone disassembly of the two shared helpers that implement ぼかし's
光の強さ parameter - the forward curve that runs once before the four blur
passes and the inverse curve that runs once after them.

These functions are not part of ぼかし. They are exedit-wide utilities, and
発光 drives the same pair with its 拡散速度 trackbar (which is why both
parameters top out at 60 and both are described as "slightly heavier"). The
object-effect copies below work on the 8-byte object pixel; 0x10070550 /
0x10070700 are the 6-byte frame copies of the identical math.

What the code establishes, with every float constant resolved:

  * base = 1.0 + clamp(光の強さ, 1, 100) * 0.001, so the UI range 1..60 maps
    to base 1.001..1.06 - and 光の強さ = 0 never reaches here at all, because
    func_proc skips both curves and runs the plain integer workers instead.

  * forward: the 16-bit luma is clamped to [0,4096] and replaced by the
    FLOAT pow(base, y/16) - 1, in place, reusing the same 8 bytes
    ({float y; int8 cb; int8 cr; int16 a}). The chroma is not curved at all,
    only requantised to a signed byte with (c + 8) >> 4, i.e. it loses 4 bits
    of precision for the duration of the blur.

  * inverse: y = round(ln(y + 1) * 16 / ln(base)), chroma restored by << 4.
    The luma is written back with no clamp of any kind.

  * both directions zero the whole pixel when alpha <= 0, and neither touches
    the alpha channel itself.

Because every blur pass is an AVERAGE rather than a sum, running it between
these two curves turns the arithmetic mean into a base-`base` power mean -
biased toward the brightest sample in the window. verify_light_curve.py
checks that numerically.

Run via main.py:
    uv run main.py inspect/blur/disasm_light_strength.py
"""

import re

from tools.disasm import disasm_range
from tools.pe_image import PEImage

BLOCKS = [
    (0x10070220, 0x60, "forward curve, entry (object 8-byte buffer)"),
    (0x10070290, 0x140, "forward curve, per-thread worker"),
    (0x100703F0, 0x60, "inverse curve, entry (object 8-byte buffer)"),
    (0x10070470, 0xC8, "inverse curve, per-thread worker"),
]

ANNOTATIONS = {
    0x10070220: "eax = arg4 = 光の強さ",
    0x10070227: "clamp to a minimum of 1 ...",
    0x10070236: "... and a maximum of 100 (the UI only offers 0..60)",
    0x10070240: "st0 = (double)光の強さ",
    0x1007024C: "[0x101e42f4] = arg1 = image buffer",
    0x10070255: "* 0.001",
    0x1007025D: "h >= 64 ? -> the multithread flag pushed below",
    0x10070263: "+ 1.0  =>  base",
    0x1007026A: "push worker 0x10070290",
    0x1007026F: "[0x101e4304] = arg3 = h",
    0x10070274: "[0x101e4300] = arg2 = w",
    0x1007027A: "[0x101e4318] = base (double)",

    0x1007028C: "esi = [0x10135c68] = exedit's object-buffer row stride, in pixels",
    0x100702BD: "reload base",
    0x10070311: "src.a <= 0 ? -> 0x100703b2, zero the pixel",
    0x1007031C: "eax = src.cb (int16 at +2)",
    0x10070320: "ebx = src.cr (int16 at +4)",
    0x10070324: "ecx = src.y  (int16 at +0)",
    0x10070327: "+8 then >>4 = round the chroma to the nearest 1/16",
    0x10070333: "clamp y to <= 4096 ...",
    0x1007034D: "... and >= 0, so the pow exponent stays within [0,256]",
    0x10070359: "clamp cb to [-128, 127] (it must fit in one signed byte)",
    0x10070375: "clamp cr to [-128, 127]",
    0x1007038B: "st0 = base",
    0x1007038F: "st0 = (double)y",
    0x10070393: "* 0.0625 = 1/16",
    0x10070399: "call pow(base, y/16)",
    0x1007039E: "- 1.0f",
    0x100703A8: "store cr as a signed byte at +5",
    0x100703AB: "store cb as a signed byte at +4",
    0x100703AE: "store the curved luma as a FLOAT at +0 (overwrites y and cb)",
    0x100703B2: "alpha <= 0: y = 0.0f, cb = 0, cr = 0 (alpha itself untouched)",

    0x100703F0: "same clamp and the same base ...",
    0x1007044A: "... but fst (not fstp): base stays on the x87 stack",
    0x10070450: "fldln2 + fyl2x = ln(base)",
    0x10070456: "1.0 / ln(base)",
    0x1007045C: "[0x101e4310] = 1/ln(base)",

    0x10070498: "st0 = 1/ln(base)",
    0x1007049E: "* 16.0  =>  K = 16/ln(base), loop invariant",
    0x100704E6: "src.a <= 0 ? -> 0x10070524, zero the pixel",
    0x100704EC: "st0 = the blurred float luma",
    0x100704EE: "+ 1.0f  (undoes the -1 of the forward curve)",
    0x100704F4: "fldln2 + fxch + fyl2x = ln(y + 1)",
    0x100704FA: "* K",
    0x100704FC: "+ 0.5, then _ftol -> round half away from zero",
    0x10070507: "cb byte -> int16",
    0x10070511: "<< 4 restores the 1/16 quantisation step",
    0x10070517: "store the luma as int16 with NO clamp",
    0x10070524: "alpha <= 0: y = cb = cr = 0",
}


def _fp_hint(img, insn):
    """x87 operand -> the constant it loads, at the width the opcode uses.

    Deliberately narrower than tools.disasm's generic resolver: an `fld dword`
    is a float32 and printing the int32 or float64 reading of the same bytes
    next to it (which the generic resolver does) is noise here, where the whole
    point is the exact curve constant.
    """
    if not insn.mnemonic.startswith("f"):
        return ""
    m = re.search(r"\[(0x[0-9a-fA-F]{7,8})\]", insn.op_str)
    if not m:
        return ""
    va = int(m.group(1), 16)
    if "qword" in insn.op_str and img.valid(va, 8):
        return f"   ; = {img.f64(va)!r}"
    if "dword" in insn.op_str and img.valid(va, 4):
        return f"   ; = {img.f32(va)!r}f"
    return ""


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    for start, size, label in BLOCKS:
        print(f"\n--- {label} @ 0x{start:08x} ---")
        for insn, _ in disasm_range(img, start, size, resolve=False):
            note = ANNOTATIONS.get(insn.address)
            tail = f"    <-- {note}" if note else _fp_hint(img, insn)
            print(f"0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}{tail}")

    print(
        "\n"
        "Globals these helpers pass to their worker threads (they cannot take\n"
        "arguments - MULTI_THREAD_FUNC only gets thread_id/thread_num/fp/fpip):\n"
        "  0x101e42f4  image buffer          0x101e4300  w        0x101e4304  h\n"
        "  0x101e4318  base (double)         0x101e4310  1/ln(base) (inverse only)\n"
        "  0x10135c68  object-buffer row stride in pixels (0x10149840 for the\n"
        "              6-byte frame copies at 0x10070550 / 0x10070700)\n"
        "\n"
        "Pixel layout while 光の強さ > 0 (object path, still 8 bytes):\n"
        "  +0 float  curved luma = pow(base, clamp(y,0,4096)/16) - 1\n"
        "  +4 int8   cb, quantised to 1/16    +5 int8  cr, quantised to 1/16\n"
        "  +6 int16  alpha, carried through unchanged\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
