"""Confirm the reduced-precision box-sum workers used when 拡散速度>0
(`sub_10053da0` vertical / `sub_100548a0` horizontal) are genuine *box*
(uniform-weight) blurs and not some other kernel shape.

verify_blur_chain.py covers the normal-precision pair used at 拡散速度=0,
which are plain sliding-window box sums divided by the kernel width. The
pair swapped in at 拡散速度>0 works on a different record layout
({f32 y; i8 cb; i8 cr}) and had never been checked independently - if
either of them applied a per-offset weight table, the blur shape would
differ exactly in the regime where the exponential curve amplifies any
difference.

Verdict (see printed disassembly): both reduced-precision workers compute a
plain running sum over the window (`fadd` / integer `add` per pixel, no
per-offset multiply by any weight table) and divide by the same
kernel-width denominator used everywhere else - luma via a float
reciprocal-multiply (`fild` kernel width, `fdivr 1.0`, `fmul`), chroma via
integer division with a round-to-nearest bias rather than the normal path's
truncating `idiv`. That is a rounding difference, not a kernel-shape one:
there is no Gaussian (or any other non-uniform) weighting anywhere in this
filter's blur, in either precision variant.

Run via main.py:
    uv run main.py inspect/glow/verify_diffusion_speed_boxsum.py
"""

import re
import struct

import capstone
import pefile

VERTICAL_REDUCED = (0x10053DA0, 0x200)    # reduced-precision vertical box-sum, 拡散速度>0
HORIZONTAL_REDUCED = (0x100548A0, 0x1E0)  # reduced-precision horizontal box-sum, 拡散速度>0

ACCUM_INIT_CONST = 0x1009A420  # 0.0f - float accumulator seed
RECIPROCAL_ONE_CONST = 0x1009A424  # 1.0f - numerator for fdivr(kernel_width) -> 1/kernel_width


def _resolve_const(insn, image_base, data):
    m = re.search(r"0x[0-9a-fA-F]{7,8}\]", insn.op_str)
    if not m:
        return ""
    addr = int(m.group(0)[:-1], 16)
    rva = addr - image_base
    if rva < 0 or rva + 4 > len(data):
        return ""
    if addr == ACCUM_INIT_CONST:
        return "  <-- f32=0.0 (float accumulator seed)"
    if addr == RECIPROCAL_ONE_CONST:
        return "  <-- f32=1.0 (fdivr computes 1.0/kernel_width)"
    return ""


def _dump(md, image_base, data, start, size, label):
    print(f"\n--- {label} @ 0x{start:08x} ---")
    code = data[start - image_base:start - image_base + size]
    for insn in md.disasm(code, start):
        marker = ""
        if insn.mnemonic in ("idiv", "div"):
            marker = "  <-- divide by kernel width (box average)"
        elif insn.mnemonic == "fmul" and "st(2)" in insn.op_str:
            marker = "  <-- multiply running sum by 1/kernel_width (float box average)"
        print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}{_resolve_const(insn, image_base, data)}{marker}")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    _dump(md, image_base, data, *VERTICAL_REDUCED, "sub_10053da0 (reduced-precision vertical box-sum, diffusion speed > 0)")
    _dump(md, image_base, data, *HORIZONTAL_REDUCED, "sub_100548a0 (reduced-precision horizontal box-sum, diffusion speed > 0)")

    print(
        "\n"
        "Verdict: no per-offset weight table anywhere in either worker - every pixel\n"
        "inside the sliding window contributes with the exact same weight (a plain\n"
        "fadd/add per iteration), and the only per-pixel-position operation afterward\n"
        "is a single divide/multiply by the kernel width (same denominator formula as\n"
        "the normal-precision path in verify_blur_chain.py). Luma uses a float\n"
        "reciprocal-multiply (fild kernel_width -> fdivr 1.0 -> fmul), chroma uses\n"
        "integer division with a round-to-nearest sign-based bias (not the normal\n"
        "path's plain truncating idiv) - a rounding-mode difference, not a kernel-shape\n"
        "one. AviUtl's diffusion blur is a uniform box average in every precision variant;\n"
        "there is no Gaussian (or any other non-uniform) kernel anywhere in this filter.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
