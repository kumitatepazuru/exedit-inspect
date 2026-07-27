"""Raw capstone disassembly of the part of ぼかし's func_proc that turns the
three トラックバー values into the numbers the box-blur workers actually read.

decompile_blur.py's angr output covers this correctly, but it renders the
compiler-generated constant divide as `274877907 * x >> 38`, which is easy to
misread as "some scaling" rather than "signed divide by 1000, truncating".
Reading the instructions with the magic constant resolved is what pins down:

  * that 範囲 = 0 makes func_proc return immediately, so the filter is a
    genuine no-op rather than a 1-pixel blur,
  * that 縦横比 does NOT scale both axes - it shrinks exactly one of them,
    with the sign choosing which, so 範囲 always stays the radius of the
    longer axis, and
  * that each axis radius is then split into two halves (ceil, floor) which
    are blurred as two separate box passes - the reason ぼかし is a smooth
    triangular kernel and not a boxy one (verify_pass_chain.py).

Run via main.py:
    uv run main.py inspect/blur/disasm_params.py
"""

import re

from tools.disasm import disasm_range
from tools.pe_image import PEImage

PARAM_SETUP = (0x1000E2F0, 0xE0)

ANNOTATIONS = {
    0x1000E2F9: "eax = fp->track   (FILTER+0x44)",
    0x1000E2FC: "ebx = track[0] = 範囲",
    0x1000E300: "範囲 == 0 -> return TRUE immediately, image untouched",
    0x1000E306: "ecx = track[2] = 光の強さ  (kept in a local, used at 0x1000e535)",
    0x1000E309: "eax = track[1] = 縦横比",
    0x1000E314: "ebp = 範囲  <- horizontal radius seed (ebx stays the vertical one)",
    0x1000E316: "縦横比 <= 0 ? -> 0x1000e337",
    0x1000E318: "--- 縦横比 > 0: shrink the VERTICAL radius ---",
    0x1000E31D: "ecx = 1000 - 縦横比",
    0x1000E31F: "0x10624dd3: MSVC magic number for a signed divide by 1000",
    0x1000E324: "ecx = (1000 - 縦横比) * 範囲",
    0x1000E327: "imul/sar 6 => (x * 0x10624dd3) >> 38   (i.e. x / 1000)",
    0x1000E32E: "+ sign bit: rounds the quotient toward zero, not toward -inf",
    0x1000E333: "ebx = 範囲 * (1000 - 縦横比) / 1000   <- vertical radius",
    0x1000E337: "縦横比 == 0 ? -> 0x1000e355 (both radii stay 範囲)",
    0x1000E339: "--- 縦横比 < 0: shrink the HORIZONTAL radius ---",
    0x1000E353: "ebp = 範囲 * (1000 + 縦横比) / 1000   <- horizontal radius",
    0x1000E355: "eax = fp->flag",
    0x1000E35B: "and 0x20 -> object effect vs frame filter (verify_mode_mapping.py)",
    0x1000E367: "object path: clamp so that w + 2*rx fits in the max canvas width",
    0x1000E376: "0x10196748 = exedit's max object canvas width",
    0x1000E38E: "0x101920e0 = exedit's max object canvas height",
    0x1000E3A3: "--- split each radius into two halves for two box passes ---",
    0x1000E3A8: "eax = rx / 2   (truncating)  -> rx_lo",
    0x1000E3AA: "store rx_lo",
    0x1000E3B9: "ecx = ry / 2   (truncating)  -> ry_lo",
    0x1000E3BB: "ebp = rx - rx_lo = ceil(rx/2)  -> rx_hi",
    0x1000E3C1: "ebx = ry - ry_lo = ceil(ry/2)  -> ry_hi",
    0x1000E3C3: "store ry_lo",
}


def _const_hint(img, insn):
    """Doubles behind x87 operands. Narrower than tools.disasm's resolver on
    purpose: only x87 instructions are annotated, so the radius arithmetic
    below is not buried under a reading of every integer operand."""
    hints = []
    for m in re.finditer(r"0x[0-9a-fA-F]{7,8}", insn.op_str):
        va = int(m.group(0), 16)
        if insn.mnemonic.startswith("f") and img.valid(va, 8):
            hints.append(f"{m.group(0)} = {img.f64(va)!r}")
    return ("   ; " + ", ".join(hints)) if hints else ""


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    start, size = PARAM_SETUP
    print(f"--- func_proc @ 0x{start:08x}: トラックバー -> radii ---")
    for insn, _ in disasm_range(img, start, size, resolve=False):
        note = ANNOTATIONS.get(insn.address, "")
        marker = f"    <-- {note}" if note else _const_hint(img, insn)
        print(f"0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}{marker}")

    magic = 0x10624DD3
    print(
        "\n"
        "What the constants resolve to:\n"
        f"  0x{magic:08x} = {magic}; {magic} / 2**38 = {magic / 2 ** 38!r}\n"
        f"  1/1000                = {1 / 1000!r}   (so imul+sar 38 is a divide by 1000)\n"
        "  0x10196748 / 0x101920e0 = exedit's max object canvas width / height\n"
        "\n"
        "Summary (verified numerically in verify_radius_split.py):\n"
        "  範囲 == 0                -> func_proc returns immediately\n"
        "  rx = 範囲,  ry = 範囲\n"
        "  縦横比 > 0               -> ry = trunc(範囲 * (1000 - 縦横比) / 1000)\n"
        "  縦横比 < 0               -> rx = trunc(範囲 * (1000 + 縦横比) / 1000)\n"
        "  rx_hi = rx - rx//2, rx_lo = rx//2   (likewise for ry)\n"
        "  the four box passes are then V(ry_hi), H(rx_hi), V(ry_lo), H(rx_lo)\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
