"""Raw capstone disassembly of the parts of func_proc (and a few helpers it
calls) that convert the four トラックバー values into the internal numbers
used by the blur/threshold math.

decompile_glow.py's angr-based decompilation renders most of this as
`/* unsupported instruction */` because it is x87/SSE floating point code,
which angr's decompiler does not lift to C. Reading the raw instructions by
hand (with constant operands resolved against the .rdata/.data bytes they
point at) is what actually pins down:

  * the exact fixed-point conversion used for 強さ/しきい値 (a signed
    "divide by 1000" via a compiler-generated magic-number multiply, easy to
    misread as an unrelated shift/multiply if you don't resolve the magic
    constant),
  * the geometric progression of blur radii across the fixed 6-pass loop
    (driven by a real pow(double,double) call - confirmed separately in
    decompile_glow.py's FP_HELPERS section - not just angr's inferred
    "unsupported instruction" placeholders), and
  * what 拡散速度 (diffusion "speed") actually gates: not a per-frame
    random/animated offset (there is no rand()/frame-number read anywhere
    in the functions it enables), but a switch to a faster, reduced
    precision blur implementation (see WHAT_DIFFUSION_SPEED_DOES below).

Run via main.py:
    uv run main.py inspect/glow/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x10053100, 0x336)

# sub_1006fed0 unpacks fp->ex_data (the RGB color chosen via the "光色の設定"
# checkbox/button) into 3 bytes and converts them to Y/Cb/Cr - i.e. this is
# the glow *tint color* setup, unrelated to 拡散速度. Included here so the
# two are not confused (an earlier pass at this analysis conflated them).
GLOW_COLOR_SETUP = (0x1006fed0, 0x60)

# 拡散速度 (track[3], clamped to [1,100] before use) is passed as the last
# argument to this pair of shared/generic exedit utility functions - not
# glow-specific (they write into a completely different global range,
# 0x101e42f4.., than glow's own 0x101b1fe0.. globals, and the multithread
# dispatch goes through a cached global EXFUNC pointer rather than fp's own
# - both signs this is common infrastructure reused across filters).
DIFFUSION_SPEED_ENTRY = (0x10070550, 0x60)
DIFFUSION_SPEED_WORKER = (0x100705c0, 0x140)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "func_proc (parameter setup + 6-pass blur loop)": FUNC_PROC,
        "sub_1006fed0 (光色の設定 -> Y/Cb/Cr, NOT 拡散速度)": GLOW_COLOR_SETUP,
        "sub_10070550 (拡散速度-gated buffer pass, entry/clamp)": DIFFUSION_SPEED_ENTRY,
        "sub_100705c0 (per-thread worker: pow()-curve + byte quantize)": DIFFUSION_SPEED_WORKER,
    })

    print(
        "\n"
        "Summary of what the constants above resolve to:\n"
        "  0x1009a3b0 = 0.5   (used both as a rounding bias and as the loop's initial-radius seed component)\n"
        "  0x1009a5b8 = 0.2   (pow() exponent: pow(diffusion_raw*0.5, 0.2))\n"
        "  0x10624dd3 + sar 6 + sign-fix = signed division by 1000 (magic-number divide, MSVC-generated)\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
