"""Establish how the 6 diffusion passes are wired together: what each pass
reads and writes, in which direction it slides, and how its radius is
clamped.

The two questions this answers are (a) whether the 6 passes compound into
one progressively wider blur or independently overwrite each other, and
(b) which of the two workers per pass is the vertical one - which decides
which image dimension clamps its radius.

Findings, both read straight out of the operands below:

  * Buffers ping-pong. Pass step 1 (sub_10053b10) reads fpip->ycp_temp
    (offset +8) and writes the fixed global scratch buffer at 0x101a5328;
    pass step 2 (sub_100540a0 / sub_100544a0) reads that scratch buffer and
    writes back into ycp_temp - exactly where the next iteration's step 1
    reads from. So iteration N+1 blurs on top of iteration N's output.
    Step 2 additionally folds its result into the glow accumulator (see
    verify_accumulate.py for the saturating arithmetic it uses there), so
    the final glow is the sum of all six differently-sized blurs, not just
    the widest one.

  * Step 1 slides by the row stride (*(fpip+0x14) * 6 bytes - that field is
    FILTER_PROC_INFO's max_w, a pixel count, not the byte count line_size,
    which lives at +0x44 and exedit never reads) => it is the
    VERTICAL pass, and it reads the radius/kernel globals 0x101b1fe8 /
    0x101b1ff0, which sub_10053a30 clamped against h/2-1. Step 2 slides by 6
    bytes = one pixel => HORIZONTAL, reading 0x101b1fec / 0x101b1ff8, clamped
    against w/2-1. The same split holds for the reduced-precision pair used
    at 拡散速度>0 (sub_10053da0 vertical, sub_100548a0 horizontal).

  * Kernel width is radius*2+1 in both directions (`lea eax,[ecx+ecx+1]`),
    and each worker divides its window sum by that width - a plain box
    average, no weighting (verify_diffusion_speed_boxsum.py covers the
    reduced-precision pair separately).

Which worker of the pair runs is picked by fp->flag & 0x20 - object effect
vs frame filter, see verify_mode_mapping.py.

Run via main.py:
    uv run main.py inspect/glow/verify_blur_chain.py
"""

import re

from tools.disasm import disasm_range, dump_all
from tools.pe_image import PEImage

DISPATCHER = (0x10053A30, 0xE0)
PASS1_VERTICAL = (0x10053B10, 0xB0)          # ycp_temp -> global scratch
PASS2_HORIZONTAL_FRAME = (0x10054190, 0x80)  # scratch -> ycp_temp, frame filter
PASS2_HORIZONTAL_OBJECT = (0x10054593, 0x80)  # scratch -> ycp_temp, object effect

SCRATCH_BUFFER_VA = 0x101A5328

GLOBALS = {
    0x101B1FE8: "radius clamped by h/2-1 (vertical)",
    0x101B1FF0: "kernel width for the vertical pass = 2*radius+1",
    0x101B1FEC: "radius clamped by w/2-1 (horizontal)",
    0x101B1FF8: "kernel width for the horizontal pass = 2*radius+1",
    0x101B1FE0: "image width",
    0x101B1FDC: "image height",
    0x101B2000: "diffusion speed",
    SCRATCH_BUFFER_VA: "global ping-pong scratch buffer",
}


def annotate(insn):
    for addr, name in GLOBALS.items():
        if f"0x{addr:08x}" in insn.op_str:
            return name
    if "[ecx + 8]" in insn.op_str or "[edx + 8]" in insn.op_str or "[eax + 8]" in insn.op_str:
        return "fpip->ycp_temp (offset +8)"
    if insn.mnemonic == "idiv":
        return "divide the window sum by the kernel width (box average)"
    return ""


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "sub_10053a30 (per-pass dispatcher: clamps the radius per direction, "
        "picks the worker pair)": DISPATCHER,
        "sub_10053b10 (step 1, VERTICAL: ycp_temp -> scratch)": PASS1_VERTICAL,
        "sub_100540a0 (step 2, HORIZONTAL, frame filter: scratch -> ycp_temp + accumulate)":
            PASS2_HORIZONTAL_FRAME,
        "sub_100544a0 (step 2, HORIZONTAL, object effect: scratch -> ycp_temp + accumulate)":
            PASS2_HORIZONTAL_OBJECT,
    }, resolve=False, annotations=annotate, mnemonic_width=7)

    print("\n--- which radius/kernel globals each worker actually reads ---")
    for start, size, name in ((0x10053B10, 0x300, "sub_10053b10  (step 1, speed=0)"),
                              (0x100540A0, 0x300, "sub_100540a0  (step 2, speed=0, frame)"),
                              (0x100544A0, 0x300, "sub_100544a0  (step 2, speed=0, object)"),
                              (0x10053DA0, 0x300, "sub_10053da0  (step 1, speed>0)"),
                              (0x100548A0, 0x220, "sub_100548a0  (step 2, speed>0)")):
        found = set()
        for insn, _ in disasm_range(img, start, size, resolve=False):
            for m in re.finditer(r"0x101b1f(?:e8|ec|f0|f8)", insn.op_str):
                found.add(m.group(0))
        tags = ", ".join(f"{g} ({GLOBALS[int(g, 16)]})" for g in sorted(found))
        print(f"  {name}: {tags}")

    print(
        "\n"
        "Verdict: the 6 passes are chained, not independent.\n"
        f"  ping-pong: ycp_temp (fpip+8) <-> global scratch (0x{SCRATCH_BUFFER_VA:08x})\n"
        "  step 1 is vertical (slides by the row stride, radius clamped by h/2-1),\n"
        "  step 2 is horizontal (slides by one pixel, radius clamped by w/2-1) and is\n"
        "  also the step that folds this pass's result into the glow accumulator.\n"
        "  So pass N+1 blurs pass N's already-blurred output, and the accumulator ends\n"
        "  up holding all six blur scales combined - see verify_accumulate.py for the\n"
        "  saturating arithmetic that combination actually uses.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
