"""Decompile/disassemble the ぼかし (blur) filter's func_proc and the twelve
box-blur workers it dispatches, in exedit.auf.

func_proc's address (0x1000e2f0) came from `tools.filter_table --name ぼかし`. This script
builds a small angr CFG over a narrow byte range around it (much faster than
a whole-binary CFG, and it avoids dragging in unrelated functions), then runs
angr's Decompiler on func_proc and on each worker.

Why twelve workers for one blur: the worker is picked by three independent
booleans, and every combination has its own hand-written copy in the binary -

    (object effect | frame filter)  x  (vertical | horizontal)
      x  (光の強さ = 0 -> 16-bit integer pixels
          | 光の強さ > 0 -> the pixel's luma has been replaced by a float)

The object-effect pair splits again on サイズ固定, because that checkbox
decides whether the pass is allowed to enlarge the canvas - so the object
side has 8 workers and the frame side 4. WORKERS below is grouped that way.

angr renders the 光の強さ>0 workers poorly (they carry a float accumulator on
the x87 stack across the whole scan line, which the decompiler does not lift),
so this script also does a raw capstone dump of the two shared curve helpers
that create and undo that float format. verify_box_average.py and
verify_light_curve.py read the same code with annotations instead.

Run via main.py:
    uv run main.py inspect/blur/decompile_blur.py
    uv run main.py inspect/blur/decompile_blur.py --skip-workers
"""

import argparse

from tools.decompile import decompile_targets
from tools.disasm import disasm_range
from tools.pe_image import PEImage

FUNC_PROC = 0x1000E2F0

WORKERS = {
    "func_proc (dispatcher)": FUNC_PROC,
    # 光の強さ = 0: plain 16-bit YC(A) pixels
    "int  / object / vertical   / サイズ固定 off (grows the canvas)": 0x1000EAE0,
    "int  / object / horizontal / サイズ固定 off (grows the canvas)": 0x1000EEF0,
    "int  / object / vertical   / サイズ固定 on": 0x1000F310,
    "int  / object / horizontal / サイズ固定 on": 0x1000F7E0,
    "int  / frame  / vertical": 0x1000FCB0,
    "int  / frame  / horizontal": 0x1000FF40,
    # 光の強さ > 0: luma has been replaced by a float by the forward curve
    "curve/ object / vertical   / サイズ固定 off (grows the canvas)": 0x10010190,
    "curve/ object / horizontal / サイズ固定 off (grows the canvas)": 0x100105E0,
    "curve/ object / vertical   / サイズ固定 on": 0x10010A30,
    "curve/ object / horizontal / サイズ固定 on": 0x10010F20,
    "curve/ frame  / vertical": 0x10011400,
    "curve/ frame  / horizontal": 0x100116D0,
}

# Shared (not blur-specific) helpers, dumped as raw asm. The object-buffer
# pair is the 8-byte PIXEL_YCA variant; 発光 uses the 6-byte pair for its
# 拡散速度 parameter, which is the same curve with a different pixel layout.
CURVE_HELPERS = {
    "光の強さ forward curve, object 8-byte buffer: entry (clamps to [1,100], builds base)": (0x10070220, 0x60),
    "光の強さ forward curve, object 8-byte buffer: per-thread worker (pow)": (0x10070290, 0x160),
    "光の強さ inverse curve, object 8-byte buffer: entry (builds 1/ln(base))": (0x100703F0, 0x60),
    "光の強さ inverse curve, object 8-byte buffer: per-thread worker (ln)": (0x10070470, 0xE0),
}

# The canvas pre-expansion path calls these two through exedit's own helper
# table (fp+0x64 -> 0x100a41e0), NOT through AviUtl's EXFUNC (fp+0x60).
CANVAS_HELPERS = {
    "exedit table[0x48]: clear a rect of an object/frame buffer": (0x10081F90, 0x70),
    "exedit table[0x44]: blit a rect between object/frame buffers": (0x10081B40, 0x60),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-workers", action="store_true", help="only decompile func_proc itself")
    args = parser.parse_args(argv or [])

    targets = {"func_proc (dispatcher)": FUNC_PROC} if args.skip_workers else WORKERS
    # func_proc at 0x1000e2f0 through the last worker at 0x100116d0
    base = FUNC_PROC & ~0xFFF
    decompile_targets(dll_path, targets, region=(base, base + 0x4000))

    if not args.skip_workers:
        img = PEImage(dll_path)
        for label, (addr, size) in {**CURVE_HELPERS, **CANVAS_HELPERS}.items():
            print(f"\n{'=' * 74}\n{label}  (0x{addr:08x}, raw capstone disassembly)\n{'=' * 74}")
            for insn, _ in disasm_range(img, addr, size, resolve=False):
                print(f"0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
