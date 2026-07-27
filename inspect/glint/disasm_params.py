"""Raw disassembly of the parts of 閃光 that angr's decompiler cannot render,
with every absolute memory operand resolved to the constant it points at.

Three things live only in the instructions:

  * the x87 in func_proc - `fild; fsqrt; call _ftol` for the canvas diagonal,
    and the same pattern per pixel in the workers, multiplied by the double at
    0x1009a400. That multiplier is what sets the sampling resolution, and it
    is invisible in the decompilation.
  * the compiler-generated constant divisions. Every one of them uses the same
    magic 0x10624dd3; only the shift differs, and the shift is what picks the
    divisor (`sar edx, 6` -> /1000, `sar edx, 4` -> /250). Read carelessly the
    two look interchangeable, and the /250 one is doing something surprising:
    its input has already been multiplied by 1000, so the pair computes a
    plain *4 (verify_canvas_growth.py checks that).
  * the state block at 0x101a6b7c..0x101a6bac. func_proc writes it, the
    workers read it, nothing else in exedit touches it (tools/xrefs.py on any
    member returns 閃光 code only), so it is this effect's private frame
    state rather than shared infrastructure.

Run via main.py:
    uv run main.py inspect/glint/disasm_params.py
    uv run main.py inspect/glint/disasm_params.py --section geometry
"""

import argparse

from tools.cints import MAGIC_1000, divisor_of
from tools.disasm import dump_range
from tools.pe_image import PEImage

SECTIONS = {
    # 強さ -> fixed point, and the threshold derived from it
    "strength": (0x1004E560, 0x60, "func_proc: 強さ -> fixed point + threshold"),
    # centre, maximum reach, per-pass sample cap, canvas growth
    "geometry": (0x1004E5B7, 0x1B0, "func_proc: centre, reach, sample cap, canvas growth"),
    # canvas clamp loops, サイズ固定, colour setup, worker dispatch, final blit
    "dispatch": (0x1004E7E0, 0x170, "func_proc: canvas clamp, サイズ固定, colour, dispatch, blit"),
    # the per-pixel distance -> sample count / ray length calculation
    "ray": (0x1004EA86, 0xA0, "worker: distance -> sample count and ray length"),
    # the accumulate + threshold + unpremultiply tail
    "output": (0x1004EC2E, 0x60, "worker: average, threshold, write as luminance-in-alpha"),
}

# The private per-frame state func_proc fills in for the workers.
STATE = {
    0x101A6B7C: "threshold T = 4096 - strength (floored at 0)",
    0x101A6B80: "cx = w/2 + track[1] (X)",
    0x101A6B84: "cy = h/2 + track[2] (Y)",
    0x101A6B88: "x1 - right edge of the grown canvas, in source coordinates",
    0x101A6B8C: "y1 - bottom edge of the grown canvas",
    0x101A6B90: "light colour Cb",
    0x101A6B94: "strength = trunc(raw * 4096 / 1000), 0..4096",
    0x101A6B98: "R - cap on the number of samples taken per output pixel",
    0x101A6B9C: "light colour Cr",
    0x101A6BA0: "x0 - left edge of the grown canvas (<= 0)",
    0x101A6BA4: "750 - the ray covers 750/1000 of the distance to the centre",
    0x101A6BA8: "y0 - top edge of the grown canvas (<= 0)",
    0x101A6BAC: "light colour Y",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--section", action="append", choices=sorted(SECTIONS),
                        help="only these sections; repeatable")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    for key in args.section or SECTIONS:
        start, size, label = SECTIONS[key]
        dump_range(img, start, size, label)

    print("\n--- 閃光's private per-frame state (func_proc writes, workers read) ---")
    for va, what in STATE.items():
        print(f"  0x{va:08x}  {what}")

    print("\n--- constants the operands above resolve to ---")
    print(f"  0x1009a400 = {img.f64(0x1009A400)!r}"
          "   (per-pixel: distance is measured in 1/8 px before being truncated)")
    for shift in (4, 6):
        print(f"  magic 0x{MAGIC_1000:08x} + `sar edx, {shift}` = divide by "
              f"{divisor_of(MAGIC_1000, shift)}   (checked over -4M..4M)")
    print("  0x1004e560 stores the literal 750 into 0x101a6ba4 every frame rather than")
    print("  using an immediate; nothing ever writes it another value.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
