"""Decompile the 拡散光 (diffusion light) filter's func_proc and its six
worker functions in exedit.auf.

func_proc's address (0x1001c330) comes from `tools.filter_table --name 拡散光`,
which also shows that both registrations (object effect / frame filter) share
it. This script builds a small angr CFG over the 0x1001c000-0x1001f000 window
- everything 拡散光 owns lives in that one contiguous block - and decompiles:

  * func_proc, the dispatcher: parameter conversion, the canvas-growth
    preamble, and two blur "rounds" whose radii come from splitting 拡散,
  * the three worker *pairs* it can dispatch to. Each pair is
    (vertical box pass, horizontal box pass + composite); which pair runs is
    decided by `fp->flag & 0x20` and by `サイズ固定` - see verify_mode_mapping.py.

Two caveats about reading the output:

  * angr does not lift x87, and every one of these workers divides in the FPU
    (`fild` / `fdiv` / `_ftol`) to un-premultiply the blurred colour. Those
    lines come out as `/* unsupported instruction */`; verify_box_average.py
    and verify_composite.py read them as raw instructions instead.
  * the horizontal workers are 2-3 KB of five nearly identical unrolled
    loops (ramp-up / main / tail, plus the two "outside the original image"
    variants in the canvas-growing one). The decompilation is useful for
    *which buffer each loop touches*, not for following the arithmetic.

Run via main.py:
    uv run main.py inspect/diffusion_light/decompile_diffusion_light.py
    uv run main.py inspect/diffusion_light/decompile_diffusion_light.py --only func_proc
"""

from tools.decompile import decompile_cli

FUNC_PROC = 0x1001C330

TARGETS = {
    "func_proc (dispatcher)": FUNC_PROC,
    "object, size-growing: vertical box pass": 0x1001C710,
    "object, size-growing: horizontal box pass + composite": 0x1001CB10,
    "object, サイズ固定: vertical box pass": 0x1001D710,
    "object, サイズ固定: horizontal box pass + composite": 0x1001DBD0,
    "frame filter: vertical box pass": 0x1001E4F0,
    "frame filter: horizontal box pass + composite": 0x1001E770,
}

# The one CRT stub every worker calls. exedit reaches it from the x87
# sequences angr cannot lift, so it never shows up as a call in the C output.
FP_HELPERS = {
    "double -> int truncation thunk (MSVC _ftol pattern)": (0x10091AD8, 0x30),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    base = FUNC_PROC & ~0xFFF
    decompile_cli(dll_path, TARGETS, argv, region=(base, base + 0x3000), extra=FP_HELPERS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
