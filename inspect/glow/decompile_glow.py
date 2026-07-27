"""Decompile/disassemble the 発光 (glow) filter's func_proc and its worker
functions in exedit.auf.

func_proc's address (0x10053100) was found with `tools.filter_table --name 発光`. This
script builds a small angr CFG rooted at that address (angr's CFGFast is run
over a narrow byte range around the target instead of the whole binary,
which is both much faster and avoids pulling in unrelated functions), then:

  1. runs angr's Decompiler on func_proc itself and on every worker function
     it calls (found by reading the call targets out of func_proc's own
     decompilation - see WORKERS below), and
  2. does a raw capstone disassembly of two tiny floating point helper
     stubs that angr's decompiler cannot render as C (they only manipulate
     the x87 FPU stack/control word, which is how MSVC-compiled code passes
     doubles to CRT helpers) - these turned out to be the standard MSVC
     double->int64 truncation thunk and a wrapper around pow(double,int).

Run via main.py:
    uv run main.py inspect/glow/decompile_glow.py
"""

import argparse

from tools.decompile import decompile_targets
from tools.disasm import disasm_range
from tools.pe_image import PEImage

FUNC_PROC = 0x10053100

# Worker/helper functions referenced from func_proc's decompiled body,
# grouped by role (see README.md for what each one does).
WORKERS = {
    "func_proc (dispatcher)": FUNC_PROC,
    "threshold+gain extract, frame mode": 0x100533C0,
    "threshold+gain extract, frame mode (variant)": 0x100534B0,
    "threshold+gain extract, object mode": 0x100535A0,
    "threshold+gain extract, object mode (variant)": 0x100536D0,
    "per-pass blur dispatch (radius clamp + thread fan-out)": 0x10053A30,
    "composite/add glow onto frame": 0x10053800,
    "composite/add glow into offscreen object buffer": 0x10053890,
}

# Tiny CRT-style FP helper stubs the decompiler renders as "unsupported
# instruction" soup; worth reading as raw asm instead.
FP_HELPERS = {
    "double -> int64 truncation thunk (MSVC _ftol pattern)": (0x10091AD8, 0x30),
    "pow(double, int) call wrapper": (0x10091C70, 0x20),
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-workers", action="store_true", help="only decompile func_proc itself")
    args = parser.parse_args(argv or [])

    targets = {"func_proc (dispatcher)": FUNC_PROC} if args.skip_workers else WORKERS
    base = FUNC_PROC & ~0xFFF
    decompile_targets(dll_path, targets, region=(base, base + 0x3000))

    if not args.skip_workers:
        img = PEImage(dll_path)
        for label, (addr, size) in FP_HELPERS.items():
            print(f"\n{'=' * 74}\n{label}  (0x{addr:08x}, raw capstone disassembly)\n{'=' * 74}")
            for insn, _ in disasm_range(img, addr, size, resolve=False):
                print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
