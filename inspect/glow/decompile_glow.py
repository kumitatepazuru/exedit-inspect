"""Decompile/disassemble the 発光 (glow) filter's func_proc and its worker
functions in exedit.auf.

func_proc's address (0x10053100) was found with find_glow_addr.py. This
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
import logging

import angr
import capstone
import pefile

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


def _build_cfg(proj, addr, span=0x2000):
    logging.getLogger("angr").setLevel(logging.ERROR)
    base = addr & ~0xFFF
    return proj.analyses.CFGFast(regions=[(base, base + span)], force_complete_scan=False, normalize=True)


def _decompile(proj, cfg, addr, label):
    func = cfg.functions.function(addr=addr)
    print(f"\n{'=' * 70}\n{label}  (0x{addr:08x})\n{'=' * 70}")
    if func is None:
        print("  ! angr did not recover a function at this address")
        return
    try:
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        print(dec.codegen.text)
    except Exception as e:
        print(f"  ! decompilation failed: {e}")


def _disasm(dll_path, addr, size, label):
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    rva = addr - image_base
    code = data[rva:rva + size]
    print(f"\n{'=' * 70}\n{label}  (0x{addr:08x}, raw capstone disassembly)\n{'=' * 70}")
    for insn in md.disasm(code, addr):
        print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-workers", action="store_true", help="only decompile func_proc itself")
    args = parser.parse_args(argv or [])

    proj = angr.Project(dll_path, auto_load_libs=False)
    cfg = _build_cfg(proj, FUNC_PROC, span=0x3000)

    targets = {"func_proc (dispatcher)": FUNC_PROC} if args.skip_workers else WORKERS
    for label, addr in targets.items():
        _decompile(proj, cfg, addr, label)

    if not args.skip_workers:
        for label, (addr, size) in FP_HELPERS.items():
            _disasm(dll_path, addr, size, label)


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
