"""Work out 光色の設定 ("glow color setting"): where the picked colour lives
and what changes when one has (or has not) been picked.

func_proc branches on `ex_data->field_0 & 0x1000000` to pick between two
pairs of bright-pass extraction workers (0x100533c0/0x100535a0 vs
0x100534b0/0x100536d0). This script pins down what that bit and the rest of
that dword mean by:

  1. reading FILTER_DLL.ex_data_def for the 発光 entry (the template exedit
     copies into a fresh instance's fp->ex_data on creation) directly out of
     the mapped image with pefile, and
  2. decompiling the two frame-filter extraction variants (0x100533c0 and
     0x100534b0) plus the RGB->YCbCr setup call (0x1006fed0 -> 0x1006f520)
     with angr, since that's where the per-pixel colour math lives.

Result: bit24 set = no colour picked (use each source pixel's own chroma),
bit24 clear = use the picked colour for all three channels. The default
ex_data is 0x01FFFFFF, i.e. bit24 set with an unused white placeholder.

Two things the angr output does not make obvious, covered elsewhere:
the picked colour's *Y* also scales the glow's luma (verify_extract_alpha.py),
and the conversion matrix behind 0x1006f520 is plain BT.601
(verify_ycbcr_matrix.py). The two workers decompiled here are the
frame-filter pair; the object-effect pair is 0x100535a0/0x100536d0
(verify_mode_mapping.py).

Run via main.py:
    uv run main.py inspect/glow/disasm_color.py
"""

import logging
import struct

import angr
import pefile

GLOW_STRUCT_VA = 0x100A6218  # object-effect FILTER_DLL entry (flag=0x20), from find_glow_addr.py
OFF_EX_DATA_SIZE = 0x50
OFF_EX_DATA_DEF = 0x6C

# frame-filter bright-pass extraction workers: one uses the source pixel's
# own chroma (natural color), the other uses a fixed tint derived from the
# picked color - which is which is exactly what this script confirms.
WORKER_NATURAL_OR_TINT = [0x100533C0, 0x100534B0]
COLOR_CONVERT_SETUP = 0x1006FED0
COLOR_CONVERT_WORKER = 0x1006F520


def _dump_ex_data_def(dll_path):
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()

    def rd(va):
        return struct.unpack_from("<I", data, va - image_base)[0]

    size = rd(GLOW_STRUCT_VA + OFF_EX_DATA_SIZE)
    def_ptr = rd(GLOW_STRUCT_VA + OFF_EX_DATA_DEF)
    raw = rd(def_ptr)
    print(f"ex_data_size = {size} bytes, ex_data_def @ 0x{def_ptr:08x}")
    print(f"default ex_data dword = 0x{raw:08x}")
    print(f"  bit24 (0x1000000)  = {'set' if raw & 0x1000000 else 'clear'}  (selects natural-vs-tint below)")
    print(f"  low 24 bits (RGB)  = R=0x{raw & 0xFF:02x} G=0x{(raw >> 8) & 0xFF:02x} B=0x{(raw >> 16) & 0xFF:02x}")


def _decompile(proj, cfg, addr, label):
    func = cfg.functions.function(addr=addr)
    print(f"\n{'=' * 70}\n{label}  (0x{addr:08x})\n{'=' * 70}")
    dec = proj.analyses.Decompiler(func, cfg=cfg.model)
    print(dec.codegen.text)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    logging.getLogger("angr").setLevel(logging.ERROR)

    print("--- FILTER_DLL.ex_data_def for 発光 (persisted per-instance state) ---")
    _dump_ex_data_def(dll_path)

    proj = angr.Project(dll_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(regions=[(0x10053000, 0x10056000)], force_complete_scan=False, normalize=True)

    _decompile(proj, cfg, WORKER_NATURAL_OR_TINT[0], "bright-pass extraction, bit24 SET branch")
    _decompile(proj, cfg, WORKER_NATURAL_OR_TINT[1], "bright-pass extraction, bit24 CLEAR branch")

    cfg2 = proj.analyses.CFGFast(regions=[(0x1006f000, 0x10070000)], force_complete_scan=False, normalize=True)
    _decompile(proj, cfg2, COLOR_CONVERT_SETUP, "ex_data RGB byte unpack -> calls RGB->YCbCr conversion")
    _decompile(proj, cfg2, COLOR_CONVERT_WORKER, "generic RGB->YCbCr conversion dispatch (not glow-specific)")


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
