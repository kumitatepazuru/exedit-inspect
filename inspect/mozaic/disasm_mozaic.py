"""Raw capstone disassembly of モザイク's func_proc and its four workers, with
memory operands resolved against the bytes they point at.

decompile_mozaic.py's angr output recovers the loop nest but renders the
averaging as `/* unsupported instruction */`, because the colour divide is
x87 (`fild`/`fmul`/`fdiv`/`fistp`) and angr's decompiler does not lift x87 to
C. That is precisely the part worth reading, so this script prints the
instructions instead - and resolves the two constants that would otherwise be
opaque addresses:

  * 0x1009a3a0 = 4096.0, the fixed-point scale the premultiplied colour sums
    are re-expanded by, and
  * 0x101bad24 / 0x101bad28 / 0x101bad2c, the three globals func_proc writes
    once per frame (size, offset_x, offset_y) and all four workers read. The
    --xref pass confirms nothing outside 0x1006b090..0x1006bd26 touches them,
    so they are モザイク's own state and not shared exedit scratch.

Run via main.py:
    uv run main.py inspect/mozaic/disasm_mozaic.py
    uv run main.py inspect/mozaic/disasm_mozaic.py --only func_proc
    uv run main.py inspect/mozaic/disasm_mozaic.py --xref
"""

import argparse
import re
import struct

import capstone
import pefile

# (start, size). Sizes run to the next function's aligned entry.
REGIONS = {
    "func_proc": (0x1006B090, 0x0F0),
    "object_notile": (0x1006B180, 0x2F0),
    "frame_notile": (0x1006B470, 0x240),
    "object_tile": (0x1006B6B0, 0x390),
    "frame_tile": (0x1006BA40, 0x2E6),
    "ftol": (0x10091AD8, 0x27),
}

GLOBALS = {
    0x101BAD24: "g_size     (track[0], >= 2)",
    0x101BAD28: "g_offset_x ((w % (size*2)) / 2)",
    0x101BAD2C: "g_offset_y ((h % (size*2)) / 2)",
    0x1009A3A0: "const 4096.0",
}

# FILTER / FILTER_PROC_INFO fields the code reaches through, so the register
# arithmetic is readable without cross-checking data/filter.h every line.
FIELDS = {
    "[ecx + 0x44]": "fp->track", "[ecx + 0x48]": "fp->check", "[ecx + 0x60]": "fp->exfunc",
    "[edx + 0x60]": "fp->exfunc", "[eax + 0xcc]": "exfunc->exec_multi_thread_func",
    "[edx + 0xcc]": "exfunc->exec_multi_thread_func",
}


def _annotate(insn, image_base, data):
    for pat, name in FIELDS.items():
        if pat in insn.op_str:
            return f"   ; {name}"
    m = re.search(r"0x[0-9a-fA-F]{7,8}", insn.op_str)
    if not m:
        return ""
    addr = int(m.group(0), 16)
    if addr in GLOBALS:
        return f"   ; {GLOBALS[addr]}"
    rva = addr - image_base
    if not (0 <= rva and rva + 8 <= len(data)):
        return ""
    if insn.mnemonic.startswith("f"):        # x87 operand -> show it as a double
        return f"   ; = {struct.unpack_from('<d', data, rva)[0]!r}"
    return ""


def _dump(md, image_base, data, start, size, label):
    print(f"\n{'=' * 72}\n{label}  @ 0x{start:08x} ({size} bytes)\n{'=' * 72}")
    code = data[start - image_base:start - image_base + size]
    for insn in md.disasm(code, start):
        print(f"0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}"
              f"{_annotate(insn, image_base, data)}")


def _xref(image_base, data):
    lo, hi = 0x1006B090, 0x1006BD26
    print(f"\n{'=' * 72}\nreferences to the three globals, anywhere in the image\n{'=' * 72}")
    for va in (0x101BAD24, 0x101BAD28, 0x101BAD2C):
        hits, pos = [], 0
        needle = struct.pack("<I", va)
        while True:
            pos = data.find(needle, pos)
            if pos == -1:
                break
            hits.append(image_base + pos)
            pos += 1
        outside = [h for h in hits if not (lo <= h <= hi)]
        print(f"  0x{va:08x} {GLOBALS[va]:<34} {len(hits):2d} refs, "
              f"{len(outside)} outside 0x{lo:08x}..0x{hi:08x}"
              f"{'' if not outside else '  <-- SHARED, not mozaic-private!'}")
    print("  (all four mozaic functions live inside that range, so 0 outside means")
    print("   these globals are private state, written once per frame by func_proc)")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=sorted(REGIONS), help="dump just one region")
    parser.add_argument("--xref", action="store_true", help="only run the global cross-reference")
    args = parser.parse_args(argv or [])

    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    if args.xref:
        _xref(image_base, data)
        return

    targets = {args.only: REGIONS[args.only]} if args.only else REGIONS
    for label, (start, size) in targets.items():
        _dump(md, image_base, data, start, size, label)

    if not args.only:
        _xref(image_base, data)
        print("\nftol (0x10091ad8) note: `or ah, 0xc` sets the x87 rounding-control")
        print("field to 11 = truncate toward zero, so every fistp in the workers")
        print("truncates rather than rounds to nearest.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
