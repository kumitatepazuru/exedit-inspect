"""Find every place in exedit.auf that mentions a given virtual address.

The recurring question in this project is "who else touches this?" - is a
global a filter's private state or shared infrastructure, is a worker function
reached from anywhere besides the func_proc being read, is a helper actually a
generic exedit utility. On 32-bit x86 with no position independence, every
reference to a VA is a literal little-endian dword somewhere in the image, so
a plain byte scan answers all of those at once and cannot miss a reference the
way a disassembler that mis-recovers a function can.

The scan is deliberately dumb, so read the results with that in mind: a hit is
"these four bytes equal the address", which for a busy address range will
include coincidental matches inside unrelated constants. The section a hit
lands in (printed for each) is what separates `mov eax, 0x101a6b7c` in .text
from a pointer stored in .data from noise.

Hits inside .text are shown with the instruction that contains them, and each
is attributed to the nearest preceding function entry known from the effect
table (tools/filter_table.py), which is what turns "there is a reference at
0x1004f26c" into "閃光's func_proc uses this".

That attribution is a lower bound, not a symbol table: exedit's shared helpers
and its dialog code are not in the effect table at all, so a hit inside one of
them is credited to whichever registered function happens to precede it. Treat
a small `+0x...` offset as a real attribution and a huge one (`+0x25996`) as
"somewhere after that entry".

    uv run main.py tools.xrefs --addr 0x101a6b98
    uv run main.py tools.xrefs --addr 0x1004f260 --addr 0x1004e9c0
"""

import argparse
import struct

from tools.disasm import make_md
from tools.filter_table import walk
from tools.pe_image import PEImage


def section_of(img: PEImage, va: int) -> str:
    rva = va - img.image_base
    for s in img.pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.Name.rstrip(b"\x00").decode("ascii", "replace")
    return "?"


def scan(img: PEImage, target: int) -> list[int]:
    """VAs of every 4-byte-aligned-or-not occurrence of `target` as a dword."""
    needle = struct.pack("<I", target)
    out, pos = [], 0
    while True:
        i = img.data.find(needle, pos)
        if i == -1:
            return out
        out.append(i + img.image_base)
        pos = i + 1


def instruction_containing(img: PEImage, va: int, target: int, anchor: int | None = None,
                           look_back: int = 16):
    """Return the instruction whose encoding covers `va`.

    x86 is not self-synchronising, so decoding from an arbitrary byte produces
    plausible garbage - `mov dword ptr [0x101a6b94], edx` and a decode one byte
    later that reads `adc eax, 0x101a6b94` both "contain" the address and both
    look like real instructions.

    The reliable fix is to decode forward from a point known to be an
    instruction boundary. `anchor` is that point (the nearest preceding
    function entry from the effect table); linear decoding from a real entry
    stays in sync through ordinary MSVC output. Only when there is no anchor,
    or the stream desynchronises before reaching `va`, does this fall back to
    trying every start offset and preferring a candidate that names the target.
    """
    md = make_md()
    if anchor is not None and 0 < va - anchor < 0x4000:
        for insn in md.disasm(img.code(anchor, va - anchor + 16), anchor):
            if insn.address <= va < insn.address + insn.size:
                return insn
            if insn.address > va:
                break

    hexes = (f"0x{target:x}", f"0x{target:08x}")
    best = None
    for back in range(1, look_back + 1):
        for insn in md.disasm(img.code(va - back, back + 8), va - back):
            if not (insn.address <= va < insn.address + insn.size):
                if insn.address > va:
                    break
                continue
            score = (0 if any(h in insn.op_str for h in hexes) else 1, insn.size)
            if best is None or score < best[0]:
                best = (score, insn)
            break
    return best[1] if best else None


def function_owners(img: PEImage) -> list[tuple[int, str]]:
    """(entry_va, label) for every func_proc/func_init/... in the effect table,
    sorted, so a code hit can be attributed to the effect it belongs to."""
    owners = []
    for r in walk(img):
        for name, addr in (("func_proc", r.func_proc), ("func_init", r.func_init),
                           ("func_exit", r.func_exit), ("func_update", r.func_update),
                           ("func_WndProc", r.func_wndproc)):
            if addr:
                owners.append((addr, f"{r.name}.{name}"))
    return sorted(set(owners))


def owner_of(owners, va: int):
    """(entry_va, label) of the nearest function entry at or before `va`."""
    prev = None
    for addr, label in owners:
        if addr > va:
            break
        prev = (addr, label)
    return prev


def nearest_owner(owners, va: int) -> str:
    prev = owner_of(owners, va)
    if prev is None:
        return "?"
    return f"{prev[1]} +0x{va - prev[0]:x}"


def report(img: PEImage, target: int, owners) -> None:
    hits = scan(img, target)
    print(f"\n=== 0x{target:08x} : {len(hits)} occurrence(s) ===")
    for va in hits:
        sec = section_of(img, va)
        if sec == ".text":
            own = owner_of(owners, va)
            insn = instruction_containing(img, va, target, anchor=own[0] if own else None)
            asm = f"{insn.mnemonic} {insn.op_str}" if insn else "<undecodable>"
            at = insn.address if insn else va
            print(f"  0x{va:08x} [{sec:8}] 0x{at:08x}: {asm:<42} ({nearest_owner(owners, at)})")
        else:
            print(f"  0x{va:08x} [{sec:8}] (data)")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tools.xrefs")
    parser.add_argument("--addr", action="append", required=True, help="VA to look for; repeatable")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    owners = function_owners(img)
    for a in args.addr:
        report(img, int(a, 0), owners)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
