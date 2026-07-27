"""Raw capstone disassembly of a VA range, with memory operands resolved.

angr's decompiler (tools/decompile.py) renders x87/SSE floating point code as
`/* unsupported instruction */`, and exedit's filters do all of their
parameter math in x87. Reading those instructions by hand is unavoidable - but
`fld qword ptr [0x1009a3b0]` on its own says nothing. What matters is the
*value* at 0x1009a3b0, which lives in .rdata. This module disassembles and
annotates every absolute memory operand with what the bytes there decode to
(double / float / signed int), which is what turns a wall of x87 into a
readable formula.

As a library:

    from tools.disasm import disasm_range, dump_range
    for insn, hint in disasm_range(img, 0x1004e560, 0x200):
        ...

As a script:

    uv run main.py tools.disasm --addr 0x1004e560 --size 0x300
    uv run main.py tools.disasm --addr 0x1004e560 --size 0x300 --no-resolve
"""

import argparse
import re

import capstone

from tools.pe_image import PEImage

_ABS_OPERAND = re.compile(r"0x[0-9a-fA-F]{7,8}")


def make_md() -> capstone.Cs:
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def resolve_operand(img: PEImage, insn) -> str:
    """Annotate an absolute [0x...] memory operand with the constant it holds.

    Only bracketed operands are resolved - a bare `0x1004e560` in a call/jmp is
    a code address, not data, and decoding it as a double would be noise.
    """
    m = re.search(r"\[(0x[0-9a-fA-F]{7,8})\]", insn.op_str)
    if not m:
        return ""
    va = int(m.group(1), 16)
    if not img.valid(va, 4):
        return ""
    parts = [f"i32={img.i32(va)}"]
    f32 = img.f32(va)
    if f32 is not None and (abs(f32) < 1e12) and (abs(f32) > 1e-12 or f32 == 0.0):
        parts.append(f"f32={f32!r}")
    if img.valid(va, 8):
        f64 = img.f64(va)
        if f64 is not None and (abs(f64) < 1e12) and (abs(f64) > 1e-12 or f64 == 0.0):
            parts.append(f"f64={f64!r}")
    return "  ; " + " ".join(parts)


def disasm_range(img: PEImage, start: int, size: int, resolve: bool = True):
    """Yield (insn, hint) over a VA range."""
    md = make_md()
    for insn in md.disasm(img.code(start, size), start):
        yield insn, (resolve_operand(img, insn) if resolve else "")


def dump_range(img: PEImage, start: int, size: int, label: str = "", resolve: bool = True,
               annotations=None, mnemonic_width: int = 8) -> None:
    """Print a VA range, with each instruction's note beside it.

    Annotating the disassembly is how the verify_*.py scripts here make their
    case: the claim sits next to the opcode that supports it, so a reader can
    check the reasoning against the instruction rather than against prose.
    `annotations` is either

      * a dict {address: note} - for claims about specific instructions, or
      * a callable (insn) -> note - for claims about a *kind* of instruction
        ("every idiv here is the box-average divide"), which is the stronger
        form when the point is that no counter-example appears in the range.

    Addresses in a dict that do not land on an instruction boundary are
    reported rather than dropped: a silently vanished annotation would read as
    agreement.
    """
    print(f"\n--- {label or 'disasm'} @ 0x{start:08x} ({size} bytes) ---")
    by_addr = annotations if isinstance(annotations, dict) else None
    fn = annotations if callable(annotations) else None
    seen = set()
    decoded_end = start
    for insn, hint in disasm_range(img, start, size, resolve):
        decoded_end = insn.address + insn.size
        note = ""
        if by_addr is not None:
            note = by_addr.get(insn.address, "")
            if note:
                seen.add(insn.address)
        elif fn is not None:
            note = fn(insn) or ""
        marker = f"    <-- {note}" if note else ""
        print(f"0x{insn.address:08x}: {insn.mnemonic:<{mnemonic_width}} {insn.op_str}{hint}{marker}")
    # Complain only about annotations inside the span actually decoded. Two
    # kinds of address are deliberately not flagged: ones meant for a different
    # dump (scripts share one dict across several ranges), and ones pointing at
    # the instruction just past the end, where the range simply stops one
    # instruction short rather than the annotation being wrong.
    missed = sorted(a for a in (by_addr or {}) if start <= a < decoded_end and a not in seen)
    if missed:
        print("  ! annotations that did not land on an instruction boundary in this range: "
              + ", ".join(f"0x{a:08x}" for a in missed))


def function_body(img: PEImage, addr: int, limit: int = 0x700) -> list:
    """Instructions of the function at `addr`, stopping where it ends.

    exedit's workers sit back to back, each ending in `ret` followed by `nop`
    padding to the next 16-byte boundary. Scanning a fixed span instead spills
    into the neighbouring function, which is how a worker that reads only one
    axis' globals ends up looking like it reads both - the exact mistake
    several verify_*.py scripts here exist to rule out. `ret` + `nop` is the
    end marker; `limit` only bounds the search.
    """
    out = []
    for insn, _ in disasm_range(img, addr, limit, resolve=False):
        if insn.mnemonic == "nop" and out and out[-1].mnemonic == "ret":
            break
        out.append(insn)
    return out


def dump_all(img: PEImage, targets: dict, resolve: bool = True, annotations=None,
             mnemonic_width: int = 8) -> None:
    """targets: {label: (start_va, size)}"""
    for label, (start, size) in targets.items():
        dump_range(img, start, size, label, resolve, annotations, mnemonic_width)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tools.disasm")
    parser.add_argument("--addr", action="append", required=True,
                        help="start VA, e.g. 0x1004e560; repeatable")
    parser.add_argument("--size", default="0x200", help="bytes to disassemble per address")
    parser.add_argument("--no-resolve", action="store_true",
                        help="do not annotate absolute memory operands with their constants")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    size = int(args.size, 0)
    for a in args.addr:
        dump_range(img, int(a, 0), size, resolve=not args.no_resolve)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
